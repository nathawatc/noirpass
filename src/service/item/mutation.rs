//! Item mutations retained through persistence and required notifications.

use std::collections::HashMap;

use zbus::fdo;
use zbus::object_server::{ObjectServer, SignalEmitter};
use zbus::{OwnedObjectPath, Variant};

use super::{ITEM_INTERFACE, Item, root_path};
use crate::service::collection::{
    Collection, emit_collection_items_and_modified, emit_collection_modified,
};
use crate::service::session::Secret;
use crate::service::{
    SESSION_COLLECTION_ID, SecretError, collection_path, emit_property_changed,
    object_removed_or_absent,
};

impl Item {
    pub(super) async fn set_secret_inner(
        &self,
        secret: Secret,
        owner: &str,
        connection: &zbus::Connection,
    ) -> Result<(), SecretError> {
        let plaintext = self.state.secret_to_plaintext(&secret, owner)?;
        let (plaintext, ciphertext) = if self.collection_id == SESSION_COLLECTION_ID {
            (Some(plaintext), None)
        } else {
            (None, Some(self.state.encrypt_secret(plaintext).await?))
        };
        let lifecycle = self
            .state
            .lock_owned_collection_lifecycle(&self.collection_id)
            .await;
        let meta = if self.collection_id == SESSION_COLLECTION_ID {
            self.state.update_session_item(
                &self.id,
                None,
                None,
                Some(&secret.content_type),
                plaintext,
            )?
        } else {
            let id = self.id.clone();
            self.state
                .blocking(Some(lifecycle.clone()), move |state| {
                    Ok(state.store().update_item(
                        &id,
                        None,
                        None,
                        Some(&secret.content_type),
                        ciphertext.as_deref(),
                    )?)
                })
                .await?
        };

        let item_path = self.path();
        let item_emitter =
            SignalEmitter::new(connection, item_path.clone()).map_err(SecretError::ZBus)?;
        let collection_emitter =
            SignalEmitter::new(connection, collection_path(&self.collection_id))
                .map_err(SecretError::ZBus)?;
        emit_property_changed(
            &item_emitter,
            ITEM_INTERFACE,
            "Modified",
            Variant::from(meta.modified),
        )
        .await?;
        Collection::item_changed(&collection_emitter, item_path)
            .await
            .map_err(SecretError::ZBus)?;
        emit_collection_modified(
            &self.state,
            connection,
            &self.collection_id,
            meta.modified,
            lifecycle.clone(),
        )
        .await?;
        Ok(())
    }
}

impl Item {
    pub(super) async fn delete_inner(
        &self,
        server: &ObjectServer,
        connection: &zbus::Connection,
    ) -> Result<OwnedObjectPath, SecretError> {
        let lifecycle = self
            .state
            .lock_owned_collection_lifecycle(&self.collection_id)
            .await;
        if self.collection_id == SESSION_COLLECTION_ID {
            self.state.delete_session_item(&self.id)?;
        } else {
            let id = self.id.clone();
            self.state
                .blocking(Some(lifecycle.clone()), move |state| {
                    Ok(state.store().delete_item(&id)?)
                })
                .await?;
        }

        object_removed_or_absent(server.remove::<Self, _>(&self.path()).await)
            .map_err(SecretError::ZBus)?;

        let emitter = SignalEmitter::new(connection, collection_path(&self.collection_id))
            .map_err(SecretError::ZBus)?;
        Collection::item_deleted(&emitter, self.path())
            .await
            .map_err(SecretError::ZBus)?;
        emit_collection_items_and_modified(
            &self.state,
            server,
            connection,
            &self.collection_id,
            lifecycle.clone(),
        )
        .await?;

        Ok(root_path())
    }

    /// Complete metadata persistence and signals even after caller cancellation.
    pub(super) async fn update_metadata(
        &self,
        label: Option<&str>,
        attributes: Option<HashMap<String, String>>,
        connection: &zbus::Connection,
    ) -> fdo::Result<()> {
        let activity = match &label {
            Some(label) => self.state.request(label)?,
            None => self.state.request(&attributes.as_ref().ok_or_else(|| {
                fdo::Error::InvalidArgs("metadata update requires label or attributes".into())
            })?)?,
        };
        let label = label.map(str::to_owned);
        let object = self.clone();
        let connection = connection.clone();
        tokio::spawn(activity.run(async move {
            let lifecycle = object
                .state
                .lock_owned_collection_lifecycle(&object.collection_id)
                .await;
            let relabel = label.is_some();
            let meta = if object.collection_id == SESSION_COLLECTION_ID {
                object
                    .state
                    .update_session_item(&object.id, label.as_deref(), attributes, None, None)
                    .map_err(fdo::Error::from)?
            } else {
                let id = object.id.clone();
                object
                    .state
                    .blocking(Some(lifecycle.clone()), move |state| {
                        Ok(state.store().update_item(
                            &id,
                            label.as_deref(),
                            attributes,
                            None,
                            None,
                        )?)
                    })
                    .await?
            };
            let path = object.path();
            let item_emitter = SignalEmitter::new(&connection, path.clone())?;
            let collection_emitter =
                SignalEmitter::new(&connection, collection_path(&object.collection_id))?;
            if relabel {
                emit_property_changed(
                    &item_emitter,
                    ITEM_INTERFACE,
                    "Label",
                    Variant::from(meta.label.as_str()),
                )
                .await?;
            } else {
                emit_property_changed(
                    &item_emitter,
                    ITEM_INTERFACE,
                    "Attributes",
                    Variant::from(meta.attributes),
                )
                .await?;
            }
            emit_property_changed(
                &item_emitter,
                ITEM_INTERFACE,
                "Modified",
                Variant::from(meta.modified),
            )
            .await?;
            Collection::item_changed(&collection_emitter, path).await?;
            emit_collection_modified(
                &object.state,
                &connection,
                &object.collection_id,
                meta.modified,
                lifecycle.clone(),
            )
            .await?;
            Ok(())
        }))
        .await
        .map_err(|_| fdo::Error::Failed("item metadata mutation failed".into()))?
    }
}
