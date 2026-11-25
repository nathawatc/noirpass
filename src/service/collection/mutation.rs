//! Collection mutations from persistence through object publication and signals.

use std::collections::HashMap;

use zbus::fdo;
use zbus::object_server::{ObjectServer, SignalEmitter};
use zbus::{OwnedObjectPath, OwnedVariant};

use super::{
    Collection, emit_collection_items_and_modified, emit_collection_label_modified,
    emit_collection_modified, root_path,
};
use crate::service::session::Secret;
use crate::service::{
    ITEM_ATTRIBUTES_PROPERTY, ITEM_INTERFACE, ITEM_LABEL_PROPERTY, SERVICE_PATH,
    SESSION_COLLECTION_ALIAS, SESSION_COLLECTION_ID, SecretError, Service, alias_path,
    collection_path, emit_property_changed, item_path, object_removed_or_absent, register_item,
};
use zbus::Variant;

impl Collection {
    pub(super) async fn create_item_inner(
        &self,
        properties: HashMap<String, OwnedVariant>,
        secret: Secret,
        replace: bool,
        server: &ObjectServer,
        connection: &zbus::Connection,
        owner: &str,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath), SecretError> {
        let label = match properties.get(ITEM_LABEL_PROPERTY) {
            None => String::new(),
            Some(value) => String::try_from(value.clone()).map_err(|_| {
                SecretError::InvalidArgs(format!("{ITEM_LABEL_PROPERTY} must be a string"))
            })?,
        };
        let attributes = match properties.get(ITEM_ATTRIBUTES_PROPERTY) {
            None => HashMap::new(),
            Some(value) => HashMap::<String, String>::try_from(value.clone()).map_err(|_| {
                SecretError::InvalidArgs(format!(
                    "{ITEM_ATTRIBUTES_PROPERTY} must be a string dictionary"
                ))
            })?,
        };

        let plaintext = self.state.secret_to_plaintext(&secret, owner)?;
        let initial_id = self.resolve_id()?;
        let (plaintext, ciphertext) = if initial_id == SESSION_COLLECTION_ID {
            (Some(plaintext), None)
        } else {
            (None, Some(self.state.encrypt_secret(plaintext).await?))
        };
        let lifecycle = self
            .state
            .lock_owned_collection_lifecycle(&initial_id)
            .await;
        // Aliases can change during encryption. Resolve again under lifecycle serialization.
        let id = self.resolve_id()?;
        if id != initial_id {
            return Err(fdo::Error::Failed(
                "collection alias changed during encryption; retry".into(),
            )
            .into());
        }

        // Emit from the canonical collection path regardless of how we were
        // addressed (id or alias).
        let emitter =
            SignalEmitter::new(connection, collection_path(&id)).map_err(SecretError::ZBus)?;

        let (meta, replaced) = if id == SESSION_COLLECTION_ID {
            self.state.create_or_replace_session_item(
                &label,
                attributes,
                &secret.content_type,
                plaintext.expect("session plaintext was retained"),
                replace,
            )?
        } else {
            let collection_id = id.clone();
            self.state
                .blocking(Some(lifecycle.clone()), move |state| {
                    Ok(state.store().create_or_replace_item(
                        &collection_id,
                        &label,
                        attributes,
                        &secret.content_type,
                        ciphertext
                            .as_deref()
                            .expect("persistent target was encrypted"),
                        replace,
                    )?)
                })
                .await?
        };
        let path = register_item(server, &self.state, &id, &meta.id)
            .await
            .map_err(SecretError::ZBus)?;
        if replaced {
            let item_emitter = SignalEmitter::new(connection, path.clone())?;
            emit_property_changed(
                &item_emitter,
                ITEM_INTERFACE,
                "Label",
                Variant::from(meta.label.as_str()),
            )
            .await?;
            emit_property_changed(
                &item_emitter,
                ITEM_INTERFACE,
                "Modified",
                Variant::from(meta.modified),
            )
            .await?;
            Self::item_changed(&emitter, path.clone()).await?;
            emit_collection_modified(
                &self.state,
                connection,
                &id,
                meta.modified,
                lifecycle.clone(),
            )
            .await?;
            return Ok((path, root_path()));
        }
        Self::item_created(&emitter, path.clone()).await?;
        emit_collection_items_and_modified(&self.state, server, connection, &id, lifecycle.clone())
            .await?;
        Ok((path, root_path()))
    }
}

impl Collection {
    pub(super) async fn delete_inner(
        &self,
        server: &ObjectServer,
        connection: &zbus::Connection,
    ) -> Result<OwnedObjectPath, SecretError> {
        let lifecycle = self.state.lock_owned_namespace_lifecycle().await;
        let id = self.resolve_id()?;
        if id == SESSION_COLLECTION_ID {
            return Err(fdo::Error::NotSupported(
                "the built-in session collection cannot be deleted".into(),
            )
            .into());
        }
        let real_path = collection_path(&id);

        let collection_id = id.clone();
        let deleted = self
            .state
            .blocking(Some(lifecycle.clone()), move |state| {
                Ok(state.store().delete_collection(&collection_id)?)
            })
            .await?;

        // Unregister exactly the objects removed by the Store transaction.
        // Attempt every removal even when one ObjectServer operation fails.
        let mut cleanup_error = None;
        for item_id in deleted.item_ids {
            if let Err(err) = object_removed_or_absent(
                server
                    .remove::<crate::service::item::Item, _>(&item_path(&id, &item_id))
                    .await,
            ) && cleanup_error.is_none()
            {
                cleanup_error = Some(err);
            }
        }
        if let Err(err) = object_removed_or_absent(server.remove::<Self, _>(&real_path).await)
            && cleanup_error.is_none()
        {
            cleanup_error = Some(err);
        }
        for name in deleted.aliases {
            if name == SESSION_COLLECTION_ALIAS {
                continue;
            }
            if let Ok(path) = alias_path(&name)
                && let Err(err) = object_removed_or_absent(server.remove::<Self, _>(&path).await)
                && cleanup_error.is_none()
            {
                cleanup_error = Some(err);
            }
        }
        if let Some(err) = cleanup_error {
            return Err(SecretError::ZBus(err));
        }

        let emitter = SignalEmitter::new(connection, SERVICE_PATH).map_err(SecretError::ZBus)?;
        Service::collection_deleted(&emitter, real_path)
            .await
            .map_err(SecretError::ZBus)?;
        let service_ref = server
            .interface::<_, Service>(SERVICE_PATH)
            .await
            .map_err(SecretError::ZBus)?;
        service_ref
            .get()
            .await
            .collections_changed(service_ref.signal_emitter())
            .await
            .map_err(SecretError::ZBus)?;

        Ok(root_path())
    }

    pub(super) async fn set_label_inner(
        &self,
        label: &str,
        server: &ObjectServer,
        connection: &zbus::Connection,
    ) -> fdo::Result<()> {
        let initial_id = self.resolve_id()?;
        let lifecycle = self
            .state
            .lock_owned_collection_lifecycle(&initial_id)
            .await;
        let id = self.resolve_id()?;
        if id != initial_id {
            return Err(fdo::Error::Failed("collection alias changed; retry".into()));
        }
        let meta = if id == SESSION_COLLECTION_ID {
            self.state
                .set_session_collection_label(label)
                .map_err(fdo::Error::from)?
        } else {
            let collection_id = id.clone();
            let label = label.to_string();
            self.state
                .blocking(Some(lifecycle.clone()), move |state| {
                    Ok(state.store().set_collection_label(&collection_id, &label)?)
                })
                .await?
        };
        emit_collection_label_modified(
            &self.state,
            server,
            connection,
            &id,
            &meta.label,
            meta.modified,
            lifecycle,
        )
        .await?;
        let emitter = SignalEmitter::new(connection, SERVICE_PATH)?;
        Service::collection_changed(&emitter, collection_path(&id)).await?;
        Ok(())
    }
}
