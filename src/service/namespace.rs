//! Collection creation and alias publication under exclusive namespace serialization.
//!
//! Persistence uses a reserved blocking worker. The admitted owned task retains the namespace
//! guard through object registration and signals even when its caller stops waiting.

use std::collections::HashMap;

use zbus::fdo;
use zbus::object_server::{ObjectServer, SignalEmitter};
use zbus::{OwnedObjectPath, OwnedVariant};

use super::objects::root_path;
use super::{
    SESSION_COLLECTION_ALIAS, SESSION_COLLECTION_ID, SecretError, Service, collection,
    collection_path, parse_collection_path, register_alias, register_collection, unregister_alias,
};

impl Service {
    pub(super) async fn create_collection_inner(
        &self,
        properties: HashMap<String, OwnedVariant>,
        alias: &str,
        server: &ObjectServer,
        emitter: &SignalEmitter<'_>,
    ) -> fdo::Result<(OwnedObjectPath, OwnedObjectPath)> {
        let label = match properties.get("org.freedesktop.Secret.Collection.Label") {
            None => None,
            Some(value) => Some(String::try_from(value.clone()).map_err(|_| {
                fdo::Error::InvalidArgs(
                    "org.freedesktop.Secret.Collection.Label must be a string".into(),
                )
            })?),
        };
        let relabel = label.is_some();
        let lifecycle = self.state.lock_owned_namespace_lifecycle().await;
        let alias_for_worker = alias.to_string();
        let (id, created) = self
            .state
            .blocking(Some(lifecycle.clone()), move |state| {
                if !alias_for_worker.is_empty()
                    && let Some(existing) = state.read_alias(&alias_for_worker)?
                    && (existing == SESSION_COLLECTION_ID
                        || state.store().get_collection(&existing).is_ok())
                {
                    if let Some(label) = label.as_deref() {
                        if existing == SESSION_COLLECTION_ID {
                            state.set_session_collection_label(label)?;
                        } else {
                            state.store().set_collection_label(&existing, label)?;
                        }
                    }
                    return Ok((existing, false));
                }
                let alias = (!alias_for_worker.is_empty()).then_some(alias_for_worker.as_str());
                let meta = state
                    .store()
                    .create_collection(label.as_deref().unwrap_or(""), alias)?;
                Ok((meta.id, true))
            })
            .await?;
        let path = collection_path(&id);
        if !created {
            if relabel {
                collection::emit_collection_label_modified(
                    &self.state,
                    server,
                    emitter.connection(),
                    &id,
                )
                .await?;
                Self::collection_changed(emitter, path.clone()).await?;
            }
            return Ok((path, root_path()));
        }
        register_collection(server, &self.state, &id).await?;
        if !alias.is_empty() {
            register_alias(server, &self.state, alias).await?;
        }
        Self::collection_created(emitter, path.clone()).await?;
        self.collections_changed(emitter).await?;
        Ok((path, root_path()))
    }

    pub(super) async fn set_alias_inner(
        &self,
        name: &str,
        collection: OwnedObjectPath,
        server: &ObjectServer,
        connection: &zbus::Connection,
    ) -> Result<(), SecretError> {
        if name == SESSION_COLLECTION_ALIAS {
            return Err(fdo::Error::NotSupported(
                "the session alias is reserved for temporary secrets".into(),
            )
            .into());
        }
        let lifecycle = self.state.lock_owned_namespace_lifecycle().await;
        let name_for_worker = name.to_string();
        let (previous, id) = self
            .state
            .blocking(Some(lifecycle.clone()), move |state| {
                let previous = state.read_alias(&name_for_worker)?;
                if collection.as_str() == "/" {
                    state.store().set_alias(&name_for_worker, None)?;
                    state.remove_session_alias(&name_for_worker);
                    return Ok((previous, None));
                }
                let id = parse_collection_path(collection.as_str()).ok_or_else(|| {
                    SecretError::NoSuchObject(format!("{collection} is not a collection path"))
                })?;
                if id == SESSION_COLLECTION_ID {
                    state.set_session_alias(&name_for_worker)?;
                } else {
                    state.store().set_alias(&name_for_worker, Some(&id))?;
                    state.remove_session_alias(&name_for_worker);
                }
                Ok((previous, Some(id)))
            })
            .await?;
        let Some(id) = id else {
            unregister_alias(server, name)
                .await
                .map_err(SecretError::ZBus)?;
            return Ok(());
        };
        register_alias(server, &self.state, name)
            .await
            .map_err(SecretError::ZBus)?;
        if previous
            .as_deref()
            .is_some_and(|previous| previous != id.as_str())
        {
            collection::emit_alias_target_invalidated(connection, name).await?;
        }
        Ok(())
    }
}
