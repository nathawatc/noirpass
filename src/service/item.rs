//! `org.freedesktop.Secret.Item` objects.
//!
//! One object per secret, served at
//! `/org/freedesktop/secrets/collection/<col>/<item>`. Persistent values only
//! exist in plaintext transiently around the `OpenPGP` layer; values in the
//! built-in `session` collection remain only in zeroizing process memory.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use zbus::names::InterfaceName;
use zbus::object_server::{ObjectServer, SignalEmitter};
use zbus::zvariant::{OwnedObjectPath, Value};
use zbus::{fdo, interface};

use crate::service::collection::{
    Collection, emit_collection_items_changed, emit_session_collection_modified,
};
use crate::service::session::Secret;
use crate::service::{
    SESSION_COLLECTION_ID, SecretError, ServiceState, collection_path, item_path, message_sender,
    object_removed_or_absent,
};

/// The "no prompt" object path.
fn no_prompt() -> OwnedObjectPath {
    OwnedObjectPath::try_from("/").expect("/ is a valid object path")
}

const ITEM_INTERFACE: &str = "org.freedesktop.Secret.Item";

/// A `org.freedesktop.Secret.Item` D-Bus object.
#[derive(Clone)]
pub struct Item {
    state: Arc<ServiceState>,
    collection_id: String,
    id: String,
}

impl Item {
    /// Create an item object for stored item `id` in `collection_id`.
    #[must_use]
    pub fn new(state: Arc<ServiceState>, collection_id: String, id: String) -> Self {
        Self {
            state,
            collection_id,
            id,
        }
    }

    /// This item's D-Bus path.
    fn path(&self) -> OwnedObjectPath {
        item_path(&self.collection_id, &self.id)
    }

    /// Emit the changed signal for Attributes while mutation serialization remains held.
    pub(crate) async fn emit_attributes_changed(
        &self,
        emitter: &SignalEmitter<'_>,
    ) -> fdo::Result<()> {
        let mut changed = HashMap::new();
        changed.insert("Attributes", Value::from(self.attributes()?));
        fdo::Properties::properties_changed(
            emitter,
            InterfaceName::from_static_str_unchecked(ITEM_INTERFACE),
            changed,
            Cow::Borrowed(&[]),
        )
        .await?;
        Ok(())
    }

    /// Emit the changed signal for Label while mutation serialization remains held.
    pub(crate) async fn emit_label_changed(&self, emitter: &SignalEmitter<'_>) -> fdo::Result<()> {
        let mut changed = HashMap::new();
        changed.insert("Label", Value::from(self.label()?));
        fdo::Properties::properties_changed(
            emitter,
            InterfaceName::from_static_str_unchecked(ITEM_INTERFACE),
            changed,
            Cow::Borrowed(&[]),
        )
        .await?;
        Ok(())
    }
}

impl Item {
    async fn set_secret_inner(
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
        if self.collection_id == SESSION_COLLECTION_ID {
            self.state.update_session_item(
                &self.id,
                None,
                None,
                Some(&secret.content_type),
                plaintext,
            )?;
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
                .await?;
        }

        let item_path = self.path();
        let item_emitter =
            SignalEmitter::new(connection, item_path.clone()).map_err(SecretError::ZBus)?;
        let collection_emitter =
            SignalEmitter::new(connection, collection_path(&self.collection_id))
                .map_err(SecretError::ZBus)?;
        self.modified_changed(&item_emitter)
            .await
            .map_err(SecretError::ZBus)?;
        Collection::item_changed(&collection_emitter, item_path)
            .await
            .map_err(SecretError::ZBus)?;
        emit_session_collection_modified(&self.state, connection, &self.collection_id).await?;
        Ok(())
    }
}

impl Item {
    #[cfg(test)]
    pub(crate) async fn set_label_for_test(
        &self,
        label: &str,
        connection: &zbus::Connection,
    ) -> fdo::Result<()> {
        self.set_label(label, connection).await
    }

    async fn delete_inner(
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

        // ItemDeleted is a Collection signal, emitted from the collection path.
        let emitter = SignalEmitter::new(connection, collection_path(&self.collection_id))
            .map_err(SecretError::ZBus)?;
        Collection::item_deleted(&emitter, self.path())
            .await
            .map_err(SecretError::ZBus)?;
        // Refresh client-side caches of the collection's `Items` property.
        emit_collection_items_changed(&self.state, server, connection, &self.collection_id)
            .await
            .map_err(SecretError::from)?;
        emit_session_collection_modified(&self.state, connection, &self.collection_id).await?;

        Ok(no_prompt())
    }

    /// Complete metadata persistence and signals even after caller cancellation.
    async fn update_metadata(
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
        tokio::spawn(async move {
            let _activity = activity;
            let lifecycle = object
                .state
                .lock_owned_collection_lifecycle(&object.collection_id)
                .await;
            let relabel = label.is_some();
            if object.collection_id == SESSION_COLLECTION_ID {
                object
                    .state
                    .update_session_item(&object.id, label.as_deref(), attributes, None, None)
                    .map_err(fdo::Error::from)?;
            } else {
                let id = object.id.clone();
                object
                    .state
                    .blocking(Some(lifecycle.clone()), move |state| {
                        Ok(state
                            .store()
                            .update_item(&id, label.as_deref(), attributes, None, None)
                            .map_err(fdo::Error::from))
                    })
                    .await
                    .map_err(|err| fdo::Error::Failed(err.to_string()))??;
            }
            let path = object.path();
            let item_emitter = SignalEmitter::new(&connection, path.clone())?;
            let collection_emitter =
                SignalEmitter::new(&connection, collection_path(&object.collection_id))?;
            if relabel {
                object.emit_label_changed(&item_emitter).await?;
            } else {
                object.emit_attributes_changed(&item_emitter).await?;
            }
            object.modified_changed(&item_emitter).await?;
            Collection::item_changed(&collection_emitter, path).await?;
            emit_session_collection_modified(&object.state, &connection, &object.collection_id)
                .await?;
            Ok(())
        })
        .await
        .map_err(|_| fdo::Error::Failed("item metadata mutation failed".into()))?
    }
}

#[interface(name = "org.freedesktop.Secret.Item")]
impl Item {
    /// Retrieve the secret, decrypted via `gpg-agent` and encoded for the
    /// given session.
    #[zbus(out_args("secret"))]
    async fn get_secret(
        &self,
        session: OwnedObjectPath,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<(Secret,), SecretError> {
        let _activity = self.state.request(&session)?;
        let owner = message_sender(&header)?;
        let secret = if self.collection_id == SESSION_COLLECTION_ID {
            let (meta, plaintext) = self.state.read_session_item_secret(&self.id)?;
            self.state
                .plaintext_to_secret(&session, &plaintext, &meta.content_type, &owner)?
        } else {
            self.state
                .persistent_secret(&self.collection_id, &self.id, &session, &owner, None)
                .await?
        };
        Ok((secret,))
    }

    /// Replace the secret value (and content type) of this item.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "zbus deserializes method arguments by value"
    )]
    async fn set_secret(
        &self,
        secret: Secret,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<(), SecretError> {
        let activity = self.state.request(&secret)?;
        let owner = message_sender(&header)?;
        let object = self.clone();
        let connection = connection.clone();
        // Once admitted, finish commit, object publication, and signals even if the caller leaves.
        tokio::spawn(async move {
            let _activity = activity;
            object.set_secret_inner(secret, &owner, &connection).await
        })
        .await
        .map_err(|_| fdo::Error::Failed("secret mutation failed".into()))?
    }

    /// Delete this item and its secret value (and persistent file, when present).
    #[zbus(out_args("prompt"))]
    async fn delete(
        &self,
        #[zbus(object_server)] server: &ObjectServer,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<OwnedObjectPath, SecretError> {
        let activity = self.state.request(&0u8)?;
        let object = self.clone();
        let server = server.clone();
        let connection = connection.clone();
        tokio::spawn(async move {
            let _activity = activity;
            object.delete_inner(&server, &connection).await
        })
        .await
        .map_err(|_| fdo::Error::Failed("item deletion failed".into()))?
    }

    /// Always `false`: noirpass has no lock state (`gpg-agent` is the gate).
    #[zbus(property)]
    fn locked(&self) -> fdo::Result<bool> {
        let _activity = self.state.activity()?;
        Ok(false)
    }

    /// Lookup attributes.
    #[zbus(property(emits_changed_signal = "false"))]
    fn attributes(&self) -> fdo::Result<HashMap<String, String>> {
        let _activity = self.state.activity()?;
        let meta = if self.collection_id == SESSION_COLLECTION_ID {
            self.state
                .get_session_item(&self.id)
                .map_err(fdo::Error::from)?
        } else {
            self.state
                .store()
                .get_item(&self.id)
                .map_err(fdo::Error::from)?
        };
        Ok(meta.attributes)
    }

    /// Replace the lookup attributes (bumps the modified timestamp).
    #[zbus(property)]
    async fn set_attributes(
        &self,
        attributes: HashMap<String, String>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> fdo::Result<()> {
        self.update_metadata(None, Some(attributes), connection)
            .await
    }

    /// Human-readable label.
    #[zbus(property(emits_changed_signal = "false"))]
    fn label(&self) -> fdo::Result<String> {
        let _activity = self.state.activity()?;
        let meta = if self.collection_id == SESSION_COLLECTION_ID {
            self.state
                .get_session_item(&self.id)
                .map_err(fdo::Error::from)?
        } else {
            self.state
                .store()
                .get_item(&self.id)
                .map_err(fdo::Error::from)?
        };
        Ok(meta.label)
    }

    /// Relabel the item (bumps the modified timestamp).
    #[zbus(property)]
    async fn set_label(
        &self,
        label: &str,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> fdo::Result<()> {
        self.update_metadata(Some(label), None, connection).await
    }

    /// Creation time, seconds since the Unix epoch.
    #[zbus(property)]
    fn created(&self) -> fdo::Result<u64> {
        let _activity = self.state.activity()?;
        let meta = if self.collection_id == SESSION_COLLECTION_ID {
            self.state
                .get_session_item(&self.id)
                .map_err(fdo::Error::from)?
        } else {
            self.state
                .store()
                .get_item(&self.id)
                .map_err(fdo::Error::from)?
        };
        Ok(meta.created)
    }

    /// Last modification time, seconds since the Unix epoch.
    #[zbus(property)]
    fn modified(&self) -> fdo::Result<u64> {
        let _activity = self.state.activity()?;
        let meta = if self.collection_id == SESSION_COLLECTION_ID {
            self.state
                .get_session_item(&self.id)
                .map_err(fdo::Error::from)?
        } else {
            self.state
                .store()
                .get_item(&self.id)
                .map_err(fdo::Error::from)?
        };
        Ok(meta.modified)
    }
}
