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
        let _activity = self.state.activity()?;
        let owner = message_sender(&header)?;
        let secret = if self.collection_id == SESSION_COLLECTION_ID {
            let (meta, plaintext) = self.state.read_session_item_secret(&self.id)?;
            self.state
                .plaintext_to_secret(&session, &plaintext, &meta.content_type, &owner)?
        } else {
            let (meta, ciphertext) = self.state.store().read_item_secret(&self.id)?;
            self.state
                .ciphertext_to_secret(&session, &ciphertext, &meta.content_type, &owner)
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
        let _activity = self.state.activity()?;
        let _lifecycle = self.state.lock_object_lifecycle().await;
        let owner = message_sender(&header)?;
        if self.collection_id == SESSION_COLLECTION_ID {
            let plaintext = self.state.secret_to_plaintext(&secret, &owner)?;
            self.state.update_session_item(
                &self.id,
                None,
                None,
                Some(&secret.content_type),
                Some(plaintext),
            )?;
        } else {
            let ciphertext = self.state.secret_to_ciphertext(&secret, &owner)?;
            self.state.store().update_item(
                &self.id,
                None,
                None,
                Some(&secret.content_type),
                Some(&ciphertext),
            )?;
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

    /// Delete this item and its secret value (and persistent file, when present).
    #[zbus(out_args("prompt"))]
    async fn delete(
        &self,
        #[zbus(object_server)] server: &ObjectServer,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<OwnedObjectPath, SecretError> {
        let _activity = self.state.activity()?;
        let _lifecycle = self.state.lock_object_lifecycle().await;
        if self.collection_id == SESSION_COLLECTION_ID {
            self.state.delete_session_item(&self.id)?;
        } else {
            self.state.store().delete_item(&self.id)?;
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
        let _activity = self.state.activity()?;
        let _lifecycle = self.state.lock_object_lifecycle().await;
        if self.collection_id == SESSION_COLLECTION_ID {
            self.state
                .update_session_item(&self.id, None, Some(attributes), None, None)
                .map_err(fdo::Error::from)?;
        } else {
            self.state
                .store()
                .update_item(&self.id, None, Some(attributes), None, None)
                .map_err(fdo::Error::from)?;
        }

        let item_path = self.path();
        let item_emitter = SignalEmitter::new(connection, item_path.clone())?;
        let collection_emitter =
            SignalEmitter::new(connection, collection_path(&self.collection_id))?;
        self.emit_attributes_changed(&item_emitter).await?;
        self.modified_changed(&item_emitter).await?;
        Collection::item_changed(&collection_emitter, item_path).await?;
        emit_session_collection_modified(&self.state, connection, &self.collection_id).await?;
        Ok(())
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
        let _activity = self.state.activity()?;
        let _lifecycle = self.state.lock_object_lifecycle().await;
        if self.collection_id == SESSION_COLLECTION_ID {
            self.state
                .update_session_item(&self.id, Some(label), None, None, None)
                .map_err(fdo::Error::from)?;
        } else {
            self.state
                .store()
                .update_item(&self.id, Some(label), None, None, None)
                .map_err(fdo::Error::from)?;
        }

        let item_path = self.path();
        let item_emitter = SignalEmitter::new(connection, item_path.clone())?;
        let collection_emitter =
            SignalEmitter::new(connection, collection_path(&self.collection_id))?;
        self.emit_label_changed(&item_emitter).await?;
        self.modified_changed(&item_emitter).await?;
        Collection::item_changed(&collection_emitter, item_path).await?;
        emit_session_collection_modified(&self.state, connection, &self.collection_id).await?;
        Ok(())
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
