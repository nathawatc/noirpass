//! `org.freedesktop.Secret.Item` objects.
//!
//! One object per stored secret, served at
//! `/org/freedesktop/secrets/collection/<col>/<item>`. Secret values only
//! exist in plaintext transiently, between the session cipher and the
//! `OpenPGP` layer.

use std::collections::HashMap;
use std::sync::Arc;

use zbus::object_server::{ObjectServer, SignalEmitter};
use zbus::zvariant::OwnedObjectPath;
use zbus::{fdo, interface};

use crate::service::collection::Collection;
use crate::service::session::Secret;
use crate::service::{
    SecretError, ServiceState, collection_path, item_path, message_sender, object_removed_or_absent,
};

/// The "no prompt" object path.
fn no_prompt() -> OwnedObjectPath {
    OwnedObjectPath::try_from("/").expect("/ is a valid object path")
}

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
        let (meta, ciphertext) = self.state.store().read_item_secret(&self.id)?;
        let secret = self
            .state
            .ciphertext_to_secret(&session, &ciphertext, &meta.content_type, &owner)
            .await?;
        Ok((secret,))
    }

    /// Replace the secret value (and content type) of this item.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "zbus deserializes method arguments by value"
    )]
    fn set_secret(
        &self,
        secret: Secret,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<(), SecretError> {
        let _activity = self.state.activity()?;
        let owner = message_sender(&header)?;
        let ciphertext = self.state.secret_to_ciphertext(&secret, &owner)?;
        self.state.store().update_item(
            &self.id,
            None,
            None,
            Some(&secret.content_type),
            Some(&ciphertext),
        )?;
        Ok(())
    }

    /// Delete this item and its secret file.
    #[zbus(out_args("prompt"))]
    async fn delete(
        &self,
        #[zbus(object_server)] server: &ObjectServer,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<OwnedObjectPath, SecretError> {
        let _activity = self.state.activity()?;
        let _lifecycle = self.state.lock_object_lifecycle().await;
        self.state.store().delete_item(&self.id)?;

        object_removed_or_absent(server.remove::<Self, _>(&self.path()).await)
            .map_err(SecretError::ZBus)?;

        // ItemDeleted is a Collection signal, emitted from the collection path.
        let emitter = SignalEmitter::new(connection, collection_path(&self.collection_id))
            .map_err(SecretError::ZBus)?;
        Collection::item_deleted(&emitter, self.path())
            .await
            .map_err(SecretError::ZBus)?;
        // Refresh client-side caches of the collection's `Items` property.
        let col_ref = server
            .interface::<_, Collection>(collection_path(&self.collection_id))
            .await
            .map_err(SecretError::ZBus)?;
        col_ref
            .get()
            .await
            .items_changed(col_ref.signal_emitter())
            .await
            .map_err(SecretError::ZBus)?;

        Ok(no_prompt())
    }

    /// Always `false`: noirpass has no lock state (`gpg-agent` is the gate).
    #[zbus(property)]
    fn locked(&self) -> fdo::Result<bool> {
        let _activity = self.state.activity()?;
        Ok(false)
    }

    /// Lookup attributes.
    #[zbus(property)]
    fn attributes(&self) -> fdo::Result<HashMap<String, String>> {
        let _activity = self.state.activity()?;
        let meta = self
            .state
            .store()
            .get_item(&self.id)
            .map_err(fdo::Error::from)?;
        Ok(meta.attributes)
    }

    /// Replace the lookup attributes (bumps the modified timestamp).
    #[zbus(property)]
    fn set_attributes(&self, attributes: HashMap<String, String>) -> fdo::Result<()> {
        let _activity = self.state.activity()?;
        self.state
            .store()
            .update_item(&self.id, None, Some(attributes), None, None)
            .map_err(fdo::Error::from)?;
        Ok(())
    }

    /// Human-readable label.
    #[zbus(property)]
    fn label(&self) -> fdo::Result<String> {
        let _activity = self.state.activity()?;
        let meta = self
            .state
            .store()
            .get_item(&self.id)
            .map_err(fdo::Error::from)?;
        Ok(meta.label)
    }

    /// Relabel the item (bumps the modified timestamp).
    #[zbus(property)]
    fn set_label(&self, label: &str) -> fdo::Result<()> {
        let _activity = self.state.activity()?;
        self.state
            .store()
            .update_item(&self.id, Some(label), None, None, None)
            .map_err(fdo::Error::from)?;
        Ok(())
    }

    /// Creation time, seconds since the Unix epoch.
    #[zbus(property)]
    fn created(&self) -> fdo::Result<u64> {
        let _activity = self.state.activity()?;
        let meta = self
            .state
            .store()
            .get_item(&self.id)
            .map_err(fdo::Error::from)?;
        Ok(meta.created)
    }

    /// Last modification time, seconds since the Unix epoch.
    #[zbus(property)]
    fn modified(&self) -> fdo::Result<u64> {
        let _activity = self.state.activity()?;
        let meta = self
            .state
            .store()
            .get_item(&self.id)
            .map_err(fdo::Error::from)?;
        Ok(meta.modified)
    }
}
