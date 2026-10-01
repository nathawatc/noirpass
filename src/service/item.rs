//! `org.freedesktop.Secret.Item` objects.
//!
//! One object per secret, served at
//! `/org/freedesktop/secrets/collection/<col>/<item>`. Persistent values only
//! exist in plaintext transiently around the `OpenPGP` layer; values in the
//! built-in `session` collection remain only in zeroizing process memory.

mod mutation;

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use zbus::names::InterfaceName;
use zbus::object_server::{ObjectServer, SignalEmitter};
use zbus::zvariant::{OwnedObjectPath, Value};
use zbus::{fdo, interface};

use crate::service::objects::root_path;
use crate::service::session::Secret;
use crate::service::{SESSION_COLLECTION_ID, SecretError, ServiceState, item_path, message_sender};

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

    #[cfg(test)]
    pub(crate) async fn set_label_for_test(
        &self,
        label: &str,
        connection: &zbus::Connection,
    ) -> fdo::Result<()> {
        self.set_label(label, connection).await
    }

    fn metadata(&self) -> fdo::Result<crate::store::ItemMeta> {
        if self.collection_id == SESSION_COLLECTION_ID {
            self.state
                .get_session_item(&self.id)
                .map_err(fdo::Error::from)
        } else {
            self.state
                .store()
                .get_item(&self.id)
                .map_err(fdo::Error::from)
        }
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
        let activity = self.state.request(&session)?;
        activity
            .run(async {
                let owner = message_sender(&header)?;
                let secret = if self.collection_id == SESSION_COLLECTION_ID {
                    let (meta, plaintext) = self.state.read_session_item_secret(&self.id)?;
                    self.state.plaintext_to_secret(
                        &session,
                        &plaintext,
                        &meta.content_type,
                        &owner,
                    )?
                } else {
                    self.state
                        .persistent_secret(&self.collection_id, &self.id, &session, &owner, None)
                        .await?
                };
                Ok((secret,))
            })
            .await
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
        tokio::spawn(
            activity.run(async move { object.set_secret_inner(secret, &owner, &connection).await }),
        )
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
        tokio::spawn(activity.run(async move { object.delete_inner(&server, &connection).await }))
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
        let meta = self.metadata()?;
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
        let meta = self.metadata()?;
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
        let meta = self.metadata()?;
        Ok(meta.created)
    }

    /// Last modification time, seconds since the Unix epoch.
    #[zbus(property)]
    fn modified(&self) -> fdo::Result<u64> {
        let _activity = self.state.activity()?;
        let meta = self.metadata()?;
        Ok(meta.modified)
    }
}
