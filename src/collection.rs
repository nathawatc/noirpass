//! `org.freedesktop.Secret.Collection` objects.
//!
//! One object per stored collection, served at
//! `/org/freedesktop/secrets/collection/<id>`. Collections are always
//! unlocked (see [`crate::service`] module docs for the locking rationale).

use std::collections::HashMap;
use std::sync::Arc;

use zbus::object_server::{ObjectServer, SignalEmitter};
use zbus::zvariant::{OwnedObjectPath, OwnedValue};
use zbus::{fdo, interface};

use crate::service::{
    SERVICE_PATH, SecretError, Service, ServiceState, collection_path, item_path, register_item,
};
use crate::session::Secret;

/// The "no prompt" object path.
fn no_prompt() -> OwnedObjectPath {
    OwnedObjectPath::try_from("/").expect("/ is a valid object path")
}

/// A `org.freedesktop.Secret.Collection` D-Bus object.
pub struct Collection {
    state: Arc<ServiceState>,
    id: String,
}

impl Collection {
    /// Create a collection object for the stored collection `id`.
    #[must_use]
    pub fn new(state: Arc<ServiceState>, id: String) -> Self {
        Self { state, id }
    }

    /// This collection's D-Bus path.
    fn path(&self) -> OwnedObjectPath {
        collection_path(&self.id)
    }
}

#[interface(name = "org.freedesktop.Secret.Collection")]
impl Collection {
    /// Search this collection for items whose attributes are a superset of
    /// `attributes`. Everything is unlocked, so all matches are returned.
    #[zbus(out_args("results"))]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "zbus deserializes method arguments by value"
    )]
    fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> fdo::Result<Vec<OwnedObjectPath>> {
        self.state.touch();
        let results = self
            .state
            .store()
            .search_items(&attributes)
            .map_err(fdo::Error::from)?
            .into_iter()
            .filter(|meta| meta.collection == self.id)
            .map(|meta| item_path(&meta.collection, &meta.id))
            .collect();
        Ok(results)
    }

    /// Create (or replace) an item in this collection.
    ///
    /// The incoming [`Secret`] is decrypted with its session cipher and
    /// re-encrypted to the user's `OpenPGP` key before it touches disk. With
    /// `replace = true`, an item whose attributes match exactly is updated in
    /// place (`ItemChanged`); otherwise a new item is created (`ItemCreated`).
    #[zbus(out_args("item", "prompt"))]
    async fn create_item(
        &self,
        properties: HashMap<String, OwnedValue>,
        secret: Secret,
        replace: bool,
        #[zbus(object_server)] server: &ObjectServer,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath), SecretError> {
        self.state.touch();

        let label = properties
            .get("org.freedesktop.Secret.Item.Label")
            .and_then(|v| String::try_from(v.clone()).ok())
            .unwrap_or_default();
        let attributes = properties
            .get("org.freedesktop.Secret.Item.Attributes")
            .and_then(|v| HashMap::<String, String>::try_from(v.clone()).ok())
            .unwrap_or_default();

        let ciphertext = self.state.secret_to_ciphertext(&secret)?;

        let existing = if replace {
            self.state
                .store()
                .find_item_by_attrs_exact(&self.id, &attributes)?
        } else {
            None
        };

        if let Some(meta) = existing {
            self.state.store().update_item(
                &meta.id,
                Some(&label),
                None,
                Some(&secret.content_type),
                Some(&ciphertext),
            )?;
            let path = item_path(&self.id, &meta.id);
            Self::item_changed(&emitter, path.clone()).await?;
            return Ok((path, no_prompt()));
        }

        let meta = self.state.store().create_item(
            &self.id,
            &label,
            attributes,
            &secret.content_type,
            &ciphertext,
        )?;
        let path = register_item(server, &self.state, &self.id, &meta.id)
            .await
            .map_err(SecretError::ZBus)?;
        Self::item_created(&emitter, path.clone()).await?;
        Ok((path, no_prompt()))
    }

    /// Delete this collection, all its items and their secret files.
    ///
    /// Deleting the default collection is allowed; `ensure_default` recreates
    /// it on the next daemon startup.
    #[zbus(out_args("prompt"))]
    async fn delete(
        &self,
        #[zbus(object_server)] server: &ObjectServer,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<OwnedObjectPath, SecretError> {
        self.state.touch();

        let items = self.state.store().list_items(&self.id)?;
        self.state.store().delete_collection(&self.id)?;

        // Unregister the item objects, then this collection object itself.
        for item in items {
            let _ = server
                .remove::<crate::item::Item, _>(&item_path(&self.id, &item.id))
                .await;
        }
        server
            .remove::<Self, _>(&self.path())
            .await
            .map_err(SecretError::ZBus)?;

        // CollectionDeleted is a Service signal, emitted from the service path.
        let emitter = SignalEmitter::new(connection, SERVICE_PATH).map_err(SecretError::ZBus)?;
        Service::collection_deleted(&emitter, self.path())
            .await
            .map_err(SecretError::ZBus)?;

        Ok(no_prompt())
    }

    /// Object paths of the items in this collection.
    #[zbus(property)]
    fn items(&self) -> fdo::Result<Vec<OwnedObjectPath>> {
        let items = self
            .state
            .store()
            .list_items(&self.id)
            .map_err(fdo::Error::from)?;
        Ok(items
            .into_iter()
            .map(|meta| item_path(&meta.collection, &meta.id))
            .collect())
    }

    /// Human-readable label.
    #[zbus(property)]
    fn label(&self) -> fdo::Result<String> {
        let meta = self
            .state
            .store()
            .get_collection(&self.id)
            .map_err(fdo::Error::from)?;
        Ok(meta.label)
    }

    /// Relabel the collection (bumps the modified timestamp and emits
    /// `CollectionChanged` on the service).
    #[zbus(property)]
    async fn set_label(
        &self,
        label: &str,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> fdo::Result<()> {
        self.state.touch();
        self.state
            .store()
            .set_collection_label(&self.id, label)
            .map_err(fdo::Error::from)?;
        let emitter = SignalEmitter::new(connection, SERVICE_PATH)?;
        Service::collection_changed(&emitter, self.path()).await?;
        Ok(())
    }

    /// Always `false`: noirpass has no lock state (`gpg-agent` is the gate).
    #[zbus(property)]
    #[allow(clippy::unused_self, reason = "zbus property getters take &self")]
    fn locked(&self) -> bool {
        false
    }

    /// Creation time, seconds since the Unix epoch.
    #[zbus(property)]
    fn created(&self) -> fdo::Result<u64> {
        let meta = self
            .state
            .store()
            .get_collection(&self.id)
            .map_err(fdo::Error::from)?;
        Ok(meta.created)
    }

    /// Last modification time, seconds since the Unix epoch.
    #[zbus(property)]
    fn modified(&self) -> fdo::Result<u64> {
        let meta = self
            .state
            .store()
            .get_collection(&self.id)
            .map_err(fdo::Error::from)?;
        Ok(meta.modified)
    }

    /// An item was created in this collection.
    #[zbus(signal)]
    pub async fn item_created(
        emitter: &SignalEmitter<'_>,
        item: OwnedObjectPath,
    ) -> zbus::Result<()>;

    /// An item in this collection was deleted.
    #[zbus(signal)]
    pub async fn item_deleted(
        emitter: &SignalEmitter<'_>,
        item: OwnedObjectPath,
    ) -> zbus::Result<()>;

    /// An item in this collection changed.
    #[zbus(signal)]
    pub async fn item_changed(
        emitter: &SignalEmitter<'_>,
        item: OwnedObjectPath,
    ) -> zbus::Result<()>;
}
