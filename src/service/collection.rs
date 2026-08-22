//! `org.freedesktop.Secret.Collection` objects.
//!
//! One object per stored collection, served at
//! `/org/freedesktop/secrets/collection/<id>`. The same interface is *also*
//! served at the spec's alias paths (`/org/freedesktop/secrets/aliases/<name>`,
//! e.g. `aliases/default`, which libsecret uses directly): an alias-backed
//! instance resolves the target collection through the store on every call, so
//! re-pointing an alias is reflected immediately. Collections are always
//! unlocked (see [`crate::service`] module docs for the locking rationale).

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use zbus::names::InterfaceName;
use zbus::object_server::{ObjectServer, SignalEmitter};
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zbus::{fdo, interface};

use crate::service::item::Item;
use crate::service::session::Secret;
use crate::service::{
    SERVICE_PATH, SecretError, Service, ServiceState, alias_path, collection_path, item_path,
    message_sender, object_removed_or_absent, register_item,
};

/// The "no prompt" object path.
fn no_prompt() -> OwnedObjectPath {
    OwnedObjectPath::try_from("/").expect("/ is a valid object path")
}

const COLLECTION_INTERFACE: &str = "org.freedesktop.Secret.Collection";

/// Return the canonical path and every valid persisted alias path for `id`.
fn collection_object_paths_for_id(
    state: &ServiceState,
    id: &str,
) -> fdo::Result<Vec<OwnedObjectPath>> {
    let mut paths = vec![collection_path(id)];
    for (name, target) in state.store().list_aliases().map_err(fdo::Error::from)? {
        if target == id
            && let Ok(path) = alias_path(&name)
        {
            paths.push(path);
        }
    }
    Ok(paths)
}

/// Emit Label and Modified for every served path representing `id`.
pub(crate) async fn emit_collection_label_modified(
    state: &ServiceState,
    server: &ObjectServer,
    connection: &zbus::Connection,
    id: &str,
) -> fdo::Result<()> {
    for path in collection_object_paths_for_id(state, id)? {
        let collection_ref = server.interface::<_, Collection>(&path).await?;
        let collection = collection_ref.get().await;
        let emitter = SignalEmitter::new(connection, path)?;
        collection.emit_label_changed(&emitter).await?;
        collection.modified_changed(&emitter).await?;
    }
    Ok(())
}

/// Emit Items for every served path representing `id`.
pub(crate) async fn emit_collection_items_changed(
    state: &ServiceState,
    server: &ObjectServer,
    connection: &zbus::Connection,
    id: &str,
) -> fdo::Result<()> {
    for path in collection_object_paths_for_id(state, id)? {
        let collection_ref = server.interface::<_, Collection>(&path).await?;
        let collection = collection_ref.get().await;
        let emitter = SignalEmitter::new(connection, path)?;
        collection.items_changed(&emitter).await?;
    }
    Ok(())
}

/// Invalidate alias properties that resolve through its persisted target.
pub(crate) async fn emit_alias_target_invalidated(
    connection: &zbus::Connection,
    name: &str,
) -> fdo::Result<()> {
    let Ok(path) = alias_path(name) else {
        return Ok(());
    };
    let emitter = SignalEmitter::new(connection, path)?;
    fdo::Properties::properties_changed(
        &emitter,
        InterfaceName::from_static_str_unchecked(COLLECTION_INTERFACE),
        HashMap::new(),
        Cow::Borrowed(&["Items", "Label", "Created", "Modified"]),
    )
    .await?;
    Ok(())
}

/// What a served collection object points at.
enum Target {
    /// A collection by id (the canonical `/collection/<id>` object).
    Collection(String),
    /// An alias resolved through the store on every call
    /// (the `/aliases/<name>` objects).
    Alias(String),
}

/// A `org.freedesktop.Secret.Collection` D-Bus object.
pub struct Collection {
    state: Arc<ServiceState>,
    target: Target,
}

impl Collection {
    /// Create a collection object for the stored collection `id`.
    #[must_use]
    pub fn new(state: Arc<ServiceState>, id: String) -> Self {
        Self {
            state,
            target: Target::Collection(id),
        }
    }

    /// Create a collection object that resolves the alias `name` at call time.
    #[must_use]
    pub fn for_alias(state: Arc<ServiceState>, name: String) -> Self {
        Self {
            state,
            target: Target::Alias(name),
        }
    }

    /// The id of the collection this object currently points at.
    ///
    /// For alias-backed objects this re-reads the alias, so a dangling or
    /// removed alias yields `UnknownObject`.
    fn resolve_id(&self) -> fdo::Result<String> {
        match &self.target {
            Target::Collection(id) => Ok(id.clone()),
            Target::Alias(name) => self
                .state
                .store()
                .read_alias(name)
                .map_err(fdo::Error::from)?
                .ok_or_else(|| fdo::Error::UnknownObject(format!("alias {name} is not set"))),
        }
    }

    /// Emit the changed signal for Label while mutation serialization remains held.
    async fn emit_label_changed(&self, emitter: &SignalEmitter<'_>) -> fdo::Result<()> {
        let mut changed = HashMap::new();
        changed.insert("Label", Value::from(self.label()?));
        fdo::Properties::properties_changed(
            emitter,
            InterfaceName::from_static_str_unchecked(COLLECTION_INTERFACE),
            changed,
            Cow::Borrowed(&[]),
        )
        .await?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) async fn delete_for_test(
        &self,
        server: &ObjectServer,
        connection: &zbus::Connection,
    ) -> Result<OwnedObjectPath, SecretError> {
        self.delete(server, connection).await
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
        let _activity = self.state.activity()?;
        let id = self.resolve_id()?;
        let results = self
            .state
            .store()
            .search_items(&attributes)
            .map_err(fdo::Error::from)?
            .into_iter()
            .filter(|meta| meta.collection == id)
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
    /// Signals are emitted from the canonical collection path, also when this
    /// call arrives via an alias path.
    #[zbus(out_args("item", "prompt"))]
    async fn create_item(
        &self,
        properties: HashMap<String, OwnedValue>,
        secret: Secret,
        replace: bool,
        #[zbus(object_server)] server: &ObjectServer,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath), SecretError> {
        let _activity = self.state.activity()?;
        let _lifecycle = self.state.lock_object_lifecycle().await;
        let label = match properties.get("org.freedesktop.Secret.Item.Label") {
            None => String::new(),
            Some(value) => String::try_from(value.clone()).map_err(|_| {
                SecretError::InvalidArgs(
                    "org.freedesktop.Secret.Item.Label must be a string".into(),
                )
            })?,
        };
        let attributes = match properties.get("org.freedesktop.Secret.Item.Attributes") {
            None => HashMap::new(),
            Some(value) => HashMap::<String, String>::try_from(value.clone()).map_err(|_| {
                SecretError::InvalidArgs(
                    "org.freedesktop.Secret.Item.Attributes must be a string dictionary".into(),
                )
            })?,
        };

        let id = self.resolve_id()?;
        let owner = message_sender(&header)?;

        let ciphertext = self.state.secret_to_ciphertext(&secret, &owner)?;

        // Emit from the canonical collection path regardless of how we were
        // addressed (id or alias).
        let emitter =
            SignalEmitter::new(connection, collection_path(&id)).map_err(SecretError::ZBus)?;

        let (meta, replaced) = self.state.store().create_or_replace_item(
            &id,
            &label,
            attributes,
            &secret.content_type,
            &ciphertext,
            replace,
        )?;
        let path = register_item(server, &self.state, &id, &meta.id)
            .await
            .map_err(SecretError::ZBus)?;
        if replaced {
            let item_emitter = SignalEmitter::new(connection, path.clone())?;
            let item_ref = server.interface::<_, Item>(&path).await?;
            let item = item_ref.get().await;
            item.emit_label_changed(&item_emitter).await?;
            item.modified_changed(&item_emitter).await?;
            Self::item_changed(&emitter, path.clone()).await?;
            return Ok((path, no_prompt()));
        }
        Self::item_created(&emitter, path.clone()).await?;
        // Refresh client-side caches of the `Items` property on every path.
        emit_collection_items_changed(&self.state, server, connection, &id).await?;
        Ok((path, no_prompt()))
    }

    /// Delete this collection, all its items and their secret files.
    ///
    /// Also unregisters any alias objects that pointed at it. Deleting the
    /// default collection is allowed; `ensure_default` recreates it on the
    /// next daemon startup.
    #[zbus(out_args("prompt"))]
    async fn delete(
        &self,
        #[zbus(object_server)] server: &ObjectServer,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<OwnedObjectPath, SecretError> {
        let _activity = self.state.activity()?;
        let _lifecycle = self.state.lock_object_lifecycle().await;
        let id = self.resolve_id()?;
        let real_path = collection_path(&id);

        let deleted = self.state.store().delete_collection(&id)?;

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

        // CollectionDeleted is a Service signal, emitted from the service path.
        let emitter = SignalEmitter::new(connection, SERVICE_PATH).map_err(SecretError::ZBus)?;
        Service::collection_deleted(&emitter, real_path)
            .await
            .map_err(SecretError::ZBus)?;
        // Refresh client-side caches of the service's `Collections` property.
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

        Ok(no_prompt())
    }

    /// Object paths of the items in this collection.
    #[zbus(property)]
    fn items(&self) -> fdo::Result<Vec<OwnedObjectPath>> {
        let _activity = self.state.activity()?;
        let id = self.resolve_id()?;
        let items = self
            .state
            .store()
            .list_items(&id)
            .map_err(fdo::Error::from)?;
        Ok(items
            .into_iter()
            .map(|meta| item_path(&meta.collection, &meta.id))
            .collect())
    }

    /// Human-readable label.
    #[zbus(property(emits_changed_signal = "false"))]
    fn label(&self) -> fdo::Result<String> {
        let _activity = self.state.activity()?;
        let id = self.resolve_id()?;
        let meta = self
            .state
            .store()
            .get_collection(&id)
            .map_err(fdo::Error::from)?;
        Ok(meta.label)
    }

    /// Relabel the collection (bumps the modified timestamp and emits
    /// `CollectionChanged` on the service).
    #[zbus(property)]
    async fn set_label(
        &self,
        label: &str,
        #[zbus(object_server)] server: &ObjectServer,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> fdo::Result<()> {
        let _activity = self.state.activity()?;
        let _lifecycle = self.state.lock_object_lifecycle().await;
        let id = self.resolve_id()?;
        self.state
            .store()
            .set_collection_label(&id, label)
            .map_err(fdo::Error::from)?;
        emit_collection_label_modified(&self.state, server, connection, &id).await?;
        let emitter = SignalEmitter::new(connection, SERVICE_PATH)?;
        Service::collection_changed(&emitter, collection_path(&id)).await?;
        Ok(())
    }

    /// Always `false`: noirpass has no lock state (`gpg-agent` is the gate).
    #[zbus(property)]
    fn locked(&self) -> fdo::Result<bool> {
        let _activity = self.state.activity()?;
        Ok(false)
    }

    /// Creation time, seconds since the Unix epoch.
    #[zbus(property)]
    fn created(&self) -> fdo::Result<u64> {
        let _activity = self.state.activity()?;
        let id = self.resolve_id()?;
        let meta = self
            .state
            .store()
            .get_collection(&id)
            .map_err(fdo::Error::from)?;
        Ok(meta.created)
    }

    /// Last modification time, seconds since the Unix epoch.
    #[zbus(property)]
    fn modified(&self) -> fdo::Result<u64> {
        let _activity = self.state.activity()?;
        let id = self.resolve_id()?;
        let meta = self
            .state
            .store()
            .get_collection(&id)
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
