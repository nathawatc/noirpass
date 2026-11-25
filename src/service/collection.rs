//! `org.freedesktop.Secret.Collection` objects.
//!
//! One object per collection, served at
//! `/org/freedesktop/secrets/collection/<id>`. Persistent collections resolve
//! through the store; the built-in `session` collection is process-memory-only.
//! The same interface is *also*
//! served at the spec's alias paths (`/org/freedesktop/secrets/aliases/<name>`,
//! e.g. `aliases/default`, which libsecret uses directly): an alias-backed
//! instance resolves the target collection through the store on every call, so
//! re-pointing an alias is reflected immediately. Collections are always
//! unlocked (see [`crate::service`] module docs for the locking rationale).

mod mutation;
mod signals;

#[cfg(test)]
pub(crate) use signals::emit_collection_items_changed;
pub(crate) use signals::{
    emit_alias_target_invalidated, emit_collection_items_and_modified,
    emit_collection_label_modified, emit_collection_modified,
};

use std::collections::HashMap;
use std::sync::Arc;

use zbus::object_server::{ObjectServer, SignalEmitter};
use zbus::{OwnedObjectPath, OwnedVariant};
use zbus::{fdo, interface};

use crate::service::objects::root_path;
use crate::service::session::Secret;
use crate::service::{SESSION_COLLECTION_ID, SecretError, ServiceState, item_path, message_sender};

const COLLECTION_INTERFACE: &str = "org.freedesktop.Secret.Collection";

/// What a served collection object points at.
#[derive(Clone)]
enum Target {
    /// A collection by id (the canonical `/collection/<id>` object).
    Collection(String),
    /// An alias resolved through the store on every call
    /// (the `/aliases/<name>` objects).
    Alias(String),
}

/// A `org.freedesktop.Secret.Collection` D-Bus object.
#[derive(Clone)]
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
                .read_alias(name)
                .map_err(fdo::Error::from)?
                .ok_or_else(|| fdo::Error::UnknownObject(format!("alias {name} is not set"))),
        }
    }

    fn metadata(&self) -> fdo::Result<crate::store::CollectionMeta> {
        let id = self.resolve_id()?;
        if id == SESSION_COLLECTION_ID {
            Ok(self.state.session_collection_meta())
        } else {
            self.state
                .store()
                .get_collection(&id)
                .map_err(fdo::Error::from)
        }
    }

    /// Resolve an alias after worker admission and preserve property error names.
    fn item_paths(&self) -> fdo::Result<Vec<OwnedObjectPath>> {
        let id = self.resolve_id()?;
        let items = if id == SESSION_COLLECTION_ID {
            self.state.list_session_items()
        } else {
            self.state
                .store()
                .search_collection_items(&id, &HashMap::new())
                .map_err(fdo::Error::from)?
        };
        Ok(items
            .into_iter()
            .map(|meta| item_path(&meta.collection, &meta.id))
            .collect())
    }

    #[cfg(test)]
    pub(crate) async fn create_item_for_test(
        &self,
        secret: Secret,
        server: &ObjectServer,
        connection: &zbus::Connection,
        header: zbus::message::Header<'_>,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath), SecretError> {
        self.create_item(HashMap::new(), secret, false, server, connection, header)
            .await
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
    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> fdo::Result<Vec<OwnedObjectPath>> {
        let activity = self.state.request(&attributes)?;
        let object = self.clone();
        tokio::spawn(activity.run(async move {
            let id = object.resolve_id()?;
            let items = if id == SESSION_COLLECTION_ID {
                object.state.search_session_items(&attributes)
            } else {
                object
                    .state
                    .blocking(None, move |state| {
                        Ok(state.store().search_collection_items(&id, &attributes)?)
                    })
                    .await?
            };
            Ok(items
                .into_iter()
                .map(|meta| item_path(&meta.collection, &meta.id))
                .collect())
        }))
        .await
        .map_err(|_| fdo::Error::Failed("collection search failed".into()))?
    }

    /// Create (or replace) an item in this collection.
    ///
    /// The incoming [`Secret`] is decrypted with its transport session cipher.
    /// Persistent collections re-encrypt it to the user's `OpenPGP` key before
    /// disk; the built-in `session` collection keeps only zeroizing memory. With
    /// `replace = true`, an item whose attributes match exactly is updated in
    /// place (`ItemChanged`); otherwise a new item is created (`ItemCreated`).
    /// Signals are emitted from the canonical collection path, also when this
    /// call arrives via an alias path.
    #[zbus(out_args("item", "prompt"))]
    async fn create_item(
        &self,
        properties: HashMap<String, OwnedVariant>,
        secret: Secret,
        replace: bool,
        #[zbus(object_server)] server: &ObjectServer,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath), SecretError> {
        let activity = self.state.request(&(&properties, &secret, replace))?;
        let owner = message_sender(&header)?;
        let object = self.clone();
        let server = server.clone();
        let connection = connection.clone();
        tokio::spawn(activity.run(async move {
            object
                .create_item_inner(properties, secret, replace, &server, &connection, &owner)
                .await
        }))
        .await
        .map_err(|_| fdo::Error::Failed("secret mutation failed".into()))?
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
        let activity = self.state.request(&0u8)?;
        let object = self.clone();
        let server = server.clone();
        let connection = connection.clone();
        tokio::spawn(activity.run(async move { object.delete_inner(&server, &connection).await }))
            .await
            .map_err(|_| fdo::Error::Failed("collection deletion failed".into()))?
    }

    /// Object paths of the items in this collection.
    #[zbus(property)]
    async fn items(&self) -> fdo::Result<Vec<OwnedObjectPath>> {
        let activity = Arc::new(self.state.activity()?);
        if matches!(&self.target, Target::Collection(id) if id == SESSION_COLLECTION_ID)
            || matches!(&self.target, Target::Alias(name) if self.state.is_session_alias(name))
        {
            return Ok(self
                .state
                .list_session_items()
                .into_iter()
                .map(|meta| item_path(&meta.collection, &meta.id))
                .collect());
        }
        let object = self.clone();
        Ok(self
            .state
            .blocking_admitted(activity, None, move |_| Ok(object.item_paths()?))
            .await?)
    }

    /// Human-readable label.
    #[zbus(property(emits_changed_signal = "false"))]
    fn label(&self) -> fdo::Result<String> {
        let _activity = self.state.activity()?;
        let meta = self.metadata()?;
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
        let activity = self.state.request(label)?;
        let object = self.clone();
        let label = label.to_string();
        let server = server.clone();
        let connection = connection.clone();
        tokio::spawn(
            activity.run(async move { object.set_label_inner(&label, &server, &connection).await }),
        )
        .await
        .map_err(|_| fdo::Error::Failed("collection metadata mutation failed".into()))?
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
