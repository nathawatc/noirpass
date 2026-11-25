//! The `org.freedesktop.Secret.Service` interface and shared daemon state.
//!
//! # Object model
//!
//! * service — `/org/freedesktop/secrets`
//! * collections — `/org/freedesktop/secrets/collection/<id>`
//! * items — `/org/freedesktop/secrets/collection/<col>/<item>`
//! * sessions — `/org/freedesktop/secrets/session/s<n>`
//!
//! # Locking model
//!
//! noirpass is *always unlocked*: `Item.Locked` and `Collection.Locked` are
//! always `false`. Persistent secrets are gated by `gpg-agent`, which enforces
//! the user's passphrase/pinentry policy on decryption. Temporary secrets in
//! the built-in `session` collection are already resident in daemon memory.
//! `Unlock` reports requested objects as already unlocked. `Lock` cannot lock any object, so its
//! `locked` result is empty. No Prompt object is exposed; both methods return
//! `/` as their prompt path. This is a deliberate, documented deviation from
//! keyrings that implement their own locking.

mod bulk;
pub mod collection;
mod error;
pub mod item;
mod namespace;
mod objects;
pub mod session;
mod state;

use bulk::MAX_BULK_SECRET_BYTES;
pub use error::SecretError;
pub use objects::{
    ALGORITHM_DH, ALGORITHM_PLAIN, SERVICE_NAME, SERVICE_PATH, SESSION_COLLECTION_ALIAS,
    SESSION_COLLECTION_ID, alias_path, collection_path, item_path, parse_collection_path,
    parse_item_path, register_alias, register_collection, register_existing, register_item,
    session_path, unregister_alias,
};
pub use state::ServiceState;

pub(crate) use objects::{
    COLLECTION_INTERFACE, COLLECTION_LABEL_PROPERTY, ITEM_ATTRIBUTES_PROPERTY, ITEM_INTERFACE,
    ITEM_LABEL_PROPERTY, object_removed_or_absent,
};
use objects::{register_session_object_with, root_path, validate_session_owner};

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use zbus::names::InterfaceName;
use zbus::object_server::{ObjectServer, SignalEmitter};
use zbus::{OwnedObjectPath, OwnedVariant, Variant};
use zbus::{fdo, interface};

use crate::crypto::{DhHandshake, SessionCipher};
use crate::service::session::Secret;

/// The `org.freedesktop.Secret.Service` D-Bus object.
#[derive(Clone)]
pub struct Service {
    state: Arc<ServiceState>,
}

impl Service {
    /// Create the service object.
    #[must_use]
    pub fn new(state: Arc<ServiceState>) -> Self {
        Self { state }
    }
}

/// Require message-bus sender identity before accessing client-owned state.
fn message_sender_fdo(header: &zbus::message::Header<'_>) -> fdo::Result<String> {
    header
        .sender()
        .map(ToString::to_string)
        .ok_or_else(|| fdo::Error::AccessDenied("missing D-Bus sender identity".into()))
}

/// Require message-bus sender identity before accessing client-owned state.
pub(crate) fn message_sender(header: &zbus::message::Header<'_>) -> Result<String, SecretError> {
    message_sender_fdo(header).map_err(Into::into)
}

/// Emit one `PropertiesChanged` entry for an already-known updated value.
pub(crate) async fn emit_property_changed(
    emitter: &SignalEmitter<'_>,
    interface: &'static str,
    name: &'static str,
    value: Variant<'_>,
) -> fdo::Result<()> {
    fdo::Properties::properties_changed(
        emitter,
        InterfaceName::from_static_str_unchecked(interface),
        HashMap::from([(name, value)]),
        Cow::Borrowed(&[]),
    )
    .await?;
    Ok(())
}

#[interface(name = "org.freedesktop.Secret.Service")]
impl Service {
    /// Open a transport session.
    ///
    /// `plain` requires an empty string as `input` and returns an empty string;
    /// the DH algorithm expects the client's public key as a byte array and
    /// returns ours. Unknown algorithms yield
    /// `org.freedesktop.DBus.Error.NotSupported`.
    #[zbus(out_args("output", "result"))]
    async fn open_session(
        &self,
        algorithm: &str,
        input: Variant<'_>,
        #[zbus(object_server)] server: &ObjectServer,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> fdo::Result<(OwnedVariant, OwnedObjectPath)> {
        let activity = self.state.request(&(algorithm, &input))?;
        let (owner, output, cipher) = match algorithm {
            ALGORITHM_PLAIN => {
                let input = String::try_from(input).map_err(|_| {
                    fdo::Error::InvalidArgs("plain session input must be an empty string".into())
                })?;
                if !input.is_empty() {
                    return Err(fdo::Error::InvalidArgs(
                        "plain session input must be an empty string".into(),
                    ));
                }
                let owner = message_sender_fdo(&header)?;
                self.state.ensure_session_capacity(&owner)?;
                (
                    owner,
                    Variant::from("")
                        .try_to_owned()
                        .map_err(|e| fdo::Error::Failed(e.to_string()))?,
                    SessionCipher::Plain,
                )
            }
            ALGORITHM_DH => {
                let client_pub = Vec::<u8>::try_from(input).map_err(|_| {
                    fdo::Error::InvalidArgs("expected client public key as byte array".into())
                })?;
                let owner = message_sender_fdo(&header)?;
                self.state.ensure_session_capacity(&owner)?;
                let (server_pub, cipher) = DhHandshake::respond(&client_pub)
                    .map_err(|e| fdo::Error::InvalidArgs(e.to_string()))?;
                (
                    owner,
                    Variant::from(server_pub)
                        .try_to_owned()
                        .map_err(|e| fdo::Error::Failed(e.to_string()))?,
                    cipher,
                )
            }
            other => {
                return Err(fdo::Error::NotSupported(format!(
                    "unsupported session algorithm {other}"
                )));
            }
        };

        let state = self.state.clone();
        let server = server.clone();
        let connection = connection.clone();
        activity
            .spawn("session registration failed", async move {
                let path = register_session_object_with(
                    &server,
                    &state,
                    cipher,
                    owner.clone(),
                    rand::random,
                )
                .await?;
                if connection.is_bus() {
                    let presence = async {
                        let proxy = zbus::fdo::DBusProxy::new(&connection).await?;
                        let name = zbus::names::BusName::try_from(owner.as_str())
                            .map_err(|err| fdo::Error::InvalidArgs(err.to_string()))?;
                        proxy.name_has_owner(name).await
                    };
                    validate_session_owner(&server, &state, &path, &owner, presence).await?;
                }
                Ok((output, path))
            })
            .await
    }

    /// Create a collection.
    ///
    /// If `alias` is non-empty and already resolves to a collection, that
    /// collection is returned instead of creating a new one (spec behavior).
    #[zbus(out_args("collection", "prompt"))]
    async fn create_collection(
        &self,
        properties: HashMap<String, OwnedVariant>,
        alias: &str,
        #[zbus(object_server)] server: &ObjectServer,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> fdo::Result<(OwnedObjectPath, OwnedObjectPath)> {
        let activity = self.state.request(&(&properties, alias))?;
        let object = self.clone();
        let alias = alias.to_string();
        let server = server.clone();
        let emitter = emitter.into_owned();
        activity
            .spawn("collection creation failed", async move {
                object
                    .create_collection_inner(properties, &alias, &server, &emitter)
                    .await
            })
            .await
    }

    /// Search all collections for items whose attributes are a superset of
    /// `attributes`. The `locked` result is always empty (see module docs).
    #[zbus(out_args("unlocked", "locked"))]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "zbus deserializes method arguments by value"
    )]
    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> fdo::Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>)> {
        let activity = self.state.request(&attributes)?;
        let state = self.state.clone();
        activity
            .spawn("item search failed", async move {
                let query = attributes.clone();
                let mut unlocked: Vec<_> = state
                    .blocking(None, move |state| Ok(state.store().search_items(&query)?))
                    .await?
                    .into_iter()
                    .map(|meta| item_path(&meta.collection, &meta.id))
                    .collect();
                unlocked.extend(
                    state
                        .search_session_items(&attributes)
                        .into_iter()
                        .map(|meta| item_path(&meta.collection, &meta.id)),
                );
                Ok((unlocked, Vec::new()))
            })
            .await
    }

    /// Unlock objects. Everything is already unlocked, so all inputs are
    /// returned immediately and no prompt is needed.
    #[zbus(out_args("unlocked", "prompt"))]
    fn unlock(
        &self,
        objects: Vec<OwnedObjectPath>,
    ) -> fdo::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)> {
        let _activity = self.state.activity()?;
        Ok((objects, root_path()))
    }

    /// Lock objects. Noirpass has no lock state, so no object can be
    /// successfully locked. The `locked` result is empty, `Locked` stays
    /// `false`, and `gpg-agent` remains the real gate on secret access.
    #[zbus(out_args("locked", "prompt"))]
    fn lock(
        &self,
        objects: Vec<OwnedObjectPath>,
    ) -> fdo::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)> {
        let _activity = self.state.activity()?;
        drop(objects);
        Ok((Vec::new(), root_path()))
    }

    /// Fetch the secrets of multiple items in one round trip.
    ///
    /// Item paths that do not resolve to a current item are silently skipped
    /// (lenient interop choice); a bad transport session is an error.
    #[zbus(out_args("secrets"))]
    async fn get_secrets(
        &self,
        items: Vec<OwnedObjectPath>,
        session: OwnedObjectPath,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<HashMap<OwnedObjectPath, Secret>, SecretError> {
        let activity = self.state.request(&(&items, &session))?;
        activity
            .clone()
            .run(async {
                let owner = message_sender(&header)?;
                bulk::get_secrets(&self.state, &activity, &items, &session, &owner).await
            })
            .await
    }

    /// Resolve an alias to a collection path. Unknown aliases return `/`.
    #[zbus(out_args("collection"))]
    fn read_alias(&self, name: &str) -> fdo::Result<OwnedObjectPath> {
        let _activity = self.state.activity()?;
        match self.state.read_alias(name).map_err(fdo_err)? {
            Some(id)
                if id == SESSION_COLLECTION_ID
                    || self.state.store().get_collection(&id).is_ok() =>
            {
                Ok(collection_path(&id))
            }
            _ => Ok(root_path()),
        }
    }

    /// Point an alias at a collection, or remove it when `collection` is `/`.
    ///
    /// Also serves/removes the matching `.../aliases/<name>` object.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "zbus deserializes method arguments by value"
    )]
    async fn set_alias(
        &self,
        name: &str,
        collection: OwnedObjectPath,
        #[zbus(object_server)] server: &ObjectServer,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<(), SecretError> {
        let activity = self.state.request(&(name, &collection))?;
        let object = self.clone();
        let name = name.to_string();
        let server = server.clone();
        let connection = connection.clone();
        activity
            .spawn("alias mutation failed", async move {
                object
                    .set_alias_inner(&name, collection, &server, &connection)
                    .await
            })
            .await
    }

    /// Object paths of all collections.
    #[zbus(property)]
    fn collections(&self) -> fdo::Result<Vec<OwnedObjectPath>> {
        let _activity = self.state.activity()?;
        let collections = self.state.store().list_collections().map_err(fdo_err)?;
        let mut paths = vec![collection_path(SESSION_COLLECTION_ID)];
        paths.extend(
            collections
                .into_iter()
                .map(|meta| collection_path(&meta.id)),
        );
        Ok(paths)
    }

    /// A collection was created.
    #[zbus(signal)]
    pub async fn collection_created(
        emitter: &SignalEmitter<'_>,
        collection: OwnedObjectPath,
    ) -> zbus::Result<()>;

    /// A collection was deleted.
    #[zbus(signal)]
    pub async fn collection_deleted(
        emitter: &SignalEmitter<'_>,
        collection: OwnedObjectPath,
    ) -> zbus::Result<()>;

    /// A collection changed (e.g. relabelled).
    #[zbus(signal)]
    pub async fn collection_changed(
        emitter: &SignalEmitter<'_>,
        collection: OwnedObjectPath,
    ) -> zbus::Result<()>;
}

/// Shorthand: map a core error onto its D-Bus representation.
fn fdo_err(err: crate::Error) -> fdo::Error {
    err.into()
}

#[cfg(test)]
mod tests;
