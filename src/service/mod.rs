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

pub mod collection;
pub mod item;
mod objects;
pub mod session;
mod state;

pub use objects::{
    ALGORITHM_DH, ALGORITHM_PLAIN, SERVICE_PATH, SESSION_COLLECTION_ALIAS, SESSION_COLLECTION_ID,
    alias_path, collection_path, item_path, parse_collection_path, parse_item_path, register_alias,
    register_collection, register_existing, register_item, session_path, unregister_alias,
};
pub use state::ServiceState;

pub(crate) use objects::object_removed_or_absent;
use objects::{register_session_object_with, root_path};

use std::collections::HashMap;
use std::sync::Arc;

use zbus::object_server::{ObjectServer, SignalEmitter};
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zbus::{fdo, interface};

use crate::crypto::{DhHandshake, SessionCipher};
use crate::service::session::Secret;

// --- errors ----------------------------------------------------------------

/// Secret Service and standard D-Bus method errors.
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.freedesktop")]
pub enum SecretError {
    /// Transparent wrapper for errors without a dedicated public variant.
    #[zbus(error)]
    ZBus(zbus::Error),
    /// Invalid client arguments.
    #[zbus(name = "DBus.Error.InvalidArgs")]
    InvalidArgs(String),
    /// The session named in a `Secret` does not exist.
    #[zbus(name = "Secret.Error.NoSession")]
    NoSession(String),
    /// The referenced object does not exist.
    #[zbus(name = "Secret.Error.NoSuchObject")]
    NoSuchObject(String),
}

impl From<fdo::Error> for SecretError {
    fn from(err: fdo::Error) -> Self {
        match err {
            fdo::Error::InvalidArgs(message) => Self::InvalidArgs(message),
            other => Self::ZBus(zbus::Error::FDO(Box::new(other))),
        }
    }
}

impl From<crate::Error> for SecretError {
    fn from(err: crate::Error) -> Self {
        match err {
            crate::Error::NotFound(msg) => Self::NoSuchObject(msg),
            other => fdo::Error::Failed(other.to_string()).into(),
        }
    }
}

// --- the Service interface ---------------------------------------------------

/// The `org.freedesktop.Secret.Service` D-Bus object.
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
pub(crate) fn message_sender(header: &zbus::message::Header<'_>) -> Result<String, SecretError> {
    header
        .sender()
        .map(ToString::to_string)
        .ok_or_else(|| fdo::Error::AccessDenied("missing D-Bus sender identity".into()).into())
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
        input: Value<'_>,
        #[zbus(object_server)] server: &ObjectServer,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> fdo::Result<(OwnedValue, OwnedObjectPath)> {
        let _activity = self.state.activity()?;
        let (output, cipher) = match algorithm {
            ALGORITHM_PLAIN => {
                let input = String::try_from(input).map_err(|_| {
                    fdo::Error::InvalidArgs("plain session input must be an empty string".into())
                })?;
                if !input.is_empty() {
                    return Err(fdo::Error::InvalidArgs(
                        "plain session input must be an empty string".into(),
                    ));
                }
                (
                    Value::from("")
                        .try_to_owned()
                        .map_err(|e| fdo::Error::Failed(e.to_string()))?,
                    SessionCipher::Plain,
                )
            }
            ALGORITHM_DH => {
                let client_pub = Vec::<u8>::try_from(input).map_err(|_| {
                    fdo::Error::InvalidArgs("expected client public key as byte array".into())
                })?;
                let handshake = DhHandshake::generate();
                let server_pub = handshake.public_bytes();
                let cipher = handshake
                    .derive(&client_pub)
                    .map_err(|e| fdo::Error::InvalidArgs(e.to_string()))?;
                (
                    Value::from(server_pub)
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

        let owner = header
            .sender()
            .map(ToString::to_string)
            .ok_or_else(|| fdo::Error::AccessDenied("missing D-Bus sender identity".into()))?;
        let path =
            register_session_object_with(server, &self.state, cipher, owner, rand::random).await?;
        Ok((output, path))
    }

    /// Create a collection.
    ///
    /// If `alias` is non-empty and already resolves to a collection, that
    /// collection is returned instead of creating a new one (spec behavior).
    #[zbus(out_args("collection", "prompt"))]
    async fn create_collection(
        &self,
        properties: HashMap<String, OwnedValue>,
        alias: &str,
        #[zbus(object_server)] server: &ObjectServer,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> fdo::Result<(OwnedObjectPath, OwnedObjectPath)> {
        let _activity = self.state.activity()?;
        let _lifecycle = self.state.lock_object_lifecycle().await;

        let label = match properties.get("org.freedesktop.Secret.Collection.Label") {
            None => None,
            Some(value) => Some(String::try_from(value.clone()).map_err(|_| {
                fdo::Error::InvalidArgs(
                    "org.freedesktop.Secret.Collection.Label must be a string".into(),
                )
            })?),
        };

        if !alias.is_empty()
            && let Some(existing) = self.state.read_alias(alias).map_err(fdo_err)?
            && (existing == SESSION_COLLECTION_ID
                || self.state.store().get_collection(&existing).is_ok())
        {
            let path = collection_path(&existing);
            if let Some(label) = label.as_deref() {
                if existing == SESSION_COLLECTION_ID {
                    self.state
                        .set_session_collection_label(label)
                        .map_err(fdo_err)?;
                } else {
                    self.state
                        .store()
                        .set_collection_label(&existing, label)
                        .map_err(fdo_err)?;
                }
                collection::emit_collection_label_modified(
                    &self.state,
                    server,
                    emitter.connection(),
                    &existing,
                )
                .await?;
                Self::collection_changed(&emitter, path.clone()).await?;
            }
            return Ok((path, root_path()));
        }

        let alias_opt = (!alias.is_empty()).then_some(alias);
        let meta = self
            .state
            .store()
            .create_collection(label.as_deref().unwrap_or(""), alias_opt)
            .map_err(fdo_err)?;

        let path = register_collection(server, &self.state, &meta.id).await?;
        if let Some(alias) = alias_opt {
            register_alias(server, &self.state, alias).await?;
        }
        Self::collection_created(&emitter, path.clone()).await?;
        // Invalidate client-side property caches (zbus proxies cache
        // `Collections` and only refresh on PropertiesChanged).
        self.collections_changed(&emitter).await?;
        Ok((path, root_path()))
    }

    /// Search all collections for items whose attributes are a superset of
    /// `attributes`. The `locked` result is always empty (see module docs).
    #[zbus(out_args("unlocked", "locked"))]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "zbus deserializes method arguments by value"
    )]
    fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> fdo::Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>)> {
        let _activity = self.state.activity()?;
        let mut unlocked: Vec<_> = self
            .state
            .store()
            .search_items(&attributes)
            .map_err(fdo_err)?
            .into_iter()
            .map(|meta| item_path(&meta.collection, &meta.id))
            .collect();
        unlocked.extend(
            self.state
                .search_session_items(&attributes)
                .into_iter()
                .map(|meta| item_path(&meta.collection, &meta.id)),
        );
        Ok((unlocked, Vec::new()))
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
        let _activity = self.state.activity()?;
        let owner = message_sender(&header)?;
        if self.state.session_cipher(&session, &owner).is_none() {
            return Err(SecretError::NoSession(format!("no session {session}")));
        }

        let mut out = HashMap::new();
        for path in items {
            let Some((collection_id, item_id)) = parse_item_path(path.as_str()) else {
                continue;
            };
            if collection_id == SESSION_COLLECTION_ID {
                let (meta, plaintext) = match self.state.read_session_item_secret(&item_id) {
                    Ok(item) => item,
                    Err(crate::Error::NotFound(_)) => continue,
                    Err(err) => return Err(err.into()),
                };
                let secret = self.state.plaintext_to_secret(
                    &session,
                    &plaintext,
                    &meta.content_type,
                    &owner,
                )?;
                out.insert(path, secret);
                continue;
            }

            let (meta, ciphertext) = match self.state.store().read_item_secret(&item_id) {
                Ok(item) => item,
                Err(crate::Error::NotFound(_)) => continue,
                Err(err) => return Err(err.into()),
            };
            if meta.collection != collection_id {
                continue;
            }
            let secret = self
                .state
                .ciphertext_to_secret(&session, &ciphertext, &meta.content_type, &owner)
                .await?;
            out.insert(path, secret);
        }
        Ok(out)
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
        let _activity = self.state.activity()?;
        let _lifecycle = self.state.lock_object_lifecycle().await;
        if name == SESSION_COLLECTION_ALIAS {
            return Err(fdo::Error::NotSupported(
                "the session alias is reserved for temporary secrets".into(),
            )
            .into());
        }
        let previous = self.state.read_alias(name)?;
        if collection.as_str() == "/" {
            self.state.store().set_alias(name, None)?;
            self.state.remove_session_alias(name);
            unregister_alias(server, name)
                .await
                .map_err(SecretError::ZBus)?;
            return Ok(());
        }
        let id = parse_collection_path(collection.as_str()).ok_or_else(|| {
            SecretError::NoSuchObject(format!("{collection} is not a collection path"))
        })?;
        if id == SESSION_COLLECTION_ID {
            self.state.set_session_alias(name)?;
        } else {
            // Verify the collection exists before pointing an alias at it.
            self.state.store().get_collection(&id)?;
            self.state.store().set_alias(name, Some(&id))?;
            self.state.remove_session_alias(name);
        }
        register_alias(server, &self.state, name)
            .await
            .map_err(SecretError::ZBus)?;
        if previous
            .as_deref()
            .is_some_and(|previous| previous != id.as_str())
        {
            collection::emit_alias_target_invalidated(connection, name)
                .await
                .map_err(SecretError::from)?;
        }
        Ok(())
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
