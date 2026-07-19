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
//! noirpass is *always unlocked*: the real gate on secrets is `gpg-agent`,
//! which enforces the user's passphrase/pinentry policy on every decryption.
//! `Lock`/`Unlock` therefore complete immediately and `Locked` is always
//! `false`; this is a deliberate, documented deviation from keyrings that
//! implement their own locking.

use std::collections::{HashMap, hash_map::Entry};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard};
use zbus::object_server::{ObjectServer, SignalEmitter};
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zbus::{fdo, interface};

use crate::crypto::{DhHandshake, SessionCipher};
use crate::gpg::Gpg;
use crate::session::{Secret, Session};
use crate::store::Store;

/// Path of the service object.
pub const SERVICE_PATH: &str = "/org/freedesktop/secrets";

/// The DH session algorithm identifier from the Secret Service spec.
pub const ALGORITHM_DH: &str = "dh-ietf1024-sha256-aes128-cbc-pkcs7";

/// The plain (no transport encryption) session algorithm identifier.
pub const ALGORITHM_PLAIN: &str = "plain";

/// Bound retries so a broken entropy source fails instead of looping forever.
/// Exhausting this with random 128-bit IDs requires 128 consecutive collisions.
const SESSION_ALLOCATION_ATTEMPTS: usize = 128;

// --- path helpers ---------------------------------------------------------

/// The "no object" path used for prompt-less returns and unset aliases.
fn root_path() -> OwnedObjectPath {
    OwnedObjectPath::try_from("/").expect("/ is a valid object path")
}

/// D-Bus path of a collection. Collection ids are hex strings (or `default`),
/// which are always valid path elements.
#[must_use]
pub fn collection_path(collection_id: &str) -> OwnedObjectPath {
    OwnedObjectPath::try_from(format!("{SERVICE_PATH}/collection/{collection_id}"))
        .expect("collection ids are valid path elements")
}

/// D-Bus path of an item inside a collection.
#[must_use]
pub fn item_path(collection_id: &str, item_id: &str) -> OwnedObjectPath {
    OwnedObjectPath::try_from(format!(
        "{SERVICE_PATH}/collection/{collection_id}/{item_id}"
    ))
    .expect("ids are valid path elements")
}

/// D-Bus path of session number `n`.
#[must_use]
pub fn session_path(n: u128) -> OwnedObjectPath {
    OwnedObjectPath::try_from(format!("{SERVICE_PATH}/session/s{n}"))
        .expect("session numbers are valid path elements")
}

/// D-Bus alias path (`.../aliases/<name>`), per the Secret Service spec.
///
/// Fails for alias names that are not valid path elements; such aliases are
/// still stored and resolvable through `ReadAlias`, they just get no object.
pub fn alias_path(name: &str) -> zbus::Result<OwnedObjectPath> {
    Ok(OwnedObjectPath::try_from(format!(
        "{SERVICE_PATH}/aliases/{name}"
    ))?)
}

/// Extract the collection id from a collection path, if it is one.
#[must_use]
pub fn parse_collection_path(path: &str) -> Option<String> {
    let rest = path.strip_prefix("/org/freedesktop/secrets/collection/")?;
    if rest.is_empty() || rest.contains('/') {
        return None;
    }
    Some(rest.to_string())
}

/// Extract `(collection_id, item_id)` from an item path, if it is one.
#[must_use]
pub fn parse_item_path(path: &str) -> Option<(String, String)> {
    let rest = path.strip_prefix("/org/freedesktop/secrets/collection/")?;
    let (collection, item) = rest.split_once('/')?;
    if collection.is_empty() || item.is_empty() || item.contains('/') {
        return None;
    }
    Some((collection.to_string(), item.to_string()))
}

// --- errors ----------------------------------------------------------------

/// Custom Secret Service D-Bus errors (`org.freedesktop.Secret.Error.*`).
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.freedesktop.Secret.Error")]
pub enum SecretError {
    /// Transparent wrapper so standard zbus/fdo errors keep their names.
    #[zbus(error)]
    ZBus(zbus::Error),
    /// The session named in a `Secret` does not exist.
    NoSession(String),
    /// The referenced object does not exist.
    NoSuchObject(String),
    /// The object is locked (unused: noirpass is always unlocked).
    IsLocked(String),
}

impl From<fdo::Error> for SecretError {
    fn from(err: fdo::Error) -> Self {
        Self::ZBus(zbus::Error::FDO(Box::new(err)))
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

// --- shared state -----------------------------------------------------------

/// A registered session: its transport cipher and the unique bus name of the
/// client that opened it (used to reap sessions of vanished clients).
struct SessionEntry {
    cipher: Arc<SessionCipher>,
    owner: String,
}

/// State shared by every D-Bus object of the daemon.
pub struct ServiceState {
    store: Store,
    gpg: Gpg,
    sessions: Mutex<HashMap<OwnedObjectPath, SessionEntry>>,
    last_activity: Mutex<Instant>,
    object_lifecycle: AsyncMutex<()>,
}

impl ServiceState {
    /// Bundle the storage and `GnuPG` handles into shared daemon state.
    #[must_use]
    pub fn new(store: Store, gpg: Gpg) -> Arc<Self> {
        Arc::new(Self {
            store,
            gpg,
            sessions: Mutex::new(HashMap::new()),
            last_activity: Mutex::new(Instant::now()),
            object_lifecycle: AsyncMutex::new(()),
        })
    }

    /// The metadata/secret store.
    #[must_use]
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// The `OpenPGP` encryption handle.
    #[must_use]
    pub fn gpg(&self) -> &Gpg {
        &self.gpg
    }

    /// Serialize Store mutations with matching D-Bus object lifecycle changes.
    pub(crate) async fn lock_object_lifecycle(&self) -> AsyncMutexGuard<'_, ()> {
        self.object_lifecycle.lock().await
    }

    /// Record D-Bus activity now. Called at the top of every method handler
    /// so the idle-exit timer only fires on a genuinely quiet bus.
    pub fn touch(&self) {
        *self.last_activity.lock().expect("activity lock poisoned") = Instant::now();
    }

    /// Time elapsed since the last recorded activity.
    #[must_use]
    pub fn idle_for(&self) -> Duration {
        self.last_activity
            .lock()
            .expect("activity lock poisoned")
            .elapsed()
    }

    /// Number of currently open sessions.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.lock().expect("session lock poisoned").len()
    }

    /// Register a session cipher for the opening client's unique bus name.
    pub fn register_session(
        &self,
        cipher: SessionCipher,
        owner: String,
    ) -> fdo::Result<OwnedObjectPath> {
        self.register_session_with(cipher, owner, rand::random)
    }

    fn register_session_with<F>(
        &self,
        cipher: SessionCipher,
        owner: String,
        mut next_id: F,
    ) -> fdo::Result<OwnedObjectPath>
    where
        F: FnMut() -> u128,
    {
        let mut sessions = self.sessions.lock().expect("session lock poisoned");
        for _ in 0..SESSION_ALLOCATION_ATTEMPTS {
            let path = session_path(next_id());
            if let Entry::Vacant(entry) = sessions.entry(path.clone()) {
                entry.insert(SessionEntry {
                    cipher: Arc::new(cipher),
                    owner,
                });
                return Ok(path);
            }
        }
        Err(fdo::Error::Failed(format!(
            "could not allocate session path after {SESSION_ALLOCATION_ATTEMPTS} attempts"
        )))
    }

    /// Drop every session owned by `owner` (a unique bus name that vanished),
    /// returning the object paths so their D-Bus objects can be removed.
    /// Without this, clients that exit without calling `Session.Close` (most
    /// of them) would pin `session_count` above zero and block idle-exit.
    pub fn remove_sessions_owned_by(&self, owner: &str) -> Vec<OwnedObjectPath> {
        let mut sessions = self.sessions.lock().expect("session lock poisoned");
        let paths: Vec<OwnedObjectPath> = sessions
            .iter()
            .filter(|(_, entry)| entry.owner == owner)
            .map(|(path, _)| path.clone())
            .collect();
        for path in &paths {
            sessions.remove(path);
        }
        paths
    }

    /// Remove a session; returns whether it existed.
    pub fn remove_session(&self, path: &OwnedObjectPath, owner: &str) -> bool {
        let mut sessions = self.sessions.lock().expect("session lock poisoned");
        if sessions.get(path).is_some_and(|entry| entry.owner == owner) {
            sessions.remove(path);
            true
        } else {
            false
        }
    }

    /// Look up the cipher of an open session owned by `owner`.
    #[must_use]
    pub fn session_cipher(
        &self,
        path: &OwnedObjectPath,
        owner: &str,
    ) -> Option<Arc<SessionCipher>> {
        self.sessions
            .lock()
            .expect("session lock poisoned")
            .get(path)
            .filter(|entry| entry.owner == owner)
            .map(|entry| entry.cipher.clone())
    }

    /// Decrypt an incoming [`Secret`] with its session cipher, `gpg`-encrypt
    /// the plaintext for storage and return the at-rest ciphertext.
    pub fn secret_to_ciphertext(
        &self,
        secret: &Secret,
        owner: &str,
    ) -> Result<Vec<u8>, SecretError> {
        let cipher = self
            .session_cipher(&secret.session, owner)
            .ok_or_else(|| SecretError::NoSession(format!("no session {}", secret.session)))?;
        let plaintext = cipher.decrypt(&secret.parameters, &secret.value)?;
        Ok(self.gpg.encrypt(&plaintext)?)
    }

    /// Decrypt an item's at-rest ciphertext via `gpg-agent` and re-encrypt it
    /// for transport under `session`'s cipher.
    pub async fn ciphertext_to_secret(
        &self,
        session: &OwnedObjectPath,
        ciphertext: &[u8],
        content_type: &str,
        owner: &str,
    ) -> Result<Secret, SecretError> {
        let cipher = self
            .session_cipher(session, owner)
            .ok_or_else(|| SecretError::NoSession(format!("no session {session}")))?;
        let plaintext = self.gpg.decrypt(ciphertext).await?;
        let (parameters, value) = cipher.encrypt(&plaintext);
        Ok(Secret {
            session: session.clone(),
            parameters,
            value,
            content_type: content_type.to_string(),
        })
    }
}

// --- object registration -----------------------------------------------------

async fn register_session_object_with<F>(
    server: &ObjectServer,
    state: &Arc<ServiceState>,
    cipher: SessionCipher,
    owner: String,
    next_id: F,
) -> fdo::Result<OwnedObjectPath>
where
    F: FnMut() -> u128,
{
    // Reserve map state before exposing the D-Bus object. Never hold the
    // synchronous session mutex across ObjectServer::at().
    let path = state.register_session_with(cipher, owner.clone(), next_id)?;
    match server
        .at(&path, Session::new(state.clone(), path.clone()))
        .await
    {
        Ok(true) if state.session_cipher(&path, &owner).is_some() => Ok(path),
        Ok(true) => {
            // Owner disconnected while ObjectServer::at() yielded.
            let _ = server.remove::<Session, _>(&path).await;
            Err(fdo::Error::Failed(
                "session owner disconnected during registration".into(),
            ))
        }
        Ok(false) => {
            state.remove_session(&path, &owner);
            Err(fdo::Error::Failed(format!(
                "session object path {path} is already registered"
            )))
        }
        Err(err) => {
            state.remove_session(&path, &owner);
            // ObjectServer::at() can add the interface before a later signal
            // emission fails. Best-effort removal restores both registries.
            let _ = server.remove::<Session, _>(&path).await;
            Err(err.into())
        }
    }
}

/// Serve a [`crate::collection::Collection`] object for `collection_id`.
pub async fn register_collection(
    server: &ObjectServer,
    state: &Arc<ServiceState>,
    collection_id: &str,
) -> zbus::Result<OwnedObjectPath> {
    let path = collection_path(collection_id);
    server
        .at(
            &path,
            crate::collection::Collection::new(state.clone(), collection_id.to_string()),
        )
        .await?;
    Ok(path)
}

/// Serve a [`crate::item::Item`] object for `item_id` in `collection_id`.
pub async fn register_item(
    server: &ObjectServer,
    state: &Arc<ServiceState>,
    collection_id: &str,
    item_id: &str,
) -> zbus::Result<OwnedObjectPath> {
    let path = item_path(collection_id, item_id);
    server
        .at(
            &path,
            crate::item::Item::new(
                state.clone(),
                collection_id.to_string(),
                item_id.to_string(),
            ),
        )
        .await?;
    Ok(path)
}

/// Serve a [`crate::collection::Collection`] object at the alias path
/// `/org/freedesktop/secrets/aliases/<name>` that resolves `name` at call
/// time. Alias names that are not valid path elements are skipped.
pub async fn register_alias(
    server: &ObjectServer,
    state: &Arc<ServiceState>,
    name: &str,
) -> zbus::Result<()> {
    if let Ok(path) = alias_path(name) {
        server
            .at(
                &path,
                crate::collection::Collection::for_alias(state.clone(), name.to_string()),
            )
            .await?;
    }
    Ok(())
}

/// Treat an `ObjectServer` interface as successfully removed when already absent.
pub(crate) fn object_removed_or_absent(result: zbus::Result<bool>) -> zbus::Result<()> {
    match result {
        Ok(_) | Err(zbus::Error::InterfaceNotFound) => Ok(()),
        Err(err) => Err(err),
    }
}

/// Remove the alias object at `/org/freedesktop/secrets/aliases/<name>`,
/// if it exists.
pub async fn unregister_alias(server: &ObjectServer, name: &str) -> zbus::Result<()> {
    if let Ok(path) = alias_path(name) {
        object_removed_or_absent(
            server
                .remove::<crate::collection::Collection, _>(&path)
                .await,
        )?;
    }
    Ok(())
}

/// Serve objects for every collection, item and alias already in the store.
///
/// Called once at startup, after the service object itself is up but before
/// the well-known name is requested.
pub async fn register_existing(
    server: &ObjectServer,
    state: &Arc<ServiceState>,
) -> zbus::Result<()> {
    let collections = state
        .store()
        .list_collections()
        .map_err(|e| zbus::Error::FDO(Box::new(e.into())))?;
    for collection in collections {
        register_collection(server, state, &collection.id).await?;
        let items = state
            .store()
            .list_items(&collection.id)
            .map_err(|e| zbus::Error::FDO(Box::new(e.into())))?;
        for item in items {
            register_item(server, state, &collection.id, &item.id).await?;
        }
    }
    let aliases = state
        .store()
        .list_aliases()
        .map_err(|e| zbus::Error::FDO(Box::new(e.into())))?;
    for (name, _) in aliases {
        register_alias(server, state, &name).await?;
    }
    Ok(())
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
    /// `plain` ignores `input` and returns an empty string; the DH algorithm
    /// expects the client's public key as a byte array and returns ours.
    /// Unknown algorithms yield `org.freedesktop.DBus.Error.NotSupported`.
    #[zbus(out_args("output", "result"))]
    async fn open_session(
        &self,
        algorithm: &str,
        input: Value<'_>,
        #[zbus(object_server)] server: &ObjectServer,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> fdo::Result<(OwnedValue, OwnedObjectPath)> {
        self.state.touch();
        let (output, cipher) = match algorithm {
            ALGORITHM_PLAIN => (
                Value::from("")
                    .try_to_owned()
                    .map_err(|e| fdo::Error::Failed(e.to_string()))?,
                SessionCipher::Plain,
            ),
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
        self.state.touch();
        let _lifecycle = self.state.lock_object_lifecycle().await;

        if !alias.is_empty()
            && let Some(existing) = self.state.store().read_alias(alias).map_err(fdo_err)?
            && self.state.store().get_collection(&existing).is_ok()
        {
            return Ok((collection_path(&existing), root_path()));
        }

        let label = properties
            .get("org.freedesktop.Secret.Collection.Label")
            .and_then(|v| String::try_from(v.clone()).ok())
            .unwrap_or_default();

        let alias_opt = (!alias.is_empty()).then_some(alias);
        let meta = self
            .state
            .store()
            .create_collection(&label, alias_opt)
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
        self.state.touch();
        let unlocked = self
            .state
            .store()
            .search_items(&attributes)
            .map_err(fdo_err)?
            .into_iter()
            .map(|meta| item_path(&meta.collection, &meta.id))
            .collect();
        Ok((unlocked, Vec::new()))
    }

    /// Unlock objects. Everything is already unlocked, so all inputs are
    /// returned immediately and no prompt is needed.
    #[zbus(out_args("unlocked", "prompt"))]
    fn unlock(&self, objects: Vec<OwnedObjectPath>) -> (Vec<OwnedObjectPath>, OwnedObjectPath) {
        self.state.touch();
        (objects, root_path())
    }

    /// Lock objects. Deliberate no-op: the paths are echoed back as "locked",
    /// but `Locked` stays `false` — `gpg-agent` is the real gate on secret
    /// access, so noirpass has no lock state of its own.
    #[zbus(out_args("locked", "prompt"))]
    fn lock(&self, objects: Vec<OwnedObjectPath>) -> (Vec<OwnedObjectPath>, OwnedObjectPath) {
        self.state.touch();
        (objects, root_path())
    }

    /// Fetch the secrets of multiple items in one round trip.
    ///
    /// Item paths that do not resolve to a stored item are silently skipped
    /// (lenient interop choice); a bad session is an error.
    #[zbus(out_args("secrets"))]
    async fn get_secrets(
        &self,
        items: Vec<OwnedObjectPath>,
        session: OwnedObjectPath,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<HashMap<OwnedObjectPath, Secret>, SecretError> {
        self.state.touch();
        let owner = message_sender(&header)?;
        if self.state.session_cipher(&session, &owner).is_none() {
            return Err(SecretError::NoSession(format!("no session {session}")));
        }

        let mut out = HashMap::new();
        for path in items {
            let Some((collection_id, item_id)) = parse_item_path(path.as_str()) else {
                continue;
            };
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
        self.state.touch();
        match self.state.store().read_alias(name).map_err(fdo_err)? {
            Some(id) if self.state.store().get_collection(&id).is_ok() => Ok(collection_path(&id)),
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
    ) -> Result<(), SecretError> {
        self.state.touch();
        let _lifecycle = self.state.lock_object_lifecycle().await;
        if collection.as_str() == "/" {
            self.state.store().set_alias(name, None)?;
            unregister_alias(server, name)
                .await
                .map_err(SecretError::ZBus)?;
            return Ok(());
        }
        let id = parse_collection_path(collection.as_str()).ok_or_else(|| {
            SecretError::NoSuchObject(format!("{collection} is not a collection path"))
        })?;
        // Verify the collection exists before pointing an alias at it.
        self.state.store().get_collection(&id)?;
        self.state.store().set_alias(name, Some(&id))?;
        register_alias(server, &self.state, name)
            .await
            .map_err(SecretError::ZBus)?;
        Ok(())
    }

    /// Object paths of all collections.
    #[zbus(property)]
    fn collections(&self) -> fdo::Result<Vec<OwnedObjectPath>> {
        self.state.touch();
        let collections = self.state.store().list_collections().map_err(fdo_err)?;
        Ok(collections
            .into_iter()
            .map(|meta| collection_path(&meta.id))
            .collect())
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
mod tests {
    use super::*;
    use std::pin::Pin;

    use crate::gpg::test_support::TestGnupg;
    use zbus::connection::Builder;
    use zbus::export::futures_core::Stream;

    #[test]
    fn path_helpers_roundtrip() {
        let col = collection_path("default");
        assert_eq!(col.as_str(), "/org/freedesktop/secrets/collection/default");
        assert_eq!(
            parse_collection_path(col.as_str()).as_deref(),
            Some("default")
        );

        let item = item_path("abc123", "def456");
        assert_eq!(
            item.as_str(),
            "/org/freedesktop/secrets/collection/abc123/def456"
        );
        assert_eq!(
            parse_item_path(item.as_str()),
            Some(("abc123".to_string(), "def456".to_string()))
        );

        assert_eq!(
            session_path(7).as_str(),
            "/org/freedesktop/secrets/session/s7"
        );

        // Non-matching shapes parse to None.
        assert_eq!(parse_collection_path("/org/freedesktop/secrets"), None);
        assert_eq!(parse_collection_path(item.as_str()), None);
        assert_eq!(parse_item_path(col.as_str()), None);
        assert_eq!(parse_item_path("/somewhere/else"), None);
    }

    /// Build a state around a temp store and a hermetic `GnuPG` home.
    fn test_state(gnupg: &TestGnupg, dir: &std::path::Path) -> Arc<ServiceState> {
        let store = Store::open(dir).unwrap();
        store.ensure_default().unwrap();
        let cert = crate::gpg::parse_recipient_cert(&gnupg.export_public_binary()).unwrap();
        let gpg = Gpg::from_cert_with_homedir(cert, Some(gnupg.path().to_path_buf())).unwrap();
        ServiceState::new(store, gpg)
    }

    #[tokio::test]
    async fn session_registry_and_idle_tracker() {
        let gnupg = TestGnupg::new();
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(&gnupg, tmp.path());

        // Idle tracker: touch resets the clock.
        std::thread::sleep(Duration::from_millis(20));
        assert!(state.idle_for() >= Duration::from_millis(10));
        state.touch();
        assert!(state.idle_for() < Duration::from_millis(10));

        // Session registry add/lookup/remove.
        assert_eq!(state.session_count(), 0);

        let p1 = state
            .register_session(SessionCipher::Plain, ":1.7".into())
            .unwrap();
        assert_eq!(state.session_count(), 1);
        assert!(state.session_cipher(&p1, ":1.7").is_some());
        assert!(state.session_cipher(&p1, ":1.8").is_none());

        assert!(!state.remove_session(&p1, ":1.8"));
        assert!(state.remove_session(&p1, ":1.7"));
        assert!(!state.remove_session(&p1, ":1.7"));
        assert_eq!(state.session_count(), 0);
    }

    #[test]
    fn sessions_of_vanished_owner_are_reaped() {
        let gnupg = TestGnupg::new();
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(&gnupg, tmp.path());
        let p1 = state
            .register_session(SessionCipher::Plain, ":1.7".into())
            .unwrap();
        let _p2 = state
            .register_session(SessionCipher::Plain, ":1.8".into())
            .unwrap();
        let _p3 = state
            .register_session(SessionCipher::Plain, ":1.9".into())
            .unwrap();
        assert_eq!(state.session_count(), 3);

        let reaped = state.remove_sessions_owned_by(":1.7");
        assert_eq!(reaped, vec![p1.clone()]);
        assert_eq!(state.session_count(), 2);
        assert!(state.session_cipher(&p1, ":1.7").is_none());

        // Unknown owners and other owners' sessions are untouched.
        assert!(state.remove_sessions_owned_by(":9.9").is_empty());
        assert_eq!(state.session_count(), 2);
    }

    #[test]
    fn session_registration_retries_path_collision_without_overwrite() {
        let gnupg = TestGnupg::new();
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(&gnupg, tmp.path());
        let occupied_id = 41;
        let replacement_id = 42;
        let occupied = state
            .register_session_with(SessionCipher::Plain, ":1.7".into(), || occupied_id)
            .unwrap();
        let mut ids = [occupied_id, replacement_id].into_iter();
        let client_dh = DhHandshake::generate();
        let replacement_cipher = DhHandshake::generate()
            .derive(&client_dh.public_bytes())
            .unwrap();

        let replacement = state
            .register_session_with(replacement_cipher, ":1.8".into(), || ids.next().unwrap())
            .unwrap();

        assert_eq!(occupied, session_path(occupied_id));
        assert_eq!(replacement, session_path(replacement_id));
        assert_eq!(state.session_count(), 2);
        let occupied_cipher = state.session_cipher(&occupied, ":1.7").unwrap();
        let (parameters, value) = occupied_cipher.encrypt(b"collision probe");
        assert!(parameters.is_empty());
        assert_eq!(value, b"collision probe");
        assert!(state.session_cipher(&occupied, ":1.8").is_none());
        let replacement_cipher = state.session_cipher(&replacement, ":1.8").unwrap();
        let (parameters, _) = replacement_cipher.encrypt(b"collision probe");
        assert_eq!(parameters.len(), 16);
    }

    #[test]
    fn concurrent_session_registration_allocates_distinct_paths() {
        let gnupg = TestGnupg::new();
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(&gnupg, tmp.path());
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let mut workers = Vec::new();

        for (owner, fallback_id) in [(":1.7", 52), (":1.8", 53)] {
            let state = state.clone();
            let barrier = barrier.clone();
            workers.push(std::thread::spawn(move || {
                let mut ids = [51, fallback_id].into_iter();
                barrier.wait();
                let path = state
                    .register_session_with(SessionCipher::Plain, owner.into(), || {
                        ids.next().unwrap()
                    })
                    .unwrap();
                (owner, path)
            }));
        }
        barrier.wait();

        let registrations: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert_ne!(registrations[0].1, registrations[1].1);
        assert_eq!(state.session_count(), 2);
        for (owner, path) in registrations {
            assert!(state.session_cipher(&path, owner).is_some());
        }
    }

    #[test]
    fn session_registration_stops_after_bounded_collisions() {
        let gnupg = TestGnupg::new();
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(&gnupg, tmp.path());
        let occupied = state
            .register_session_with(SessionCipher::Plain, ":1.7".into(), || 54)
            .unwrap();
        let attempts = std::sync::atomic::AtomicUsize::new(0);

        let err = state
            .register_session_with(SessionCipher::Plain, ":1.8".into(), || {
                attempts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                54
            })
            .unwrap_err();

        assert!(err.to_string().contains("128 attempts"));
        assert_eq!(
            attempts.load(std::sync::atomic::Ordering::Relaxed),
            SESSION_ALLOCATION_ATTEMPTS
        );
        assert_eq!(state.session_count(), 1);
        assert!(state.session_cipher(&occupied, ":1.7").is_some());
    }

    #[tokio::test]
    async fn failed_object_registration_rolls_back_session_state() {
        let gnupg = TestGnupg::new();
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(&gnupg, tmp.path());
        let (server_conn, _client_conn) = p2p_pair(state.clone()).await;
        let server = server_conn.object_server();
        let occupied = session_path(61);
        assert!(
            server
                .at(&occupied, Session::new(state.clone(), occupied.clone()))
                .await
                .unwrap()
        );

        let err = register_session_object_with(
            server,
            &state,
            SessionCipher::Plain,
            ":1.7".into(),
            || 61,
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("already registered"));
        assert_eq!(state.session_count(), 0);
        assert!(server.remove::<Session, _>(&occupied).await.unwrap());
    }

    #[tokio::test]
    async fn object_registration_error_rolls_back_both_registries() {
        let gnupg = TestGnupg::new();
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(&gnupg, tmp.path());
        let (server_conn, _client_conn) = p2p_pair(state.clone()).await;
        let server = server_conn.object_server().clone();
        assert!(
            server
                .at(SERVICE_PATH, zbus::fdo::ObjectManager)
                .await
                .unwrap()
        );
        let connection_guard = server_conn.clone();
        server_conn.close().await.unwrap();
        let path = session_path(62);

        let err = register_session_object_with(
            &server,
            &state,
            SessionCipher::Plain,
            ":1.7".into(),
            || 62,
        )
        .await
        .unwrap_err();

        assert!(!err.to_string().is_empty());
        assert_eq!(state.session_count(), 0);
        assert!(matches!(
            server.interface::<_, Session>(&path).await,
            Err(zbus::Error::InterfaceNotFound)
        ));
        drop(connection_guard);
    }

    /// In-process p2p bus serving the real `Service` interface.
    async fn p2p_pair(state: Arc<ServiceState>) -> (zbus::Connection, zbus::Connection) {
        let guid = zbus::Guid::generate();
        let (p0, p1) = tokio::net::UnixStream::pair().unwrap();
        let server = Builder::unix_stream(p0)
            .server(guid)
            .unwrap()
            .p2p()
            .serve_at(SERVICE_PATH, Service::new(state))
            .unwrap()
            .build();
        let client = Builder::unix_stream(p1).p2p().build();
        let (server, client) = tokio::join!(server, client);
        (server.unwrap(), client.unwrap())
    }

    async fn next_stream_item<S>(stream: &mut S) -> Option<S::Item>
    where
        S: Stream + Unpin,
    {
        std::future::poll_fn(|context| Pin::new(&mut *stream).poll_next(context)).await
    }

    #[tokio::test]
    async fn alias_removal_is_idempotent() {
        let gnupg = TestGnupg::new();
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(&gnupg, tmp.path());
        let (server_conn, _client_conn) = p2p_pair(state.clone()).await;
        let server = server_conn.object_server();

        unregister_alias(server, "unknown").await.unwrap();
        unregister_alias(server, "unknown").await.unwrap();

        state
            .store()
            .set_alias("twice", Some(crate::store::DEFAULT_COLLECTION_ID))
            .unwrap();
        register_alias(server, &state, "twice").await.unwrap();
        state.store().set_alias("twice", None).unwrap();
        unregister_alias(server, "twice").await.unwrap();
        unregister_alias(server, "twice").await.unwrap();
        assert_eq!(state.store().read_alias("twice").unwrap(), None);
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "single end-to-end regression verifies cleanup, object removal, and both signals"
    )]
    async fn collection_delete_ignores_already_absent_interface_and_finishes_cleanup() {
        let gnupg = TestGnupg::new();
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(&gnupg, tmp.path());
        let collection = state
            .store()
            .create_collection("delete", Some("delete_alias"))
            .unwrap();
        let first = state
            .store()
            .create_item(
                &collection.id,
                "first",
                HashMap::new(),
                "text/plain",
                b"first",
            )
            .unwrap();
        let second = state
            .store()
            .create_item(
                &collection.id,
                "second",
                HashMap::new(),
                "text/plain",
                b"second",
            )
            .unwrap();
        let (server_conn, client_conn) = p2p_pair(state.clone()).await;
        let server = server_conn.object_server();
        let collection_path = register_collection(server, &state, &collection.id)
            .await
            .unwrap();
        let first_path = register_item(server, &state, &collection.id, &first.id)
            .await
            .unwrap();
        let second_path = register_item(server, &state, &collection.id, &second.id)
            .await
            .unwrap();
        register_alias(server, &state, "delete_alias")
            .await
            .unwrap();
        let alias_object = alias_path("delete_alias").unwrap();
        let deleted_rule = zbus::MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .path(SERVICE_PATH)
            .unwrap()
            .interface("org.freedesktop.Secret.Service")
            .unwrap()
            .member("CollectionDeleted")
            .unwrap()
            .build();
        let mut collection_deleted =
            zbus::MessageStream::for_match_rule(deleted_rule, &client_conn, None)
                .await
                .unwrap();
        let properties_rule = zbus::MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .path(SERVICE_PATH)
            .unwrap()
            .interface("org.freedesktop.DBus.Properties")
            .unwrap()
            .member("PropertiesChanged")
            .unwrap()
            .build();
        let mut properties_changed =
            zbus::MessageStream::for_match_rule(properties_rule, &client_conn, None)
                .await
                .unwrap();
        object_removed_or_absent(server.remove::<crate::item::Item, _>(&first_path).await).unwrap();

        crate::collection::Collection::new(state.clone(), collection.id.clone())
            .delete_for_test(server, &server_conn)
            .await
            .unwrap();

        let deleted_signal = tokio::time::timeout(
            Duration::from_secs(1),
            next_stream_item(&mut collection_deleted),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        let (deleted_path,): (OwnedObjectPath,) = deleted_signal.body().deserialize().unwrap();
        assert_eq!(deleted_path, collection_path);
        let changed_signal = tokio::time::timeout(
            Duration::from_secs(1),
            next_stream_item(&mut properties_changed),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        let (interface, changed, _invalidated): (String, HashMap<String, OwnedValue>, Vec<String>) =
            changed_signal.body().deserialize().unwrap();
        assert_eq!(interface, "org.freedesktop.Secret.Service");
        assert!(changed.contains_key("Collections"));

        assert!(matches!(
            state.store().get_collection(&collection.id),
            Err(crate::Error::NotFound(_))
        ));
        for path in [first_path, second_path] {
            assert!(matches!(
                server.interface::<_, crate::item::Item>(&path).await,
                Err(zbus::Error::InterfaceNotFound)
            ));
        }
        for path in [collection_path, alias_object] {
            assert!(matches!(
                server
                    .interface::<_, crate::collection::Collection>(&path)
                    .await,
                Err(zbus::Error::InterfaceNotFound)
            ));
        }
    }

    #[tokio::test]
    async fn item_delete_cannot_race_replacement_registration() {
        let gnupg = TestGnupg::new();
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(&gnupg, tmp.path());
        let collection = state
            .store()
            .get_collection(crate::store::DEFAULT_COLLECTION_ID)
            .unwrap();
        let attributes = HashMap::from([("service".to_string(), "mail".to_string())]);
        let item = state
            .store()
            .create_item(
                &collection.id,
                "mail",
                attributes.clone(),
                "text/plain",
                b"old",
            )
            .unwrap();
        let (server_conn, _client_conn) = p2p_pair(state.clone()).await;
        let server = server_conn.object_server().clone();
        register_collection(&server, &state, &collection.id)
            .await
            .unwrap();
        let item_object = register_item(&server, &state, &collection.id, &item.id)
            .await
            .unwrap();
        let committed = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());

        let replacement_state = state.clone();
        let replacement_server = server.clone();
        let replacement_collection = collection.id.clone();
        let replacement_attributes = attributes.clone();
        let replacement_committed = committed.clone();
        let replacement_resume = resume.clone();
        let replacement = tokio::spawn(async move {
            let _lifecycle = replacement_state.lock_object_lifecycle().await;
            let (metadata, replaced) = replacement_state
                .store()
                .create_or_replace_item(
                    &replacement_collection,
                    "updated",
                    replacement_attributes,
                    "text/plain",
                    b"new",
                    true,
                )
                .unwrap();
            assert!(replaced);
            replacement_committed.notify_one();
            replacement_resume.notified().await;
            register_item(
                &replacement_server,
                &replacement_state,
                &replacement_collection,
                &metadata.id,
            )
            .await
            .unwrap();
        });
        committed.notified().await;

        let deletion_state = state.clone();
        let deletion_server = server.clone();
        let deletion_item = item.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let deletion = tokio::spawn(async move {
            started_tx.send(()).unwrap();
            let _lifecycle = deletion_state.lock_object_lifecycle().await;
            deletion_state
                .store()
                .delete_item(&deletion_item.id)
                .unwrap();
            deletion_server
                .remove::<crate::item::Item, _>(&item_path(
                    &deletion_item.collection,
                    &deletion_item.id,
                ))
                .await
                .unwrap();
        });
        started_rx.await.unwrap();
        tokio::task::yield_now().await;
        assert!(!deletion.is_finished());

        resume.notify_one();
        replacement.await.unwrap();
        deletion.await.unwrap();
        assert!(matches!(
            state.store().get_item(&item.id),
            Err(crate::Error::NotFound(_))
        ));
        assert!(matches!(
            server.interface::<_, crate::item::Item>(&item_object).await,
            Err(zbus::Error::InterfaceNotFound)
        ));
    }

    #[tokio::test]
    async fn collection_delete_removes_concurrently_created_item_object() {
        let gnupg = TestGnupg::new();
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(&gnupg, tmp.path());
        let collection = state.store().create_collection("race", None).unwrap();
        let (server_conn, _client_conn) = p2p_pair(state.clone()).await;
        let server = server_conn.object_server().clone();
        let collection_object = register_collection(&server, &state, &collection.id)
            .await
            .unwrap();
        let committed = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());

        let creation_state = state.clone();
        let creation_server = server.clone();
        let creation_collection = collection.id.clone();
        let creation_committed = committed.clone();
        let creation_resume = resume.clone();
        let creation = tokio::spawn(async move {
            let _lifecycle = creation_state.lock_object_lifecycle().await;
            let metadata = creation_state
                .store()
                .create_item(
                    &creation_collection,
                    "created",
                    HashMap::new(),
                    "text/plain",
                    b"ciphertext",
                )
                .unwrap();
            creation_committed.notify_one();
            creation_resume.notified().await;
            register_item(
                &creation_server,
                &creation_state,
                &creation_collection,
                &metadata.id,
            )
            .await
            .unwrap();
            metadata.id
        });
        committed.notified().await;

        let deletion_state = state.clone();
        let deletion_server = server.clone();
        let deletion_collection = collection.id.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let deletion = tokio::spawn(async move {
            started_tx.send(()).unwrap();
            let _lifecycle = deletion_state.lock_object_lifecycle().await;
            let deleted = deletion_state
                .store()
                .delete_collection(&deletion_collection)
                .unwrap();
            for item_id in deleted.item_ids {
                deletion_server
                    .remove::<crate::item::Item, _>(&item_path(&deletion_collection, &item_id))
                    .await
                    .unwrap();
            }
            deletion_server
                .remove::<crate::collection::Collection, _>(&collection_path(&deletion_collection))
                .await
                .unwrap();
        });
        started_rx.await.unwrap();
        tokio::task::yield_now().await;
        assert!(!deletion.is_finished());

        resume.notify_one();
        let item_id = creation.await.unwrap();
        deletion.await.unwrap();
        assert!(matches!(
            state.store().get_collection(&collection.id),
            Err(crate::Error::NotFound(_))
        ));
        assert!(matches!(
            server
                .interface::<_, crate::item::Item>(item_path(&collection.id, &item_id))
                .await,
            Err(zbus::Error::InterfaceNotFound)
        ));
        assert!(matches!(
            server
                .interface::<_, crate::collection::Collection>(&collection_object)
                .await,
            Err(zbus::Error::InterfaceNotFound)
        ));
    }

    #[tokio::test]
    async fn collection_delete_removes_concurrently_registered_alias() {
        let gnupg = TestGnupg::new();
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(&gnupg, tmp.path());
        let collection = state.store().create_collection("race", None).unwrap();
        let (server_conn, _client_conn) = p2p_pair(state.clone()).await;
        let server = server_conn.object_server().clone();
        register_collection(&server, &state, &collection.id)
            .await
            .unwrap();
        let alias = "racing_alias";
        let alias_object = alias_path(alias).unwrap();
        let committed = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());

        let alias_state = state.clone();
        let alias_server = server.clone();
        let alias_collection = collection.id.clone();
        let alias_committed = committed.clone();
        let alias_resume = resume.clone();
        let alias_update = tokio::spawn(async move {
            let _lifecycle = alias_state.lock_object_lifecycle().await;
            alias_state
                .store()
                .set_alias(alias, Some(&alias_collection))
                .unwrap();
            alias_committed.notify_one();
            alias_resume.notified().await;
            register_alias(&alias_server, &alias_state, alias)
                .await
                .unwrap();
        });
        committed.notified().await;

        let deletion_state = state.clone();
        let deletion_server = server.clone();
        let deletion_collection = collection.id.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let deletion = tokio::spawn(async move {
            started_tx.send(()).unwrap();
            let _lifecycle = deletion_state.lock_object_lifecycle().await;
            let deleted = deletion_state
                .store()
                .delete_collection(&deletion_collection)
                .unwrap();
            for name in deleted.aliases {
                unregister_alias(&deletion_server, &name).await.unwrap();
            }
            deletion_server
                .remove::<crate::collection::Collection, _>(&collection_path(&deletion_collection))
                .await
                .unwrap();
        });
        started_rx.await.unwrap();
        tokio::task::yield_now().await;
        assert!(!deletion.is_finished());

        resume.notify_one();
        alias_update.await.unwrap();
        deletion.await.unwrap();
        assert_eq!(state.store().read_alias(alias).unwrap(), None);
        assert!(matches!(
            server
                .interface::<_, crate::collection::Collection>(&alias_object)
                .await,
            Err(zbus::Error::InterfaceNotFound)
        ));
    }

    #[tokio::test]
    async fn open_session_rejects_missing_sender() {
        let gnupg = TestGnupg::new();
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(&gnupg, tmp.path());
        let (_server_conn, client_conn) = p2p_pair(state.clone()).await;

        let iface = Some("org.freedesktop.Secret.Service");
        let dest = None::<zbus::names::BusName<'_>>;

        // Peer-to-peer messages have no bus-assigned sender identity, so
        // client-owned session state must fail closed.
        let err = client_conn
            .call_method(
                dest.clone(),
                SERVICE_PATH,
                iface,
                "OpenSession",
                &("plain", Value::from("")),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("AccessDenied"));
        assert_eq!(state.session_count(), 0);

        // Missing identity also rejects DH sessions after input validation.
        let client_dh = DhHandshake::generate();
        let err = client_conn
            .call_method(
                dest.clone(),
                SERVICE_PATH,
                iface,
                "OpenSession",
                &(ALGORITHM_DH, Value::from(client_dh.public_bytes())),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("AccessDenied"));
        assert_eq!(state.session_count(), 0);

        // Unknown algorithm is NotSupported.
        let err = client_conn
            .call_method(
                dest.clone(),
                SERVICE_PATH,
                iface,
                "OpenSession",
                &("rot13", Value::from("")),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("NotSupported"));

        // ReadAlias resolves the default collection; unknown aliases → "/".
        let reply = client_conn
            .call_method(
                dest.clone(),
                SERVICE_PATH,
                iface,
                "ReadAlias",
                &("default",),
            )
            .await
            .unwrap();
        let path: OwnedObjectPath = reply.body().deserialize().unwrap();
        assert_eq!(path.as_str(), "/org/freedesktop/secrets/collection/default");

        let reply = client_conn
            .call_method(dest, SERVICE_PATH, iface, "ReadAlias", &("nonexistent",))
            .await
            .unwrap();
        let path: OwnedObjectPath = reply.body().deserialize().unwrap();
        assert_eq!(path.as_str(), "/");
    }
}
