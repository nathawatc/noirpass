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

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
pub fn session_path(n: u64) -> OwnedObjectPath {
    OwnedObjectPath::try_from(format!("{SERVICE_PATH}/session/s{n}"))
        .expect("session numbers are valid path elements")
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

/// State shared by every D-Bus object of the daemon.
pub struct ServiceState {
    store: Store,
    gpg: Gpg,
    sessions: Mutex<HashMap<OwnedObjectPath, Arc<SessionCipher>>>,
    session_counter: AtomicU64,
    last_activity: Mutex<Instant>,
}

impl ServiceState {
    /// Bundle the storage and `GnuPG` handles into shared daemon state.
    #[must_use]
    pub fn new(store: Store, gpg: Gpg) -> Arc<Self> {
        Arc::new(Self {
            store,
            gpg,
            sessions: Mutex::new(HashMap::new()),
            session_counter: AtomicU64::new(0),
            last_activity: Mutex::new(Instant::now()),
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

    /// Allocate the object path for the next session (`.../session/s<n>`).
    pub fn next_session_path(&self) -> OwnedObjectPath {
        let n = self.session_counter.fetch_add(1, Ordering::Relaxed) + 1;
        session_path(n)
    }

    /// Register a session cipher under its object path.
    pub fn register_session(&self, path: OwnedObjectPath, cipher: SessionCipher) {
        self.sessions
            .lock()
            .expect("session lock poisoned")
            .insert(path, Arc::new(cipher));
    }

    /// Remove a session; returns whether it existed.
    pub fn remove_session(&self, path: &OwnedObjectPath) -> bool {
        self.sessions
            .lock()
            .expect("session lock poisoned")
            .remove(path)
            .is_some()
    }

    /// Look up the cipher of an open session.
    #[must_use]
    pub fn session_cipher(&self, path: &OwnedObjectPath) -> Option<Arc<SessionCipher>> {
        self.sessions
            .lock()
            .expect("session lock poisoned")
            .get(path)
            .cloned()
    }

    /// Decrypt an incoming [`Secret`] with its session cipher, `gpg`-encrypt
    /// the plaintext for storage and return the at-rest ciphertext.
    pub fn secret_to_ciphertext(&self, secret: &Secret) -> Result<Vec<u8>, SecretError> {
        let cipher = self
            .session_cipher(&secret.session)
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
    ) -> Result<Secret, SecretError> {
        let cipher = self
            .session_cipher(session)
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

/// Serve objects for every collection and item already in the store.
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

        let path = self.state.next_session_path();
        self.state.register_session(path.clone(), cipher);
        server
            .at(&path, Session::new(self.state.clone(), path.clone()))
            .await?;
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
        Self::collection_created(&emitter, path.clone()).await?;
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
    ) -> Result<HashMap<OwnedObjectPath, Secret>, SecretError> {
        self.state.touch();
        if self.state.session_cipher(&session).is_none() {
            return Err(SecretError::NoSession(format!("no session {session}")));
        }

        let mut out = HashMap::new();
        for path in items {
            let Some((_, item_id)) = parse_item_path(path.as_str()) else {
                continue;
            };
            let Ok(meta) = self.state.store().get_item(&item_id) else {
                continue;
            };
            let ciphertext = self.state.store().read_secret_file(&item_id)?;
            let secret = self
                .state
                .ciphertext_to_secret(&session, &ciphertext, &meta.content_type)
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
    #[allow(
        clippy::needless_pass_by_value,
        reason = "zbus deserializes method arguments by value"
    )]
    fn set_alias(&self, name: &str, collection: OwnedObjectPath) -> Result<(), SecretError> {
        self.state.touch();
        if collection.as_str() == "/" {
            self.state.store().set_alias(name, None)?;
            return Ok(());
        }
        let id = parse_collection_path(collection.as_str()).ok_or_else(|| {
            SecretError::NoSuchObject(format!("{collection} is not a collection path"))
        })?;
        // Verify the collection exists before pointing an alias at it.
        self.state.store().get_collection(&id)?;
        self.state.store().set_alias(name, Some(&id))?;
        Ok(())
    }

    /// Object paths of all collections.
    #[zbus(property)]
    fn collections(&self) -> fdo::Result<Vec<OwnedObjectPath>> {
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
    use crate::gpg::test_support::TestGnupg;
    use zbus::connection::Builder;

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
        let gpg = Gpg::with_homedir(gnupg.path(), None).unwrap();
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

        // Session registry add/lookup/remove; counter increments.
        let p1 = state.next_session_path();
        let p2 = state.next_session_path();
        assert_ne!(p1, p2);
        assert_eq!(state.session_count(), 0);

        state.register_session(p1.clone(), SessionCipher::Plain);
        assert_eq!(state.session_count(), 1);
        assert!(state.session_cipher(&p1).is_some());
        assert!(state.session_cipher(&p2).is_none());

        assert!(state.remove_session(&p1));
        assert!(!state.remove_session(&p1));
        assert_eq!(state.session_count(), 0);
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

    #[tokio::test]
    async fn open_session_plain_and_dh_smoke() {
        let gnupg = TestGnupg::new();
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(&gnupg, tmp.path());
        let (_server_conn, client_conn) = p2p_pair(state.clone()).await;

        let iface = Some("org.freedesktop.Secret.Service");
        let dest = None::<zbus::names::BusName<'_>>;

        // Plain session.
        let reply = client_conn
            .call_method(
                dest.clone(),
                SERVICE_PATH,
                iface,
                "OpenSession",
                &("plain", Value::from("")),
            )
            .await
            .unwrap();
        let (output, session): (OwnedValue, OwnedObjectPath) = reply.body().deserialize().unwrap();
        assert_eq!(String::try_from(output).unwrap(), "");
        assert!(
            session
                .as_str()
                .starts_with("/org/freedesktop/secrets/session/s")
        );
        assert_eq!(state.session_count(), 1);

        // DH session: run the client side of the handshake for real.
        let client_dh = DhHandshake::generate();
        let reply = client_conn
            .call_method(
                dest.clone(),
                SERVICE_PATH,
                iface,
                "OpenSession",
                &(ALGORITHM_DH, Value::from(client_dh.public_bytes())),
            )
            .await
            .unwrap();
        let (output, dh_session): (OwnedValue, OwnedObjectPath) =
            reply.body().deserialize().unwrap();
        let server_pub = Vec::<u8>::try_from(output).unwrap();
        assert_eq!(server_pub.len(), 128);
        assert_ne!(dh_session, session);
        assert_eq!(state.session_count(), 2);
        // The client can complete the handshake with our public key.
        client_dh.derive(&server_pub).unwrap();

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
