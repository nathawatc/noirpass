//! Shared daemon state, session ownership, and secret transport.
//!
//! Collection mutations hold a per-collection mutex and a shared namespace guard through
//! persistence and publication. Namespace changes take the exclusive guard, preserving alias
//! targets and collection deletion ordering without serializing unrelated item mutations.
//! Persistent mutations reserve blocking capacity first; temporary mutations need no worker slot.
//! Owned tasks carry request admission through shutdown draining so internal workers and signal
//! property reads can finish while new application handlers remain rejected.

mod activity;
mod lifecycle;
mod sessions;
mod temporary;
mod transport;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, Weak};
use std::time::Instant;

use tokio::sync::{
    Mutex as AsyncMutex, Notify, OwnedMutexGuard, OwnedRwLockReadGuard, OwnedRwLockWriteGuard,
    OwnedSemaphorePermit, RwLock as AsyncRwLock, Semaphore,
};
use zbus::OwnedObjectPath;
use zeroize::Zeroizing;

use super::{SESSION_COLLECTION_ID, SecretError};
use crate::crypto::SessionCipher;
use crate::gpg::Gpg;
use crate::now_secs;
use crate::store::{CollectionMeta, ItemMeta, Store};

/// Bound retries so a broken entropy source fails instead of looping forever.
/// Exhausting this with random 128-bit IDs requires 128 consecutive collisions.
pub(super) const SESSION_ALLOCATION_ATTEMPTS: usize = 128;

/// Bound retained transport ciphers and session objects, independently of temporary items.
pub(super) const MAX_TRANSPORT_SESSIONS: usize = 1024;
pub(super) const MAX_TRANSPORT_SESSIONS_PER_OWNER: usize = 64;

/// Share a fixed worker budget across encryption, storage, and agent decryption.
pub(super) const MAX_BLOCKING_WORKERS: usize = 4;

/// Bound application work retained while waiting for workers or lifecycle guards.
pub(super) const MAX_PENDING_REQUESTS: usize = 64;
pub(super) const MAX_PENDING_REQUEST_BYTES: u32 = 32 * 1024 * 1024;

/// Bound retries for temporary item identifiers for the same reason as session paths.
const SESSION_ITEM_ALLOCATION_ATTEMPTS: usize = 128;

/// Keep runtime alias names bounded independently of temporary item payloads.
pub(super) const MAX_SESSION_ALIASES: usize = 256;
pub(super) const MAX_SESSION_ALIAS_BYTES: usize = 4096;

// Bound retained temporary data, including client-controlled metadata.
pub(super) const MAX_SESSION_SECRET_BYTES: usize = 1024 * 1024;
pub(super) const MAX_SESSION_ITEMS: usize = 256;
pub(super) const MAX_SESSION_BYTES: usize = 16 * 1024 * 1024;
pub(super) const MAX_SESSION_ATTRIBUTES: usize = 64;
pub(super) const MAX_SESSION_STRING_BYTES: usize = 4096;
pub(super) const MAX_SESSION_METADATA_BYTES: usize = 64 * 1024;

pub(super) fn session_item_bytes(
    label: &str,
    attributes: &HashMap<String, String>,
    content_type: &str,
    secret_len: usize,
) -> Result<usize, SecretError> {
    if secret_len > MAX_SESSION_SECRET_BYTES
        || attributes.len() > MAX_SESSION_ATTRIBUTES
        || label.len() > MAX_SESSION_STRING_BYTES
        || content_type.len() > MAX_SESSION_STRING_BYTES
        || attributes.iter().any(|(key, value)| {
            key.len() > MAX_SESSION_STRING_BYTES || value.len() > MAX_SESSION_STRING_BYTES
        })
    {
        return Err(SecretError::LimitsExceeded(
            "temporary item exceeds size limits".into(),
        ));
    }
    let metadata_bytes = label.len()
        + content_type.len()
        + attributes
            .iter()
            .map(|(key, value)| key.len() + value.len())
            .sum::<usize>();
    if metadata_bytes > MAX_SESSION_METADATA_BYTES {
        return Err(SecretError::LimitsExceeded(
            "temporary item metadata exceeds size limit".into(),
        ));
    }
    Ok(metadata_bytes + secret_len)
}

/// A registered session: its transport cipher and the unique bus name of the
/// client that opened it (used to reap sessions of vanished clients).
struct SessionEntry {
    cipher: Arc<SessionCipher>,
    owner: String,
}

struct ActivityState {
    active_calls: usize,
    had_activity: bool,
    last_activity: Instant,
    shutting_down: bool,
}

struct SessionItem {
    metadata: ItemMeta,
    secret: Zeroizing<Vec<u8>>,
    bytes: usize,
}

struct SessionCollectionState {
    metadata: CollectionMeta,
    items: HashMap<String, SessionItem>,
    aliases: HashSet<String>,
    retained_bytes: usize,
}

impl SessionCollectionState {
    fn check_capacity(&self, previous: usize, replacement: usize) -> Result<usize, SecretError> {
        self.retained_bytes
            .checked_sub(previous)
            .and_then(|retained| retained.checked_add(replacement))
            .filter(|retained| *retained <= MAX_SESSION_BYTES)
            .ok_or_else(|| {
                SecretError::LimitsExceeded("temporary collection exceeds memory limit".into())
            })
    }

    fn new() -> Self {
        let now = now_secs();
        Self {
            metadata: CollectionMeta {
                id: SESSION_COLLECTION_ID.to_string(),
                label: "Session".to_string(),
                created: now,
                modified: now,
            },
            items: HashMap::new(),
            aliases: HashSet::new(),
            retained_bytes: 0,
        }
    }
}

/// Marks one in-flight D-Bus method as activity until handler return.
pub(crate) struct ActivityGuard {
    state: Arc<ServiceState>,
}

/// Retain request capacity through an admitted handler or owned mutation task.
pub(crate) struct RequestGuard {
    activity: ActivityGuard,
    _slot: OwnedSemaphorePermit,
    _bytes: OwnedSemaphorePermit,
}

tokio::task_local! {
    // Only an admitted request may continue internal work during shutdown.
    static ADMITTED_REQUEST: Arc<RequestGuard>;
}

impl RequestGuard {
    pub(crate) async fn run<F: std::future::Future>(self: Arc<Self>, future: F) -> F::Output {
        ADMITTED_REQUEST.scope(self, future).await
    }

    /// Spawn an owned task carrying request admission through caller cancellation.
    pub(crate) async fn spawn<T, E, F>(
        self: Arc<Self>,
        failure_message: &'static str,
        future: F,
    ) -> std::result::Result<T, E>
    where
        T: Send + 'static,
        E: From<zbus::fdo::Error> + Send + 'static,
        F: std::future::Future<Output = std::result::Result<T, E>> + Send + 'static,
    {
        tokio::spawn(self.run(future))
            .await
            .map_err(|_| zbus::fdo::Error::Failed(failure_message.into()))?
    }
}

impl Drop for ActivityGuard {
    fn drop(&mut self) {
        let notify = {
            let mut activity = self.state.activity.lock().expect("activity lock poisoned");
            activity.active_calls -= 1;
            activity.last_activity = Instant::now();
            activity.active_calls == 0
        };
        if notify {
            self.state.activity_complete.notify_one();
        }
    }
}

/// Serialize one collection through persistence and publication while pinning the namespace.
pub(crate) struct CollectionGuard {
    _collection: OwnedMutexGuard<()>,
    _namespace: OwnedRwLockReadGuard<()>,
}

/// Reserve persistent worker capacity before taking lifecycle serialization.
pub(crate) struct MutationGuard {
    _lifecycle: LifecycleGuard,
    permit: Option<OwnedSemaphorePermit>,
}

impl MutationGuard {
    pub(super) fn has_permit(&self) -> bool {
        self.permit.is_some()
    }
}

enum LifecycleGuard {
    Collection { _guard: CollectionGuard },
    Namespace { _guard: OwnedRwLockWriteGuard<()> },
}

/// State shared by every D-Bus object of the daemon.
pub struct ServiceState {
    store: Store,
    gpg: Gpg,
    sessions: Mutex<HashMap<OwnedObjectPath, SessionEntry>>,
    session_collection: Mutex<SessionCollectionState>,
    activity: Mutex<ActivityState>,
    activity_complete: Notify,
    object_lifecycle: Arc<AsyncRwLock<()>>,
    collection_lifecycle: Mutex<HashMap<String, Weak<AsyncMutex<()>>>>,
    blocking_slots: Arc<Semaphore>,
    request_slots: Arc<Semaphore>,
    request_bytes: Arc<Semaphore>,
}

impl ServiceState {
    /// Bundle the storage and `GnuPG` handles into shared daemon state.
    #[must_use]
    pub fn new(store: Store, gpg: Gpg) -> Arc<Self> {
        Arc::new(Self {
            store,
            gpg,
            sessions: Mutex::new(HashMap::new()),
            session_collection: Mutex::new(SessionCollectionState::new()),
            activity: Mutex::new(ActivityState {
                active_calls: 0,
                had_activity: false,
                last_activity: Instant::now(),
                shutting_down: false,
            }),
            activity_complete: Notify::new(),
            object_lifecycle: Arc::new(AsyncRwLock::new(())),
            collection_lifecycle: Mutex::new(HashMap::new()),
            blocking_slots: Arc::new(Semaphore::new(MAX_BLOCKING_WORKERS)),
            request_slots: Arc::new(Semaphore::new(MAX_PENDING_REQUESTS)),
            request_bytes: Arc::new(Semaphore::new(MAX_PENDING_REQUEST_BYTES as usize)),
        })
    }

    /// The metadata/secret store.
    #[must_use]
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// The `OpenPGP` encryption handle.
    #[cfg(test)]
    #[must_use]
    pub(in crate::service) fn gpg(&self) -> &Gpg {
        &self.gpg
    }
}
