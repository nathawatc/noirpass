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
use zbus::zvariant::OwnedObjectPath;
use zeroize::Zeroizing;

use super::SESSION_COLLECTION_ID;
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
) -> crate::Result<usize> {
    if secret_len > MAX_SESSION_SECRET_BYTES
        || attributes.len() > MAX_SESSION_ATTRIBUTES
        || label.len() > MAX_SESSION_STRING_BYTES
        || content_type.len() > MAX_SESSION_STRING_BYTES
        || attributes.iter().any(|(key, value)| {
            key.len() > MAX_SESSION_STRING_BYTES || value.len() > MAX_SESSION_STRING_BYTES
        })
    {
        return Err(crate::Error::Config(
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
        return Err(crate::Error::Config(
            "temporary item metadata exceeds size limit".into(),
        ));
    }
    Ok(metadata_bytes + secret_len)
}

fn session_item_id() -> String {
    format!("{:032x}", rand::random::<u128>())
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
}

impl SessionItem {
    fn bytes(&self) -> usize {
        self.secret.len()
            + self.metadata.label.len()
            + self.metadata.content_type.len()
            + self
                .metadata
                .attributes
                .iter()
                .map(|(key, value)| key.len() + value.len())
                .sum::<usize>()
    }
}

struct SessionCollectionState {
    metadata: CollectionMeta,
    items: HashMap<String, SessionItem>,
    aliases: HashSet<String>,
}

impl SessionCollectionState {
    fn check_capacity(&self, previous: usize, replacement: usize) -> crate::Result<()> {
        // ponytail: at most 256 items; scan instead of maintaining a second mutable counter.
        let retained: usize = self.items.values().map(SessionItem::bytes).sum();
        if retained - previous + replacement > MAX_SESSION_BYTES {
            return Err(crate::Error::Config(
                "temporary collection exceeds memory limit".into(),
            ));
        }
        Ok(())
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
    _permit: Option<OwnedSemaphorePermit>,
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
    #[must_use]
    pub fn gpg(&self) -> &Gpg {
        &self.gpg
    }
}
