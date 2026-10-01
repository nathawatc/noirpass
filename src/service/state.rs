//! Shared daemon state, session ownership, and secret transport.

use std::collections::{HashMap, HashSet, hash_map::Entry};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::{
    Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard, Notify, OwnedMutexGuard,
    OwnedSemaphorePermit, Semaphore,
};
use zbus::fdo;
use zbus::zvariant::OwnedObjectPath;
use zeroize::Zeroizing;

use super::{SESSION_COLLECTION_ALIAS, SESSION_COLLECTION_ID, SecretError, session_path};
use crate::crypto::SessionCipher;
use crate::gpg::Gpg;
use crate::service::session::Secret;
use crate::store::{CollectionMeta, ItemMeta, Store};

/// Bound retries so a broken entropy source fails instead of looping forever.
/// Exhausting this with random 128-bit IDs requires 128 consecutive collisions.
pub(super) const SESSION_ALLOCATION_ATTEMPTS: usize = 128;

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

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn session_item_id() -> String {
    format!("{:032x}", rand::random::<u128>())
}

// --- shared state -----------------------------------------------------------

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

/// Reserve blocking capacity before taking lifecycle serialization.
/// Shared ownership keeps both reservations alive through commit and publication.
pub(crate) struct MutationGuard {
    _lifecycle: OwnedMutexGuard<()>,
    _permit: OwnedSemaphorePermit,
}

/// State shared by every D-Bus object of the daemon.
pub struct ServiceState {
    store: Store,
    gpg: Gpg,
    sessions: Mutex<HashMap<OwnedObjectPath, SessionEntry>>,
    session_collection: Mutex<SessionCollectionState>,
    activity: Mutex<ActivityState>,
    activity_complete: Notify,
    object_lifecycle: Arc<AsyncMutex<()>>,
    blocking_slots: Arc<Semaphore>,
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
            object_lifecycle: Arc::new(AsyncMutex::new(())),
            blocking_slots: Arc::new(Semaphore::new(4)),
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

    /// Run synchronous encryption/storage without blocking executor threads.
    /// Keep admission, capacity, and any mutation lock alive even if the waiter is cancelled.
    pub(crate) async fn blocking<T: Send + 'static>(
        self: &Arc<Self>,
        lifecycle: Option<Arc<MutationGuard>>,
        operation: impl FnOnce(&Self) -> Result<T, SecretError> + Send + 'static,
    ) -> Result<T, SecretError> {
        let activity = self.activity()?;
        let permit = if lifecycle.is_none() {
            Some(
                self.blocking_slots
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| fdo::Error::Failed("blocking work is unavailable".into()))?,
            )
        } else {
            None // MutationGuard already reserved capacity before acquiring the lifecycle lock.
        };
        let state = self.clone();
        tokio::task::spawn_blocking(move || {
            let (_activity, _permit, _lifecycle) = (activity, permit, lifecycle);
            operation(&state)
        })
        .await
        .map_err(|_| fdo::Error::Failed("blocking work failed".into()))?
    }

    pub(crate) async fn lock_owned_object_lifecycle(&self) -> Arc<MutationGuard> {
        let permit = self
            .blocking_slots
            .clone()
            .acquire_owned()
            .await
            .expect("blocking capacity is never closed");
        let lifecycle = self.object_lifecycle.clone().lock_owned().await;
        Arc::new(MutationGuard {
            _lifecycle: lifecycle,
            _permit: permit,
        })
    }

    /// Track one D-Bus method until its handler returns.
    pub(crate) fn activity(self: &Arc<Self>) -> fdo::Result<ActivityGuard> {
        let mut activity = self.activity.lock().expect("activity lock poisoned");
        if activity.shutting_down {
            return Err(fdo::Error::Failed("service is shutting down".into()));
        }
        activity.active_calls += 1;
        activity.had_activity = true;
        Ok(ActivityGuard {
            state: self.clone(),
        })
    }

    /// Close admission for new application handlers.
    pub fn begin_shutdown(&self) {
        self.activity
            .lock()
            .expect("activity lock poisoned")
            .shutting_down = true;
    }

    /// Wake shutdown selection when the last active handler completes.
    pub async fn wait_for_activity_completion(&self) {
        self.activity_complete.notified().await;
    }

    /// Wait until every already-admitted application handler has returned.
    pub async fn wait_for_active_calls(&self) {
        loop {
            // Create notification future before checking the condition. `notify_one`
            // preserves a completion that races with the check as a stored permit.
            let notified = self.activity_complete.notified();
            let active_calls = self
                .activity
                .lock()
                .expect("activity lock poisoned")
                .active_calls;
            if active_calls == 0 {
                return;
            }
            notified.await;
        }
    }

    /// Atomically select idle shutdown against application-handler admission.
    pub fn try_begin_idle_shutdown(&self, idle_exit: i64) -> bool {
        if idle_exit < 0 {
            return false;
        }

        let mut activity = self.activity.lock().expect("activity lock poisoned");
        if activity.shutting_down || activity.active_calls != 0 {
            return false;
        }
        if !self
            .sessions
            .lock()
            .expect("session lock poisoned")
            .is_empty()
            || !self
                .session_collection
                .lock()
                .expect("session collection lock poisoned")
                .items
                .is_empty()
        {
            return false;
        }

        let eligible = if idle_exit == 0 {
            activity.had_activity
        } else {
            let idle_limit = Duration::from_secs(
                u64::try_from(idle_exit).expect("positive idle timeout must fit u64"),
            );
            activity.last_activity.elapsed() >= idle_limit
        };
        if eligible {
            activity.shutting_down = true;
        }
        eligible
    }

    /// Resolve reserved and runtime aliases before persisted aliases.
    pub(crate) fn read_alias(&self, name: &str) -> crate::Result<Option<String>> {
        if self.is_session_alias(name) {
            return Ok(Some(SESSION_COLLECTION_ID.to_string()));
        }
        self.store.read_alias(name)
    }

    pub(crate) fn is_session_alias(&self, name: &str) -> bool {
        name == SESSION_COLLECTION_ALIAS
            || self
                .session_collection
                .lock()
                .expect("session collection lock poisoned")
                .aliases
                .contains(name)
    }

    /// All aliases for temporary items, including the reserved built-in alias.
    pub(crate) fn session_collection_aliases(&self) -> Vec<String> {
        let collection = self
            .session_collection
            .lock()
            .expect("session collection lock poisoned");
        let mut aliases: Vec<_> = collection.aliases.iter().cloned().collect();
        aliases.push(SESSION_COLLECTION_ALIAS.to_string());
        aliases.sort();
        aliases
    }

    /// Replace any persisted target with a bounded, process-local session target.
    /// The caller holds object lifecycle serialization through registration and signals.
    pub(crate) fn set_session_alias(&self, name: &str) -> crate::Result<()> {
        let mut collection = self
            .session_collection
            .lock()
            .expect("session collection lock poisoned");
        if name.len() > MAX_SESSION_ALIAS_BYTES
            || (!collection.aliases.contains(name)
                && collection.aliases.len() >= MAX_SESSION_ALIASES)
        {
            return Err(crate::Error::Config(
                "temporary collection exceeds alias limits".into(),
            ));
        }
        // Never persist the session target, or leave an old target to reappear after restart.
        // Validate capacity before the Store mutation, and update memory only after a definite commit.
        self.store.set_alias(name, None)?;
        collection.aliases.insert(name.to_string());
        Ok(())
    }

    pub(crate) fn remove_session_alias(&self, name: &str) {
        self.session_collection
            .lock()
            .expect("session collection lock poisoned")
            .aliases
            .remove(name);
    }

    /// Metadata for the built-in in-memory session collection.
    pub(crate) fn session_collection_meta(&self) -> CollectionMeta {
        self.session_collection
            .lock()
            .expect("session collection lock poisoned")
            .metadata
            .clone()
    }

    /// Update the session collection label without persisting it.
    pub(crate) fn set_session_collection_label(&self, label: &str) -> crate::Result<()> {
        if label.len() > MAX_SESSION_STRING_BYTES {
            return Err(crate::Error::Config(
                "temporary collection label exceeds size limit".into(),
            ));
        }
        let mut collection = self
            .session_collection
            .lock()
            .expect("session collection lock poisoned");
        collection.metadata.label = label.to_string();
        collection.metadata.modified = now_secs();
        Ok(())
    }

    /// List temporary items in stable id order.
    pub(crate) fn list_session_items(&self) -> Vec<ItemMeta> {
        let collection = self
            .session_collection
            .lock()
            .expect("session collection lock poisoned");
        let mut items: Vec<_> = collection
            .items
            .values()
            .map(|item| item.metadata.clone())
            .collect();
        items.sort_by(|left, right| left.id.cmp(&right.id));
        items
    }

    /// Search temporary items by Secret Service superset attribute semantics.
    pub(crate) fn search_session_items(&self, attrs: &HashMap<String, String>) -> Vec<ItemMeta> {
        let collection = self
            .session_collection
            .lock()
            .expect("session collection lock poisoned");
        let mut items: Vec<_> = collection
            .items
            .values()
            .filter(|item| {
                attrs.iter().all(|(name, expected)| {
                    item.metadata
                        .attributes
                        .get(name)
                        .is_some_and(|actual| actual == expected)
                })
            })
            .map(|item| item.metadata.clone())
            .collect();
        items.sort_by(|left, right| left.id.cmp(&right.id));
        items
    }

    /// Fetch temporary item metadata.
    pub(crate) fn get_session_item(&self, id: &str) -> crate::Result<ItemMeta> {
        self.session_collection
            .lock()
            .expect("session collection lock poisoned")
            .items
            .get(id)
            .map(|item| item.metadata.clone())
            .ok_or_else(|| crate::Error::NotFound(format!("item {id}")))
    }

    /// Fetch temporary item metadata and a zeroizing copy of its secret.
    pub(crate) fn read_session_item_secret(
        &self,
        id: &str,
    ) -> crate::Result<(ItemMeta, Zeroizing<Vec<u8>>)> {
        self.session_collection
            .lock()
            .expect("session collection lock poisoned")
            .items
            .get(id)
            .map(|item| (item.metadata.clone(), item.secret.clone()))
            .ok_or_else(|| crate::Error::NotFound(format!("item {id}")))
    }

    /// Create or replace an exact attribute match in the temporary collection.
    pub(crate) fn create_or_replace_session_item(
        &self,
        label: &str,
        attributes: HashMap<String, String>,
        content_type: &str,
        secret: Zeroizing<Vec<u8>>,
        replace: bool,
    ) -> crate::Result<(ItemMeta, bool)> {
        let replacement_bytes = session_item_bytes(label, &attributes, content_type, secret.len())?;
        let mut collection = self
            .session_collection
            .lock()
            .expect("session collection lock poisoned");

        let existing_id = if replace {
            collection
                .items
                .values()
                .find(|item| item.metadata.attributes == attributes)
                .map(|item| item.metadata.id.clone())
        } else {
            None
        };

        let previous_bytes = existing_id
            .as_ref()
            .map_or(0, |id| collection.items[id].bytes());
        collection.check_capacity(previous_bytes, replacement_bytes)?;
        if existing_id.is_none() && collection.items.len() >= MAX_SESSION_ITEMS {
            return Err(crate::Error::Config(
                "temporary collection exceeds item limit".into(),
            ));
        }

        let now = now_secs();
        if let Some(id) = existing_id {
            let metadata = {
                let item = collection.items.get_mut(&id).expect("matched item exists");
                item.metadata.label = label.to_string();
                item.metadata.content_type = content_type.to_string();
                item.metadata.modified = now;
                item.secret = secret;
                item.metadata.clone()
            };
            collection.metadata.modified = now;
            return Ok((metadata, true));
        }

        let id = (0..SESSION_ITEM_ALLOCATION_ATTEMPTS)
            .map(|_| session_item_id())
            .find(|candidate| !collection.items.contains_key(candidate))
            .ok_or_else(|| {
                crate::Error::Config(format!(
                    "could not allocate temporary item id after {SESSION_ITEM_ALLOCATION_ATTEMPTS} attempts"
                ))
            })?;
        let metadata = ItemMeta {
            id: id.clone(),
            collection: SESSION_COLLECTION_ID.to_string(),
            label: label.to_string(),
            attributes,
            content_type: content_type.to_string(),
            ciphertext_sha256: None,
            created: now,
            modified: now,
        };
        collection.items.insert(
            id,
            SessionItem {
                metadata: metadata.clone(),
                secret,
            },
        );
        collection.metadata.modified = now;
        Ok((metadata, false))
    }

    /// Update fields of a temporary item, zeroizing any replaced secret.
    pub(crate) fn update_session_item(
        &self,
        id: &str,
        label: Option<&str>,
        attributes: Option<HashMap<String, String>>,
        content_type: Option<&str>,
        secret: Option<Zeroizing<Vec<u8>>>,
    ) -> crate::Result<ItemMeta> {
        let mut collection = self
            .session_collection
            .lock()
            .expect("session collection lock poisoned");
        let item = collection
            .items
            .get(id)
            .ok_or_else(|| crate::Error::NotFound(format!("item {id}")))?;
        let replacement_bytes = session_item_bytes(
            label.unwrap_or(&item.metadata.label),
            attributes.as_ref().unwrap_or(&item.metadata.attributes),
            content_type.unwrap_or(&item.metadata.content_type),
            secret
                .as_ref()
                .map_or(item.secret.len(), |secret| secret.len()),
        )?;
        collection.check_capacity(item.bytes(), replacement_bytes)?;
        let now = now_secs();
        let metadata = {
            let item = collection
                .items
                .get_mut(id)
                .ok_or_else(|| crate::Error::NotFound(format!("item {id}")))?;
            if let Some(label) = label {
                item.metadata.label = label.to_string();
            }
            if let Some(attributes) = attributes {
                item.metadata.attributes = attributes;
            }
            if let Some(content_type) = content_type {
                item.metadata.content_type = content_type.to_string();
            }
            if let Some(secret) = secret {
                item.secret = secret;
            }
            item.metadata.modified = now;
            item.metadata.clone()
        };
        collection.metadata.modified = now;
        Ok(metadata)
    }

    /// Delete a temporary item; dropping it zeroizes the secret bytes.
    pub(crate) fn delete_session_item(&self, id: &str) -> crate::Result<()> {
        let mut collection = self
            .session_collection
            .lock()
            .expect("session collection lock poisoned");
        if collection.items.remove(id).is_none() {
            return Err(crate::Error::NotFound(format!("item {id}")));
        }
        collection.metadata.modified = now_secs();
        Ok(())
    }

    /// Number of temporary secrets currently pinning the daemon to this login session.
    #[must_use]
    #[cfg(test)]
    pub(crate) fn session_secret_count(&self) -> usize {
        self.session_collection
            .lock()
            .expect("session collection lock poisoned")
            .items
            .len()
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

    pub(super) fn register_session_with<F>(
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
        if !paths.is_empty() {
            self.activity_complete.notify_one();
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

    /// Decrypt an incoming [`Secret`] with the transport session cipher.
    pub fn secret_to_plaintext(
        &self,
        secret: &Secret,
        owner: &str,
    ) -> Result<Zeroizing<Vec<u8>>, SecretError> {
        let cipher = self
            .session_cipher(&secret.session, owner)
            .ok_or_else(|| SecretError::NoSession(format!("no session {}", secret.session)))?;
        if matches!(cipher.as_ref(), SessionCipher::Plain) && !secret.parameters.is_empty() {
            return Err(
                fdo::Error::InvalidArgs("plain Secret parameters must be empty".into()).into(),
            );
        }
        Ok(cipher.decrypt(&secret.parameters, &secret.value)?)
    }

    /// Encrypt already-authorized zeroizing plaintext off the executor, before lifecycle locking.
    pub(crate) async fn encrypt_secret(
        self: &Arc<Self>,
        plaintext: Zeroizing<Vec<u8>>,
    ) -> Result<Vec<u8>, SecretError> {
        self.blocking(None, move |state| Ok(state.gpg.encrypt(&plaintext)?))
            .await
    }

    /// Encode plaintext for transport under an owned Secret Service session.
    pub fn plaintext_to_secret(
        &self,
        session: &OwnedObjectPath,
        plaintext: &[u8],
        content_type: &str,
        owner: &str,
    ) -> Result<Secret, SecretError> {
        let cipher = self
            .session_cipher(session, owner)
            .ok_or_else(|| SecretError::NoSession(format!("no session {session}")))?;
        let (parameters, value) = cipher.encrypt(plaintext);
        Ok(Secret {
            session: session.clone(),
            parameters,
            value,
            content_type: content_type.to_string(),
        })
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
        // Reject foreign/closed sessions before invoking the private-key agent.
        if self.session_cipher(session, owner).is_none() {
            return Err(SecretError::NoSession(format!("no session {session}")));
        }
        let plaintext = self.gpg.decrypt(ciphertext).await?;
        self.plaintext_to_secret(session, &plaintext, content_type, owner)
    }
}
