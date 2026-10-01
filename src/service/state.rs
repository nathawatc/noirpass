//! Shared daemon state, session ownership, and secret transport.

use std::collections::{HashMap, hash_map::Entry};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::{Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard, Notify};
use zbus::fdo;
use zbus::zvariant::OwnedObjectPath;
use zeroize::Zeroizing;

use super::{SESSION_COLLECTION_ID, SecretError, session_path};
use crate::crypto::SessionCipher;
use crate::gpg::Gpg;
use crate::service::session::Secret;
use crate::store::{CollectionMeta, ItemMeta, Store};

/// Bound retries so a broken entropy source fails instead of looping forever.
/// Exhausting this with random 128-bit IDs requires 128 consecutive collisions.
pub(super) const SESSION_ALLOCATION_ATTEMPTS: usize = 128;

/// Bound retries for temporary item identifiers for the same reason as session paths.
const SESSION_ITEM_ALLOCATION_ATTEMPTS: usize = 128;

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

struct SessionCollectionState {
    metadata: CollectionMeta,
    items: HashMap<String, SessionItem>,
}

impl SessionCollectionState {
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
        }
    }
}

/// Marks one in-flight D-Bus method as activity until handler return.
pub(crate) struct ActivityGuard<'a> {
    state: &'a ServiceState,
}

impl Drop for ActivityGuard<'_> {
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

/// State shared by every D-Bus object of the daemon.
pub struct ServiceState {
    store: Store,
    gpg: Gpg,
    sessions: Mutex<HashMap<OwnedObjectPath, SessionEntry>>,
    session_collection: Mutex<SessionCollectionState>,
    activity: Mutex<ActivityState>,
    activity_complete: Notify,
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
            session_collection: Mutex::new(SessionCollectionState::new()),
            activity: Mutex::new(ActivityState {
                active_calls: 0,
                had_activity: false,
                last_activity: Instant::now(),
                shutting_down: false,
            }),
            activity_complete: Notify::new(),
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

    /// Track one D-Bus method until its handler returns.
    pub(crate) fn activity(&self) -> fdo::Result<ActivityGuard<'_>> {
        let mut activity = self.activity.lock().expect("activity lock poisoned");
        if activity.shutting_down {
            return Err(fdo::Error::Failed("service is shutting down".into()));
        }
        activity.active_calls += 1;
        activity.had_activity = true;
        Ok(ActivityGuard { state: self })
    }

    /// Close admission for new application handlers.
    pub fn begin_shutdown(&self) {
        self.activity
            .lock()
            .expect("activity lock poisoned")
            .shutting_down = true;
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

    /// Metadata for the built-in in-memory session collection.
    pub(crate) fn session_collection_meta(&self) -> CollectionMeta {
        self.session_collection
            .lock()
            .expect("session collection lock poisoned")
            .metadata
            .clone()
    }

    /// Update the session collection label without persisting it.
    pub(crate) fn set_session_collection_label(&self, label: &str) {
        let mut collection = self
            .session_collection
            .lock()
            .expect("session collection lock poisoned");
        collection.metadata.label = label.to_string();
        collection.metadata.modified = now_secs();
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

    /// Decrypt an incoming [`Secret`], then `gpg`-encrypt it for persistent storage.
    pub fn secret_to_ciphertext(
        &self,
        secret: &Secret,
        owner: &str,
    ) -> Result<Vec<u8>, SecretError> {
        let plaintext = self.secret_to_plaintext(secret, owner)?;
        Ok(self.gpg.encrypt(&plaintext)?)
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
