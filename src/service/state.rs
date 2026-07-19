//! Shared daemon state, session ownership, and secret transport.

use std::collections::{HashMap, hash_map::Entry};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard};
use zbus::fdo;
use zbus::zvariant::OwnedObjectPath;

use super::{SecretError, session_path};
use crate::crypto::SessionCipher;
use crate::gpg::Gpg;
use crate::session::Secret;
use crate::store::Store;

/// Bound retries so a broken entropy source fails instead of looping forever.
/// Exhausting this with random 128-bit IDs requires 128 consecutive collisions.
pub(super) const SESSION_ALLOCATION_ATTEMPTS: usize = 128;

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
