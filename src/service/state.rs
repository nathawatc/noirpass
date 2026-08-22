//! Shared daemon state, session ownership, and secret transport.

use std::collections::{HashMap, hash_map::Entry};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard, Notify};
use zbus::fdo;
use zbus::zvariant::OwnedObjectPath;

use super::{SecretError, session_path};
use crate::crypto::SessionCipher;
use crate::gpg::Gpg;
use crate::service::session::Secret;
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

struct ActivityState {
    active_calls: usize,
    had_activity: bool,
    last_activity: Instant,
    shutting_down: bool,
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
