//! `org.freedesktop.Secret.Session` objects and the `Secret` wire struct.
//!
//! A session is negotiated once per client via `Service.OpenSession` and
//! defines how secret values are protected on the bus (see [`crate::crypto`]).
//! Session objects live at `/org/freedesktop/secrets/session/s<n>` and only
//! support `Close`.

use std::fmt;
use std::future::Future;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use zbus::interface;
use zbus::object_server::ObjectServer;
use zbus::zvariant::{OwnedObjectPath, Type};
use zeroize::Zeroizing;

use crate::service::{SecretError, ServiceState, message_sender};

/// The Secret Service `Secret` structure: `(oayays)`.
///
/// * `session` — the session the value is encoded for.
/// * `parameters` — algorithm parameters; the AES IV for DH sessions, empty
///   for plain sessions.
/// * `value` — the (possibly encrypted) secret value.
/// * `content_type` — MIME content type of the plaintext value.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Type)]
#[zvariant(signature = "(oayays)")]
pub struct Secret {
    /// Session the secret is encoded for.
    pub session: OwnedObjectPath,
    /// Algorithm parameters (AES IV, or empty for plain).
    pub parameters: Vec<u8>,
    /// The possibly-encrypted secret value.
    pub value: Zeroizing<Vec<u8>>,
    /// MIME content type of the plaintext.
    pub content_type: String,
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Secret")
            .field("session", &self.session)
            .field("parameters", &self.parameters)
            .field("value", &"[REDACTED]")
            .field("content_type", &self.content_type)
            .finish()
    }
}

/// A `org.freedesktop.Secret.Session` D-Bus object.
///
/// Clients should call `Close`; sessions of clients that leave the bus
/// without closing are reaped by the daemon's `NameOwnerChanged` watcher.
pub struct Session {
    state: Arc<ServiceState>,
    path: OwnedObjectPath,
}

impl Session {
    /// Create a session object serving at `path`.
    #[must_use]
    pub fn new(state: Arc<ServiceState>, path: OwnedObjectPath) -> Self {
        Self { state, path }
    }

    async fn close_with_removal<F>(&self, owner: &str, removal: F) -> Result<(), SecretError>
    where
        F: Future<Output = zbus::Result<bool>>,
    {
        if self.state.session_cipher(&self.path, owner).is_none() {
            return Err(SecretError::NoSession(format!("no session {}", self.path)));
        }
        if !removal.await.map_err(SecretError::ZBus)? {
            return Err(SecretError::NoSession(format!("no session {}", self.path)));
        }
        if !self.state.remove_session(&self.path, owner) {
            return Err(SecretError::NoSession(format!("no session {}", self.path)));
        }
        Ok(())
    }
}

#[interface(name = "org.freedesktop.Secret.Session")]
impl Session {
    /// Close the session: forget its cipher and unregister the object.
    async fn close(
        &self,
        #[zbus(object_server)] server: &ObjectServer,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<(), SecretError> {
        let _activity = self.state.activity()?;
        let owner = message_sender(&header)?;
        self.close_with_removal(&owner, server.remove::<Self, _>(&self.path))
            .await
    }
}

#[cfg(test)]
mod tests;
