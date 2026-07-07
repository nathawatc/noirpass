//! `org.freedesktop.Secret.Session` objects and the `Secret` wire struct.
//!
//! A session is negotiated once per client via `Service.OpenSession` and
//! defines how secret values are protected on the bus (see [`crate::crypto`]).
//! Session objects live at `/org/freedesktop/secrets/session/s<n>` and only
//! support `Close`.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use zbus::interface;
use zbus::object_server::ObjectServer;
use zbus::zvariant::{OwnedObjectPath, Type};

use crate::service::ServiceState;

/// The Secret Service `Secret` structure: `(oayays)`.
///
/// * `session` — the session the value is encoded for.
/// * `parameters` — algorithm parameters; the AES IV for DH sessions, empty
///   for plain sessions.
/// * `value` — the (possibly encrypted) secret value.
/// * `content_type` — MIME content type of the plaintext value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct Secret {
    /// Session the secret is encoded for.
    pub session: OwnedObjectPath,
    /// Algorithm parameters (AES IV, or empty for plain).
    pub parameters: Vec<u8>,
    /// The possibly-encrypted secret value.
    pub value: Vec<u8>,
    /// MIME content type of the plaintext.
    pub content_type: String,
}

/// A `org.freedesktop.Secret.Session` D-Bus object.
///
/// Client-disconnect cleanup is not implemented (a leaked session persists
/// until the daemon exits); clients are expected to call `Close`.
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
}

#[interface(name = "org.freedesktop.Secret.Session")]
impl Session {
    /// Close the session: forget its cipher and unregister the object.
    async fn close(&self, #[zbus(object_server)] server: &ObjectServer) -> zbus::fdo::Result<()> {
        self.state.touch();
        self.state.remove_session(&self.path);
        server.remove::<Self, _>(&self.path).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zbus::zvariant::serialized::Context;
    use zbus::zvariant::{LE, to_bytes};

    #[test]
    fn secret_signature_matches_spec() {
        assert_eq!(Secret::SIGNATURE.to_string(), "(oayays)");
    }

    #[test]
    fn secret_zvariant_roundtrip() {
        let secret = Secret {
            session: OwnedObjectPath::try_from("/org/freedesktop/secrets/session/s1").unwrap(),
            parameters: vec![1, 2, 3, 4],
            value: vec![9, 8, 7],
            content_type: "text/plain".to_string(),
        };

        let ctxt = Context::new_dbus(LE, 0);
        let bytes = to_bytes(ctxt, &secret).unwrap();
        let (decoded, _): (Secret, usize) = bytes.deserialize().unwrap();
        assert_eq!(decoded, secret);
    }
}
