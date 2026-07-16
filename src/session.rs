//! `org.freedesktop.Secret.Session` objects and the `Secret` wire struct.
//!
//! A session is negotiated once per client via `Service.OpenSession` and
//! defines how secret values are protected on the bus (see [`crate::crypto`]).
//! Session objects live at `/org/freedesktop/secrets/session/s<n>` and only
//! support `Close`.

use std::future::Future;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use zbus::interface;
use zbus::object_server::ObjectServer;
use zbus::zvariant::{OwnedObjectPath, Type};

use crate::service::{SecretError, ServiceState, message_sender};

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
        self.state.touch();
        let owner = message_sender(&header)?;
        self.close_with_removal(&owner, server.remove::<Self, _>(&self.path))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{DhHandshake, SessionCipher};
    use crate::gpg::{Gpg, parse_recipient_cert, test_support::TestGnupg};
    use crate::store::Store;
    use zbus::connection::Builder;
    use zbus::zvariant::serialized::Context;
    use zbus::zvariant::{LE, to_bytes};

    fn test_state(gnupg: &TestGnupg, dir: &std::path::Path) -> Arc<ServiceState> {
        let store = Store::open(dir).unwrap();
        store.ensure_default().unwrap();
        let cert = parse_recipient_cert(&gnupg.export_public_binary()).unwrap();
        let gpg = Gpg::from_cert_with_homedir(cert, Some(gnupg.path().to_path_buf())).unwrap();
        ServiceState::new(store, gpg)
    }

    async fn p2p_pair() -> (zbus::Connection, zbus::Connection) {
        let guid = zbus::Guid::generate();
        let (p0, p1) = tokio::net::UnixStream::pair().unwrap();
        let server = Builder::unix_stream(p0).server(guid).unwrap().p2p().build();
        let client = Builder::unix_stream(p1).p2p().build();
        let (server, client) = tokio::join!(server, client);
        (server.unwrap(), client.unwrap())
    }

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

    #[tokio::test]
    async fn close_removes_object_and_session_state() {
        let gnupg = TestGnupg::new();
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(&gnupg, tmp.path());
        let owner = ":1.7";
        let path = state
            .register_session(SessionCipher::Plain, owner.into())
            .unwrap();
        let session = Session::new(state.clone(), path.clone());
        let (server_conn, _client_conn) = p2p_pair().await;
        let server = server_conn.object_server();
        assert!(
            server
                .at(&path, Session::new(state.clone(), path.clone()))
                .await
                .unwrap()
        );

        session
            .close_with_removal(owner, server.remove::<Session, _>(&path))
            .await
            .unwrap();

        assert!(state.session_cipher(&path, owner).is_none());
        assert!(matches!(
            server.interface::<_, Session>(&path).await,
            Err(zbus::Error::InterfaceNotFound)
        ));

        let err = session
            .close_with_removal(owner, std::future::ready(Ok(false)))
            .await
            .unwrap_err();
        assert!(matches!(err, SecretError::NoSession(_)));
    }

    #[tokio::test]
    async fn false_removal_result_preserves_session_state() {
        let gnupg = TestGnupg::new();
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(&gnupg, tmp.path());
        let owner = ":1.7";
        let path = state
            .register_session(SessionCipher::Plain, owner.into())
            .unwrap();
        let unrelated = state
            .register_session(SessionCipher::Plain, ":1.8".into())
            .unwrap();
        let original_cipher = state.session_cipher(&path, owner).unwrap();
        let unrelated_cipher = state.session_cipher(&unrelated, ":1.8").unwrap();
        let session = Session::new(state.clone(), path.clone());

        let err = session
            .close_with_removal(owner, std::future::ready(Ok(false)))
            .await
            .unwrap_err();

        assert!(matches!(err, SecretError::NoSession(_)));
        assert!(Arc::ptr_eq(
            &original_cipher,
            &state.session_cipher(&path, owner).unwrap()
        ));
        assert!(Arc::ptr_eq(
            &unrelated_cipher,
            &state.session_cipher(&unrelated, ":1.8").unwrap()
        ));
        assert_eq!(state.session_count(), 2);
    }

    #[tokio::test]
    async fn failed_close_preserves_state_and_can_be_retried() {
        let gnupg = TestGnupg::new();
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(&gnupg, tmp.path());
        let owner = ":1.7";
        let client_dh = DhHandshake::generate();
        let cipher = DhHandshake::generate()
            .derive(&client_dh.public_bytes())
            .unwrap();
        let path = state.register_session(cipher, owner.into()).unwrap();
        let original_cipher = state.session_cipher(&path, owner).unwrap();
        let session = Session::new(state.clone(), path.clone());
        let (server_conn, _client_conn) = p2p_pair().await;
        let server = server_conn.object_server();
        assert!(
            server
                .at(&path, Session::new(state.clone(), path.clone()))
                .await
                .unwrap()
        );

        let err = session
            .close_with_removal(
                owner,
                std::future::ready(Err(zbus::Error::Failure("injected removal failure".into()))),
            )
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            SecretError::ZBus(zbus::Error::Failure(message))
                if message == "injected removal failure"
        ));
        let restored_cipher = state.session_cipher(&path, owner).unwrap();
        assert!(Arc::ptr_eq(&original_cipher, &restored_cipher));
        assert!(state.session_cipher(&path, ":1.8").is_none());
        assert!(server.interface::<_, Session>(&path).await.is_ok());

        session
            .close_with_removal(owner, server.remove::<Session, _>(&path))
            .await
            .unwrap();
        assert!(state.session_cipher(&path, owner).is_none());
        assert!(matches!(
            server.interface::<_, Session>(&path).await,
            Err(zbus::Error::InterfaceNotFound)
        ));
    }

    #[tokio::test]
    async fn concurrent_close_preserves_unrelated_session() {
        let gnupg = TestGnupg::new();
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(&gnupg, tmp.path());
        let owner = ":1.7";
        let path = state
            .register_session(SessionCipher::Plain, owner.into())
            .unwrap();
        let unrelated = state
            .register_session(SessionCipher::Plain, ":1.8".into())
            .unwrap();
        let session = Session::new(state.clone(), path.clone());
        let (server_conn, _client_conn) = p2p_pair().await;
        let server = server_conn.object_server();
        assert!(
            server
                .at(&path, Session::new(state.clone(), path.clone()))
                .await
                .unwrap()
        );

        let (first, second) = tokio::join!(
            session.close_with_removal(owner, server.remove::<Session, _>(&path)),
            session.close_with_removal(owner, server.remove::<Session, _>(&path)),
        );

        assert!(first.is_ok() ^ second.is_ok());
        let failed = first.err().or_else(|| second.err()).unwrap();
        assert!(matches!(
            failed,
            SecretError::NoSession(_) | SecretError::ZBus(zbus::Error::InterfaceNotFound)
        ));
        assert!(state.session_cipher(&path, owner).is_none());
        assert!(state.session_cipher(&unrelated, ":1.8").is_some());
    }
}
