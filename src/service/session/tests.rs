use super::*;
use crate::crypto::{DhHandshake, SessionCipher};
use crate::gpg::test_support::TestGnupg;
use crate::service::tests::test_state;
use zbus::connection::Builder;
use zbus::zvariant::serialized::Context;
use zbus::zvariant::{LE, to_bytes};

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
fn secret_debug_redacts_value() {
    let secret = Secret {
        session: OwnedObjectPath::try_from("/org/freedesktop/secrets/session/s1").unwrap(),
        parameters: Vec::new(),
        value: Zeroizing::new(b"do not print this".to_vec()),
        content_type: "text/plain".to_string(),
    };

    let debug = format!("{secret:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("do not print this"));
}

#[test]
fn secret_zvariant_roundtrip() {
    let secret = Secret {
        session: OwnedObjectPath::try_from("/org/freedesktop/secrets/session/s1").unwrap(),
        parameters: vec![1, 2, 3, 4],
        value: Zeroizing::new(vec![9, 8, 7]),
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
