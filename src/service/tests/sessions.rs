use zbus::zvariant::{OwnedObjectPath, Value};

use super::super::objects::validate_session_owner;
use super::super::session::Session;
use super::super::{
    ALGORITHM_DH, DhHandshake, SERVICE_PATH, SessionCipher, register_session_object_with,
    session_path,
};
use super::{p2p_pair, test_state};
use crate::gpg::test_support::TestGnupg;

#[tokio::test]
async fn vanished_owner_before_registration_and_presence_failure_leave_no_session() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    let (server_conn, _client_conn) = p2p_pair(state.clone()).await;
    let server = server_conn.object_server();
    let owner = ":1.7";
    assert!(state.remove_sessions_owned_by(owner).is_empty());
    for presence in [
        Ok(false),
        Err(zbus::fdo::Error::Failed("presence query failed".into())),
    ] {
        let path =
            register_session_object_with(server, &state, SessionCipher::Plain, owner.into(), || 63)
                .await
                .unwrap();
        assert_eq!(state.session_count(), 1);
        let err =
            validate_session_owner(server, &state, &path, owner, std::future::ready(presence))
                .await
                .unwrap_err();
        assert!(matches!(
            err,
            zbus::fdo::Error::AccessDenied(_) | zbus::fdo::Error::Failed(_)
        ));
        assert_eq!(state.session_count(), 0);
        assert!(matches!(
            server.interface::<_, Session>(&path).await,
            Err(zbus::Error::InterfaceNotFound)
        ));
    }
}

#[tokio::test]
async fn failed_object_registration_rolls_back_session_state() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    let (server_conn, _client_conn) = p2p_pair(state.clone()).await;
    let server = server_conn.object_server();
    let occupied = session_path(61);
    assert!(
        server
            .at(&occupied, Session::new(state.clone(), occupied.clone()))
            .await
            .unwrap()
    );

    let err =
        register_session_object_with(server, &state, SessionCipher::Plain, ":1.7".into(), || 61)
            .await
            .unwrap_err();

    assert!(err.to_string().contains("already registered"));
    assert_eq!(state.session_count(), 0);
    assert!(server.remove::<Session, _>(&occupied).await.unwrap());
}

#[tokio::test]
async fn object_registration_error_rolls_back_both_registries() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    let (server_conn, _client_conn) = p2p_pair(state.clone()).await;
    let server = server_conn.object_server().clone();
    assert!(
        server
            .at(SERVICE_PATH, zbus::fdo::ObjectManager)
            .await
            .unwrap()
    );
    let connection_guard = server_conn.clone();
    server_conn.close().await.unwrap();
    let path = session_path(62);

    let err =
        register_session_object_with(&server, &state, SessionCipher::Plain, ":1.7".into(), || 62)
            .await
            .unwrap_err();

    assert!(!err.to_string().is_empty());
    assert_eq!(state.session_count(), 0);
    assert!(matches!(
        server.interface::<_, Session>(&path).await,
        Err(zbus::Error::InterfaceNotFound)
    ));
    drop(connection_guard);
}

#[tokio::test]
async fn open_session_rejects_missing_sender() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    let (_server_conn, client_conn) = p2p_pair(state.clone()).await;

    let iface = Some("org.freedesktop.Secret.Service");
    let dest = None::<zbus::names::BusName<'_>>;

    // Peer-to-peer messages have no bus-assigned sender identity, so
    // client-owned session state must fail closed.
    let err = client_conn
        .call_method(
            dest.clone(),
            SERVICE_PATH,
            iface,
            "OpenSession",
            &("plain", Value::from("")),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, zbus::Error::MethodError(ref name, _, _)
        if name.as_str() == "org.freedesktop.DBus.Error.AccessDenied"));
    assert_eq!(state.session_count(), 0);

    // Missing identity also rejects DH sessions after input validation.
    let client_dh = DhHandshake::generate();
    let err = client_conn
        .call_method(
            dest.clone(),
            SERVICE_PATH,
            iface,
            "OpenSession",
            &(ALGORITHM_DH, Value::from(client_dh.public_bytes())),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, zbus::Error::MethodError(ref name, _, _)
        if name.as_str() == "org.freedesktop.DBus.Error.AccessDenied"));
    assert_eq!(state.session_count(), 0);

    // Unknown algorithm is NotSupported.
    let err = client_conn
        .call_method(
            dest.clone(),
            SERVICE_PATH,
            iface,
            "OpenSession",
            &("rot13", Value::from("")),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, zbus::Error::MethodError(ref name, _, _)
        if name.as_str() == "org.freedesktop.DBus.Error.NotSupported"));

    // ReadAlias resolves the default collection; unknown aliases → "/".
    let reply = client_conn
        .call_method(
            dest.clone(),
            SERVICE_PATH,
            iface,
            "ReadAlias",
            &("default",),
        )
        .await
        .unwrap();
    let path: OwnedObjectPath = reply.body().deserialize().unwrap();
    assert_eq!(path.as_str(), "/org/freedesktop/secrets/collection/default");

    let reply = client_conn
        .call_method(dest, SERVICE_PATH, iface, "ReadAlias", &("nonexistent",))
        .await
        .unwrap();
    let path: OwnedObjectPath = reply.body().deserialize().unwrap();
    assert_eq!(path.as_str(), "/");
}
