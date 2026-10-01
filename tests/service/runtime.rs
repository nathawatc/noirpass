use std::collections::HashMap;
use std::time::{Duration, Instant};

use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

use super::super::common::{
    export_public_cert, init_noirpass_store, sigterm, spawn_daemon, spawn_dbus_daemon,
    wait_for_name, wait_with_timeout,
};
use super::harness::harness;
use super::helpers::{
    INVALID_ARGS_ERROR, NO_SESSION_ERROR, SERVICE_NAME, UNKNOWN_OBJECT_ERROR, assert_method_error,
    service_proxy,
};

pub(super) fn daemon_runtime_does_not_spawn_gpg() {
    let h = harness();
    assert!(
        !h.fake_gpg_log.exists(),
        "daemon spawned gpg: {}",
        std::fs::read_to_string(&h.fake_gpg_log).unwrap_or_default()
    );
}

pub(super) async fn transport_session_limit_is_reported_and_close_restores_capacity() {
    harness();
    let connection = zbus::Connection::session().await.unwrap();
    let proxy = service_proxy(&connection).await;
    let mut sessions = Vec::new();
    for _ in 0..64 {
        let (_, path): (OwnedValue, OwnedObjectPath) = proxy
            .call("OpenSession", &("plain", Value::from("")))
            .await
            .unwrap();
        sessions.push(path);
    }
    let err = proxy
        .call::<_, _, (OwnedValue, OwnedObjectPath)>("OpenSession", &("plain", Value::from("")))
        .await
        .unwrap_err();
    assert_method_error(&err, "org.freedesktop.DBus.Error.LimitsExceeded");
    let session = zbus::Proxy::new(
        &connection,
        SERVICE_NAME,
        &sessions[0],
        "org.freedesktop.Secret.Session",
    )
    .await
    .unwrap();
    session.call::<_, _, ()>("Close", &()).await.unwrap();
    let (_, replacement): (OwnedValue, OwnedObjectPath) = proxy
        .call("OpenSession", &("plain", Value::from("")))
        .await
        .unwrap();
    assert_ne!(replacement, sessions[0]);
    drop(session);
    drop(proxy);
    connection.close().await.unwrap();
}

#[tokio::test]
async fn rejected_plain_open_session_does_not_register_session() {
    let h = harness();
    let (mut dbus, address) = spawn_dbus_daemon();
    let store = tempfile::tempdir().unwrap();
    let cert = export_public_cert(&h.gnupg_home);
    init_noirpass_store(store.path(), &cert);
    let mut daemon = spawn_daemon(
        &address,
        &h.gnupg_home,
        store.path(),
        "0",
        Some(&h.fake_gpg_dir),
    );
    wait_for_name(&address);

    let conn = zbus::connection::Builder::address(address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let proxy = service_proxy(&conn).await;
    let err = proxy
        .call::<_, _, (OwnedValue, OwnedObjectPath)>(
            "OpenSession",
            &("plain", Value::from("non-empty")),
        )
        .await
        .unwrap_err();
    assert_method_error(&err, INVALID_ARGS_ERROR);
    drop(proxy);

    // Keep connection alive while daemon decides idle exit. A registered session
    // would keep daemon alive; successful exit proves rejected call registered none.
    let status = tokio::task::spawn_blocking(move || {
        wait_with_timeout(&mut daemon, Duration::from_secs(10))
    })
    .await
    .unwrap();
    assert!(
        status.success(),
        "daemon should idle-exit without rejected session, got {status}"
    );
    drop(conn);

    dbus.kill().expect("kill private dbus-daemon");
    let _ = dbus.wait();
}

/// Scenario 9: a daemon with `idle_exit = 0` in `config.toml` exits after its
/// client disconnects. Runs on a private bus + store so it cannot disturb `end_to_end`.
#[tokio::test]
async fn idle_exit_daemon_exits() {
    let h = harness(); // shared hermetic GNUPGHOME (env is process-global anyway)

    let (mut dbus, address) = spawn_dbus_daemon();
    let store = tempfile::tempdir().unwrap();
    let cert = export_public_cert(&h.gnupg_home);
    init_noirpass_store(store.path(), &cert);
    let config_path = store.path().join("config.toml");
    let mut config = std::fs::read_to_string(&config_path).unwrap();
    assert!(config.contains("idle_exit = 300"));
    config = config.replace("idle_exit = 300", "idle_exit = 0");
    std::fs::write(config_path, config).unwrap();
    let mut daemon = spawn_daemon(
        &address,
        &h.gnupg_home,
        store.path(),
        "",
        Some(&h.fake_gpg_dir),
    );
    wait_for_name(&address);

    // Open a session and drop the client without calling Session.Close. The
    // leaked session must not block idle-exit once NameOwnerChanged reaps it.
    {
        let conn = zbus::connection::Builder::address(address.as_str())
            .unwrap()
            .build()
            .await
            .unwrap();
        let proxy = service_proxy(&conn).await;
        let (_output, session): (OwnedValue, OwnedObjectPath) = proxy
            .call("OpenSession", &("plain", Value::from("")))
            .await
            .unwrap();
        assert!(
            session
                .as_str()
                .starts_with("/org/freedesktop/secrets/session/s")
        );
    }

    let status = tokio::task::spawn_blocking(move || {
        wait_with_timeout(&mut daemon, Duration::from_secs(10))
    })
    .await
    .unwrap();
    assert!(
        status.success(),
        "daemon should idle-exit cleanly after client disconnect, got {status}"
    );
    assert!(
        !h.fake_gpg_log.exists(),
        "daemon spawned gpg during idle-exit test: {}",
        std::fs::read_to_string(&h.fake_gpg_log).unwrap_or_default()
    );

    dbus.kill().expect("kill private dbus-daemon");
    let _ = dbus.wait();
}

#[tokio::test]
async fn temporary_secret_survives_idle_exit_but_not_bus_shutdown() {
    use noirpass::service::session::Secret;
    use zeroize::Zeroizing;

    let h = harness();
    let (mut dbus, address) = spawn_dbus_daemon();
    let store = tempfile::tempdir().unwrap();
    let cert = export_public_cert(&h.gnupg_home);
    init_noirpass_store(store.path(), &cert);
    let mut daemon = spawn_daemon(
        &address,
        &h.gnupg_home,
        store.path(),
        "0",
        Some(&h.fake_gpg_dir),
    );
    wait_for_name(&address);
    let conn = zbus::connection::Builder::address(address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let service = service_proxy(&conn).await;
    let (_, session): (OwnedValue, OwnedObjectPath) = service
        .call("OpenSession", &("plain", Value::from("")))
        .await
        .unwrap();
    let collection = zbus::Proxy::new(
        &conn,
        SERVICE_NAME,
        "/org/freedesktop/secrets/aliases/session",
        "org.freedesktop.Secret.Collection",
    )
    .await
    .unwrap();
    let secret = Secret {
        session: session.clone(),
        parameters: Vec::new(),
        value: Zeroizing::new(b"keep until bus ends".to_vec()),
        content_type: "text/plain".into(),
    };
    let properties: HashMap<String, OwnedValue> = HashMap::new();
    collection
        .call::<_, _, (OwnedObjectPath, OwnedObjectPath)>(
            "CreateItem",
            &(&properties, &secret, false),
        )
        .await
        .unwrap();
    let transport = zbus::Proxy::new(
        &conn,
        SERVICE_NAME,
        session,
        "org.freedesktop.Secret.Session",
    )
    .await
    .unwrap();
    transport.call::<_, _, ()>("Close", &()).await.unwrap();
    drop(transport);
    drop(collection);
    drop(service);
    conn.close().await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        daemon.try_wait().unwrap().is_none(),
        "temporary secret must block idle_exit=0 after transport closes"
    );
    dbus.kill().expect("kill private dbus-daemon");
    assert_eq!(
        std::os::unix::process::ExitStatusExt::signal(&dbus.wait().unwrap()),
        Some(libc::SIGKILL)
    );
    let status = tokio::task::spawn_blocking(move || {
        wait_with_timeout(&mut daemon, Duration::from_secs(10))
    })
    .await
    .unwrap();
    assert!(
        status.success(),
        "daemon must exit when its private session bus closes: {status}"
    );
}

#[tokio::test]
async fn disconnect_unregisters_owned_session() {
    let h = harness();
    let (mut dbus, address) = spawn_dbus_daemon();
    let store = tempfile::tempdir().unwrap();
    let cert = export_public_cert(&h.gnupg_home);
    init_noirpass_store(store.path(), &cert);
    let mut daemon = spawn_daemon(
        &address,
        &h.gnupg_home,
        store.path(),
        "-1",
        Some(&h.fake_gpg_dir),
    );
    wait_for_name(&address);

    let session = {
        let owner = zbus::connection::Builder::address(address.as_str())
            .unwrap()
            .build()
            .await
            .unwrap();
        let proxy = service_proxy(&owner).await;
        let (_, session): (OwnedValue, OwnedObjectPath) = proxy
            .call("OpenSession", &("plain", Value::from("")))
            .await
            .unwrap();
        session
    };

    let observer = zbus::connection::Builder::address(address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let session_proxy = zbus::Proxy::new(
        &observer,
        SERVICE_NAME,
        session,
        "org.freedesktop.Secret.Session",
    )
    .await
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let err = session_proxy
            .call::<_, _, ()>("Close", &())
            .await
            .unwrap_err();
        match &err {
            zbus::Error::MethodError(name, _, _) if name.as_str() == UNKNOWN_OBJECT_ERROR => break,
            zbus::Error::MethodError(name, _, _)
                if name.as_str() == NO_SESSION_ERROR && Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            _ => panic!("session object survived owner disconnect: {err}"),
        }
    }

    sigterm(daemon.id());
    assert!(wait_with_timeout(&mut daemon, Duration::from_secs(10)).success());
    dbus.kill().expect("kill private dbus-daemon");
    let _ = dbus.wait();
}

#[tokio::test]
async fn stale_session_path_is_not_reissued_after_restart() {
    let h = harness();
    let (mut dbus, address) = spawn_dbus_daemon();
    let store = tempfile::tempdir().unwrap();
    let cert = export_public_cert(&h.gnupg_home);
    init_noirpass_store(store.path(), &cert);
    let mut daemon = spawn_daemon(
        &address,
        &h.gnupg_home,
        store.path(),
        "-1",
        Some(&h.fake_gpg_dir),
    );
    wait_for_name(&address);

    let conn = zbus::connection::Builder::address(address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let proxy = service_proxy(&conn).await;
    let (_, stale): (OwnedValue, OwnedObjectPath) = proxy
        .call("OpenSession", &("plain", Value::from("")))
        .await
        .unwrap();

    sigterm(daemon.id());
    assert!(wait_with_timeout(&mut daemon, Duration::from_secs(10)).success());
    daemon = spawn_daemon(
        &address,
        &h.gnupg_home,
        store.path(),
        "-1",
        Some(&h.fake_gpg_dir),
    );
    wait_for_name(&address);

    let no_items: Vec<OwnedObjectPath> = Vec::new();
    let before_new = proxy
        .call::<_, _, HashMap<OwnedObjectPath, noirpass::service::session::Secret>>(
            "GetSecrets",
            &(&no_items, &stale),
        )
        .await
        .unwrap_err();
    assert_method_error(&before_new, NO_SESSION_ERROR);

    let stale_object = zbus::Proxy::new(
        &conn,
        SERVICE_NAME,
        stale.clone(),
        "org.freedesktop.Secret.Session",
    )
    .await
    .unwrap();
    let err = stale_object
        .call::<_, _, ()>("Close", &())
        .await
        .unwrap_err();
    assert_method_error(&err, UNKNOWN_OBJECT_ERROR);

    let (_, replacement): (OwnedValue, OwnedObjectPath) = proxy
        .call("OpenSession", &("plain", Value::from("")))
        .await
        .unwrap();
    let stale_after_new = proxy
        .call::<_, _, HashMap<OwnedObjectPath, noirpass::service::session::Secret>>(
            "GetSecrets",
            &(&no_items, &stale),
        )
        .await;

    let replacement_session = zbus::Proxy::new(
        &conn,
        SERVICE_NAME,
        replacement.clone(),
        "org.freedesktop.Secret.Session",
    )
    .await
    .unwrap();
    replacement_session
        .call::<_, _, ()>("Close", &())
        .await
        .unwrap();
    sigterm(daemon.id());
    assert!(wait_with_timeout(&mut daemon, Duration::from_secs(10)).success());
    dbus.kill().expect("kill private dbus-daemon");
    let _ = dbus.wait();

    assert_ne!(stale, replacement, "daemon reissued stale session path");
    let err = stale_after_new.unwrap_err();
    assert_method_error(&err, NO_SESSION_ERROR);
}
