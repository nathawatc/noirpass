#[cfg(feature = "secret-tool-smoke")]
use std::process::{Command, Stdio};

use super::super::harness::harness;
#[cfg(feature = "secret-tool-smoke")]
use super::super::helpers::SERVICE_NAME;
use super::super::helpers::attrs;

/// Scenario 7: persistence — SIGTERM the daemon, respawn on the same store,
/// and prove the at-rest `OpenPGP` encryption still decrypts via `gpg-agent`.
pub(super) async fn s7_persistence_across_restart() {
    let h = harness();
    let a = attrs("s7");
    {
        let service = oo7::dbus::Service::encrypted().await.unwrap();
        let collection = service.default_collection().await.unwrap();
        collection
            .create_item(
                "s7-label",
                &a,
                oo7::Secret::text("survives restarts"),
                true,
                None,
            )
            .await
            .unwrap();
    }

    // The blocking stop/wait/respawn dance runs off the async threads.
    tokio::task::spawn_blocking(move || {
        h.stop_daemon();
        h.respawn_daemon();
    })
    .await
    .unwrap();

    // Fresh service handle (old sessions died with the old daemon).
    let service = oo7::dbus::Service::encrypted().await.unwrap();
    let collection = service.default_collection().await.unwrap();
    let found = collection.search_items(&a).await.unwrap();
    assert_eq!(found.len(), 1, "item must survive a daemon restart");
    assert_eq!(
        found[0].secret().await.unwrap().as_bytes(),
        b"survives restarts"
    );
    found[0].delete(None).await.unwrap();
}

/// Scenario 8: a real libsecret client (`secret-tool`) stores and looks up.
#[cfg(feature = "secret-tool-smoke")]
async fn secret_service_available_at(address: &str) -> bool {
    let Ok(builder) = zbus::connection::Builder::address(address) else {
        return false;
    };
    let Ok(connection) = builder.build().await else {
        return false;
    };
    let Ok(proxy) = zbus::fdo::DBusProxy::new(&connection).await else {
        return false;
    };
    let name = zbus::names::BusName::try_from(SERVICE_NAME).expect("valid service bus name");
    proxy.name_has_owner(name).await.unwrap_or(false)
}

#[cfg(feature = "secret-tool-smoke")]
async fn secret_tool_smoke_environment_available(address: Option<&str>) -> bool {
    let Some(address) = address.filter(|address| !address.is_empty()) else {
        return false;
    };
    if !secret_service_available_at(address).await {
        return false;
    }
    Command::new("secret-tool")
        .arg("--help")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(feature = "secret-tool-smoke")]
pub(super) async fn s8_secret_tool_smoke() {
    use std::io::Write as _;

    let address = std::env::var("DBUS_SESSION_BUS_ADDRESS").ok();
    if !secret_tool_smoke_environment_available(address.as_deref()).await {
        eprintln!("scenario 8 skipped: session bus, Secret Service, or secret-tool unavailable");
        return;
    }

    let store = tokio::task::spawn_blocking(|| {
        let mut child = Command::new("secret-tool")
            .args(["store", "--label=smoke", "sm", "ke"])
            .stdin(Stdio::piped())
            .spawn()?;
        let stdin = child.stdin.as_mut().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "secret-tool stdin unavailable",
            )
        })?;
        stdin.write_all(b"hunter2\n")?;
        child.wait()
    })
    .await
    .expect("secret-tool store task panicked")
    .expect("secret-tool store failed to execute");
    assert!(store.success(), "secret-tool store failed");

    let lookup = tokio::task::spawn_blocking(|| {
        Command::new("secret-tool")
            .args(["lookup", "sm", "ke"])
            .output()
    })
    .await
    .expect("secret-tool lookup task panicked")
    .expect("secret-tool lookup failed to execute");
    assert!(lookup.status.success(), "secret-tool lookup failed");
    assert_eq!(
        String::from_utf8_lossy(&lookup.stdout).trim(),
        "hunter2",
        "lookup must return the stored secret"
    );
}

#[cfg(feature = "secret-tool-smoke")]
#[tokio::test]
async fn optional_secret_tool_smoke_skips_unavailable_environment() {
    assert!(!secret_tool_smoke_environment_available(None).await);

    let dir = tempfile::tempdir().unwrap();
    let missing_socket = dir.path().join("missing-session-bus");
    let address = format!("unix:path={}", missing_socket.display());

    assert!(!secret_tool_smoke_environment_available(Some(&address)).await);
}
