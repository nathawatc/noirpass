use std::collections::HashMap;
use std::path::Path;
use std::process::Child;
use std::time::{Duration, Instant};

use noirpass::store::{CollectionMeta, Store};
use redb::{Database, TableDefinition};

use super::super::common::{
    export_public_cert, init_noirpass_store, setup_gnupg, sigterm, spawn_daemon, spawn_dbus_daemon,
    wait_for_name, wait_with_timeout,
};
use super::harness::harness;

#[test]
fn daemon_recovers_pending_backup_and_quarantine() {
    let h = harness();
    let cert = export_public_cert(&h.gnupg_home);
    for kind in ["backup", "quarantine"] {
        let (mut dbus, address) = spawn_dbus_daemon();
        let store_dir = tempfile::tempdir().unwrap();
        init_noirpass_store(store_dir.path(), &cert);
        let store = Store::open_existing(store_dir.path()).unwrap();
        let collection = store.ensure_default().unwrap();
        let item = store
            .create_or_replace_item(
                &collection.id,
                kind,
                HashMap::new(),
                "text/plain",
                b"old-ciphertext",
                false,
            )
            .unwrap()
            .0;
        let canonical = store_dir
            .path()
            .join("secrets")
            .join(format!("{}.gpg", item.id));
        let recovery = store_dir
            .path()
            .join("secrets")
            .join(format!(".noirpass-{kind}-{}-0000000000000001.gpg", item.id));
        std::fs::rename(&canonical, &recovery).unwrap();
        if kind == "backup" {
            std::fs::write(&canonical, b"uncommitted-new-ciphertext").unwrap();
        }
        drop(store);

        let mut daemon = spawn_daemon(
            &address,
            &h.gnupg_home,
            store_dir.path(),
            "-1",
            Some(&h.fake_gpg_dir),
        );
        wait_for_name(&address);
        assert_eq!(std::fs::read(&canonical).unwrap(), b"old-ciphertext");
        assert!(!recovery.exists());

        sigterm(daemon.id());
        assert!(wait_with_timeout(&mut daemon, Duration::from_secs(10)).success());
        dbus.kill().expect("kill private dbus-daemon");
        let _ = dbus.wait();
    }
}

#[test]
fn daemon_rejects_path_unsafe_collection_identity() {
    const COLLECTIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("collections");
    let h = harness();
    let (mut dbus, address) = spawn_dbus_daemon();
    let store = tempfile::tempdir().unwrap();
    let cert = export_public_cert(&h.gnupg_home);
    init_noirpass_store(store.path(), &cert);
    let db = Database::open(store.path().join("index.redb")).unwrap();
    let txn = db.begin_write().unwrap();
    {
        let mut collections = txn.open_table(COLLECTIONS).unwrap();
        let metadata = CollectionMeta {
            id: "bad-key".to_string(),
            label: "corrupt".to_string(),
            created: 1,
            modified: 1,
        };
        let bytes = serde_json::to_vec(&metadata).unwrap();
        collections.insert("bad-key", bytes.as_slice()).unwrap();
    }
    txn.commit().unwrap();
    drop(db);
    let mut daemon = spawn_daemon(
        &address,
        &h.gnupg_home,
        store.path(),
        "-1",
        Some(&h.fake_gpg_dir),
    );

    let status = wait_with_timeout(&mut daemon, Duration::from_secs(10));
    assert!(
        !status.success(),
        "daemon must reject corrupt collection ids"
    );
    dbus.kill().expect("kill private dbus-daemon");
    let _ = dbus.wait();
}

fn startup_test_material() -> (tempfile::TempDir, Vec<u8>, tempfile::TempDir) {
    let gnupg = tempfile::tempdir().unwrap();
    setup_gnupg(gnupg.path());
    let cert = export_public_cert(gnupg.path());
    let (fake_gpg, _) = super::super::common::fake_gpg_dir();
    (gnupg, cert, fake_gpg)
}

fn remove_default_collection(store_dir: &Path, preserve_alias: bool) {
    const COLLECTIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("collections");
    const ALIASES: TableDefinition<&str, &str> = TableDefinition::new("aliases");

    let db = Database::open(store_dir.join("index.redb")).unwrap();
    let txn = db.begin_write().unwrap();
    {
        let mut collections = txn.open_table(COLLECTIONS).unwrap();
        collections.remove("default").unwrap();
    }
    if !preserve_alias {
        let mut aliases = txn.open_table(ALIASES).unwrap();
        aliases.remove("default").unwrap();
    }
    txn.commit().unwrap();
}

fn wait_for_startup_exit(daemon: &mut Child) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = daemon.try_wait().expect("try_wait") {
            return status;
        }
        if Instant::now() >= deadline {
            sigterm(daemon.id());
            return wait_with_timeout(daemon, Duration::from_secs(10));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn daemon_rejects_missing_default_collection_with_dangling_default_alias() {
    let (gnupg, cert, fake_gpg) = startup_test_material();
    let (mut dbus, address) = spawn_dbus_daemon();
    let store = tempfile::tempdir().unwrap();
    init_noirpass_store(store.path(), &cert);
    remove_default_collection(store.path(), true);

    let mut daemon = spawn_daemon(
        &address,
        gnupg.path(),
        store.path(),
        "0",
        Some(fake_gpg.path()),
    );
    let status = wait_for_startup_exit(&mut daemon);
    dbus.kill().expect("kill private dbus-daemon");
    let _ = dbus.wait();

    assert!(
        !status.success(),
        "daemon must reject dangling default alias"
    );
    let persisted = Store::open_existing(store.path()).unwrap();
    assert!(persisted.get_collection("default").is_err());
    assert_eq!(
        persisted.read_alias("default").unwrap().as_deref(),
        Some("default")
    );
    let report = persisted.check_integrity().unwrap();
    assert_eq!(
        report.corrupt_aliases,
        vec![("default".to_string(), "default".to_string())]
    );
}

#[test]
fn daemon_rejects_missing_default_collection_with_item_owner() {
    let (gnupg, cert, fake_gpg) = startup_test_material();
    let (mut dbus, address) = spawn_dbus_daemon();
    let store = tempfile::tempdir().unwrap();
    init_noirpass_store(store.path(), &cert);

    let setup = Store::open_existing(store.path()).unwrap();
    let item = setup
        .create_or_replace_item(
            "default",
            "missing-owner",
            HashMap::new(),
            "text/plain",
            b"valid-ciphertext",
            false,
        )
        .unwrap()
        .0;
    drop(setup);
    remove_default_collection(store.path(), false);

    let mut daemon = spawn_daemon(
        &address,
        gnupg.path(),
        store.path(),
        "0",
        Some(fake_gpg.path()),
    );
    let status = wait_for_startup_exit(&mut daemon);
    dbus.kill().expect("kill private dbus-daemon");
    let _ = dbus.wait();

    assert!(
        !status.success(),
        "daemon must reject item with missing owner"
    );
    let persisted = Store::open_existing(store.path()).unwrap();
    assert!(persisted.get_collection("default").is_err());
    assert_eq!(persisted.get_item(&item.id).unwrap().collection, "default");
    assert_eq!(
        persisted.read_secret_file(&item.id).unwrap(),
        b"valid-ciphertext"
    );
    let report = persisted.check_integrity().unwrap();
    assert_eq!(report.items_with_invalid_collection.len(), 1);
    assert_eq!(report.items_with_invalid_collection[0].table_key, item.id);
    assert!(report.corrupt_items.is_empty());
    assert!(report.missing_secret_items.is_empty());
    assert!(report.ciphertext_mismatches.is_empty());
}

#[test]
fn daemon_bootstraps_default_collection_after_safe_admission() {
    let (gnupg, cert, fake_gpg) = startup_test_material();
    let (mut dbus, address) = spawn_dbus_daemon();
    let store = tempfile::tempdir().unwrap();
    init_noirpass_store(store.path(), &cert);
    remove_default_collection(store.path(), false);

    let mut daemon = spawn_daemon(
        &address,
        gnupg.path(),
        store.path(),
        "-1",
        Some(fake_gpg.path()),
    );
    wait_for_name(&address);
    sigterm(daemon.id());
    let status = wait_with_timeout(&mut daemon, Duration::from_secs(10));
    dbus.kill().expect("kill private dbus-daemon");
    let _ = dbus.wait();

    assert!(status.success(), "healthy store daemon failed: {status}");
    let persisted = Store::open_existing(store.path()).unwrap();
    assert!(persisted.get_collection("default").is_ok());
    assert_eq!(
        persisted.read_alias("default").unwrap().as_deref(),
        Some("default")
    );
    assert!(persisted.check_integrity().unwrap().is_healthy());
}

#[test]
fn daemon_rejects_store_with_missing_index() {
    let h = harness();
    let (mut dbus, address) = spawn_dbus_daemon();
    let store = tempfile::tempdir().unwrap();
    let cert = export_public_cert(&h.gnupg_home);
    init_noirpass_store(store.path(), &cert);
    std::fs::remove_file(store.path().join("index.redb")).unwrap();

    let mut daemon = spawn_daemon(
        &address,
        &h.gnupg_home,
        store.path(),
        "-1",
        Some(&h.fake_gpg_dir),
    );
    let status = wait_with_timeout(&mut daemon, Duration::from_secs(10));

    assert!(!status.success(), "daemon must reject broken store");
    dbus.kill().expect("kill private dbus-daemon");
    let _ = dbus.wait();
}

#[test]
fn daemon_rejects_recipient_without_matching_secret_key() {
    let h = harness();
    let other_gnupg = tempfile::tempdir().unwrap();
    setup_gnupg(other_gnupg.path());
    let other_cert = export_public_cert(other_gnupg.path());
    let (mut dbus, address) = spawn_dbus_daemon();
    let store = tempfile::tempdir().unwrap();
    init_noirpass_store(store.path(), &other_cert);

    let status_output = super::super::common::noirpass_command()
        .arg("--store-dir")
        .arg(store.path())
        .arg("status")
        .env("GNUPGHOME", &h.gnupg_home)
        .output()
        .expect("spawn noirpass status wrong recipient");
    assert!(
        !status_output.status.success(),
        "status must reject recipient that cannot be decrypted by this GNUPGHOME"
    );
    assert!(
        String::from_utf8_lossy(&status_output.stderr).contains("no available GnuPG secret key")
    );

    let mut daemon = spawn_daemon(
        &address,
        &h.gnupg_home,
        store.path(),
        "-1",
        Some(&h.fake_gpg_dir),
    );
    let status = wait_with_timeout(&mut daemon, Duration::from_secs(10));

    assert!(
        !status.success(),
        "daemon must reject recipient that cannot be decrypted by this GNUPGHOME"
    );
    dbus.kill().expect("kill private dbus-daemon");
    let _ = dbus.wait();
    let _ = std::process::Command::new("gpgconf")
        .arg("--homedir")
        .arg(other_gnupg.path())
        .args(["--kill", "gpg-agent"])
        .status();
}
