//! CLI maintenance and store-boundary integration tests.

use std::collections::HashMap;
use std::process::Command;
use std::time::Duration;

use noirpass::store::{ItemMeta, Store};
use redb::{Database, TableDefinition};

use super::common::{
    export_public_cert, fake_gpg_dir, init_noirpass_store, init_noirpass_store_from_stdin,
    setup_gnupg, sigterm, spawn_daemon, spawn_dbus_daemon, wait_for_name, wait_with_timeout,
};

#[test]
fn cli_lists_deletes_and_repairs_stale_items() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let collection = store.ensure_default().unwrap();
    let present = store
        .create_item(
            &collection.id,
            "present secret",
            HashMap::from([("service".to_string(), "present".to_string())]),
            "text/plain",
            b"ciphertext",
        )
        .unwrap();
    let missing = store
        .create_item(
            &collection.id,
            "missing secret",
            HashMap::from([("service".to_string(), "missing".to_string())]),
            "text/plain",
            b"ciphertext",
        )
        .unwrap();
    std::fs::remove_file(
        dir.path()
            .join("secrets")
            .join(format!("{}.gpg", missing.id)),
    )
    .unwrap();
    drop(store);

    let listed = Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .env_remove("NOIRPASS_STORE")
        .arg("--store-dir")
        .arg(dir.path())
        .arg("list")
        .output()
        .expect("spawn noirpass list");
    assert!(
        listed.status.success(),
        "list failed: stdout={} stderr={}",
        String::from_utf8_lossy(&listed.stdout),
        String::from_utf8_lossy(&listed.stderr)
    );
    let stdout = String::from_utf8_lossy(&listed.stdout);
    assert!(stdout.contains(&present.id));
    assert!(stdout.contains(&missing.id));
    assert!(stdout.contains("ciphertext: missing"));

    let checked = Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .env_remove("NOIRPASS_STORE")
        .arg("--store-dir")
        .arg(dir.path())
        .args(["check", "--yes"])
        .output()
        .expect("spawn noirpass check");
    assert!(
        checked.status.success(),
        "check failed: stdout={} stderr={}",
        String::from_utf8_lossy(&checked.stdout),
        String::from_utf8_lossy(&checked.stderr)
    );
    assert!(String::from_utf8_lossy(&checked.stdout).contains("store health: repaired"));

    let store = Store::open_existing(dir.path()).unwrap();
    assert!(store.get_item(&present.id).is_ok());
    assert!(store.get_item(&missing.id).is_err());
    drop(store);

    let deleted = Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .env_remove("NOIRPASS_STORE")
        .arg("--store-dir")
        .arg(dir.path())
        .arg("delete")
        .arg(&present.id)
        .arg("--yes")
        .output()
        .expect("spawn noirpass delete");
    assert!(
        deleted.status.success(),
        "delete failed: stdout={} stderr={}",
        String::from_utf8_lossy(&deleted.stdout),
        String::from_utf8_lossy(&deleted.stderr)
    );
    assert!(String::from_utf8_lossy(&deleted.stdout).contains(&present.id));

    let store = Store::open_existing(dir.path()).unwrap();
    assert!(store.search_items(&HashMap::new()).unwrap().is_empty());
    assert!(store.check_integrity().unwrap().is_healthy());
}

#[test]
fn cli_rejects_mismatched_item_id_without_deleting_valid_item() {
    const ITEMS: TableDefinition<&str, &[u8]> = TableDefinition::new("items");
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let collection = store.ensure_default().unwrap();
    let valid_b = store
        .create_item(
            &collection.id,
            "valid-b",
            HashMap::new(),
            "text/plain",
            b"ciphertext-b",
        )
        .unwrap();
    let key_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let corrupt = ItemMeta {
        label: "corrupt-a".to_string(),
        ..valid_b.clone()
    };
    drop(store);
    let db = Database::open(dir.path().join("index.redb")).unwrap();
    let txn = db.begin_write().unwrap();
    {
        let mut items = txn.open_table(ITEMS).unwrap();
        let bytes = serde_json::to_vec(&corrupt).unwrap();
        items.insert(key_a, bytes.as_slice()).unwrap();
    }
    txn.commit().unwrap();
    drop(db);

    let listed = Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .env_remove("NOIRPASS_STORE")
        .arg("--store-dir")
        .arg(dir.path())
        .arg("list")
        .output()
        .expect("spawn noirpass list");
    assert!(
        !listed.status.success(),
        "list must reject mismatched item ids"
    );

    let deleted = Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .env_remove("NOIRPASS_STORE")
        .arg("--store-dir")
        .arg(dir.path())
        .arg("delete")
        .arg(key_a)
        .arg("--yes")
        .output()
        .expect("spawn noirpass delete");

    assert!(!deleted.status.success());
    let store = Store::open_existing(dir.path()).unwrap();
    assert_eq!(store.get_item(&valid_b.id).unwrap(), valid_b);
    assert_eq!(
        store.read_secret_file(&valid_b.id).unwrap(),
        b"ciphertext-b"
    );
    assert_eq!(store.check_integrity().unwrap().corrupt_items.len(), 1);
}

#[test]
fn cli_check_repairs_noncanonical_item_key() {
    const ITEMS: TableDefinition<&str, &[u8]> = TableDefinition::new("items");
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let collection = store.ensure_default().unwrap();
    let metadata = ItemMeta {
        id: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        collection: collection.id,
        label: "bad-key".to_string(),
        attributes: HashMap::new(),
        content_type: "text/plain".to_string(),
        ciphertext_sha256: None,
        created: 1,
        modified: 1,
    };
    drop(store);
    let db = Database::open(dir.path().join("index.redb")).unwrap();
    let txn = db.begin_write().unwrap();
    {
        let mut items = txn.open_table(ITEMS).unwrap();
        let bytes = serde_json::to_vec(&metadata).unwrap();
        items.insert("bad-key", bytes.as_slice()).unwrap();
    }
    txn.commit().unwrap();
    drop(db);

    let checked = Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .env_remove("NOIRPASS_STORE")
        .arg("--store-dir")
        .arg(dir.path())
        .args(["check", "--yes"])
        .output()
        .expect("spawn noirpass check");

    assert!(
        checked.status.success(),
        "check failed: stdout={} stderr={}",
        String::from_utf8_lossy(&checked.stdout),
        String::from_utf8_lossy(&checked.stderr)
    );
    let store = Store::open_existing(dir.path()).unwrap();
    assert!(store.check_integrity().unwrap().is_healthy());
}

#[test]
fn cli_check_recovers_quarantined_ciphertext_before_repair() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let collection = store.ensure_default().unwrap();
    let item = store
        .create_item(
            &collection.id,
            "recoverable",
            HashMap::new(),
            "text/plain",
            b"recoverable-ciphertext",
        )
        .unwrap();
    let canonical = dir.path().join("secrets").join(format!("{}.gpg", item.id));
    let quarantine = dir.path().join("secrets").join(format!(
        ".noirpass-quarantine-{}-0000000000000001.gpg",
        item.id
    ));
    std::fs::rename(&canonical, &quarantine).unwrap();
    drop(store);

    let checked = Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .env_remove("NOIRPASS_STORE")
        .arg("--store-dir")
        .arg(dir.path())
        .args(["check", "--yes"])
        .output()
        .expect("spawn noirpass check");

    assert!(
        checked.status.success(),
        "check failed: stdout={} stderr={}",
        String::from_utf8_lossy(&checked.stdout),
        String::from_utf8_lossy(&checked.stderr)
    );
    let store = Store::open_existing(dir.path()).unwrap();
    assert_eq!(store.get_item(&item.id).unwrap(), item);
    assert_eq!(
        store.read_secret_file(&item.id).unwrap(),
        b"recoverable-ciphertext"
    );
    assert!(!quarantine.exists());
    assert!(store.check_integrity().unwrap().is_healthy());
}

#[test]
fn cli_init_rejects_store_with_missing_index() {
    let gnupg = tempfile::tempdir().unwrap();
    setup_gnupg(gnupg.path());
    let store = tempfile::tempdir().unwrap();
    let cert = export_public_cert(gnupg.path());
    init_noirpass_store(store.path(), &cert);
    let config = store.path().join("config.toml");
    let stored_recipient = store.path().join("keys/recipient.pgp");
    let config_before = std::fs::read(&config).unwrap();
    let stored_recipient_before = std::fs::read(&stored_recipient).unwrap();
    let ciphertext = store.path().join("secrets/existing.gpg");
    std::fs::write(&ciphertext, b"ciphertext").unwrap();
    std::fs::remove_file(store.path().join("index.redb")).unwrap();
    let recipient_path = store.path().join("recipient.asc");
    std::fs::write(&recipient_path, &cert).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .env_remove("NOIRPASS_STORE")
        .arg("--store-dir")
        .arg(store.path())
        .arg("init")
        .arg("--recipient")
        .arg(&recipient_path)
        .output()
        .expect("spawn noirpass init with missing index");

    assert!(
        !output.status.success(),
        "init must reject missing index: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("already initialized"), "stderr: {stderr}");
    assert!(stderr.contains("index.redb"), "stderr: {stderr}");
    assert!(!store.path().join("index.redb").exists());
    assert_eq!(std::fs::read(config).unwrap(), config_before);
    assert_eq!(
        std::fs::read(stored_recipient).unwrap(),
        stored_recipient_before
    );
    assert_eq!(std::fs::read(ciphertext).unwrap(), b"ciphertext");
}

#[test]
fn cli_init_invalid_recipient_does_not_create_store() {
    let store = tempfile::tempdir().unwrap();
    let recipient_path = store.path().join("not-openpgp.asc");
    std::fs::write(&recipient_path, b"not openpgp").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .env_remove("NOIRPASS_STORE")
        .arg("--store-dir")
        .arg(store.path())
        .arg("init")
        .arg("--recipient")
        .arg(&recipient_path)
        .output()
        .expect("spawn noirpass init invalid recipient");

    assert!(!output.status.success(), "init must reject invalid cert");
    assert!(
        !store.path().join("index.redb").exists(),
        "invalid init must not create index"
    );
    assert!(
        !store.path().join("secrets").exists(),
        "invalid init must not create secrets dir"
    );
}

#[test]
fn cli_init_stdin_and_status_exit_codes() {
    let gnupg = tempfile::tempdir().unwrap();
    setup_gnupg(gnupg.path());
    let cert = export_public_cert(gnupg.path());
    let store = tempfile::tempdir().unwrap();

    let uninitialized = Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .env_remove("NOIRPASS_STORE")
        .arg("--store-dir")
        .arg(store.path())
        .arg("status")
        .output()
        .expect("spawn noirpass status uninitialized");
    assert!(!uninitialized.status.success());
    assert!(
        String::from_utf8_lossy(&uninitialized.stderr).contains("run noirpass init --recipient")
    );

    init_noirpass_store_from_stdin(store.path(), &cert);

    let usable = Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .env_remove("NOIRPASS_STORE")
        .arg("--store-dir")
        .arg(store.path())
        .arg("status")
        .env("GNUPGHOME", gnupg.path())
        .output()
        .expect("spawn noirpass status initialized");
    assert!(
        usable.status.success(),
        "status failed: stdout={} stderr={}",
        String::from_utf8_lossy(&usable.stdout),
        String::from_utf8_lossy(&usable.stderr)
    );
    let stdout = String::from_utf8_lossy(&usable.stdout);
    assert!(stdout.contains("initialized: yes"));
    assert!(stdout.contains("fingerprint matches: yes"));
    assert!(stdout.contains("cert has encryption-capable key: yes"));

    let (fake_gpg_tmp, _fake_gpg_log) = fake_gpg_dir();
    let (mut dbus, address) = spawn_dbus_daemon();
    let mut daemon = spawn_daemon(
        &address,
        gnupg.path(),
        store.path(),
        "-1",
        Some(fake_gpg_tmp.path()),
    );
    wait_for_name(&address);

    let live = Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .env_remove("NOIRPASS_STORE")
        .arg("--store-dir")
        .arg(store.path())
        .arg("status")
        .env("GNUPGHOME", gnupg.path())
        .output()
        .expect("spawn noirpass status with running daemon");
    assert!(
        live.status.success(),
        "status with running daemon failed: stdout={} stderr={}",
        String::from_utf8_lossy(&live.stdout),
        String::from_utf8_lossy(&live.stderr)
    );

    sigterm(daemon.id());
    let _ = wait_with_timeout(&mut daemon, Duration::from_secs(10));
    dbus.kill().expect("kill private dbus-daemon");
    let _ = dbus.wait();
}
