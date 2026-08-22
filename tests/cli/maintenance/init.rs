use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use noirpass::config::{Config, LifecycleLock, load_recipient};
use noirpass::gpg::parse_recipient_cert;
use noirpass::store::Store;

use crate::common::{
    add_encryption_subkey, export_public_cert, fake_gpg_dir, init_noirpass_store,
    init_noirpass_store_from_stdin, noirpass_command, setup_gnupg, sigterm, spawn_daemon,
    spawn_dbus_daemon, wait_for_name, wait_with_timeout,
};

fn child_has_open_path(child: &Child, path: &Path) -> bool {
    let Ok(entries) = fs::read_dir(format!("/proc/{}/fd", child.id())) else {
        return false;
    };
    entries
        .filter_map(Result::ok)
        .any(|entry| fs::read_link(entry.path()).is_ok_and(|target| target == path))
}

fn wait_for_children_to_open_lock(children: &mut [Child], lock_path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let mut all_open = true;
        for child in children.iter_mut() {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("init child exited before opening lifecycle lock: {status}");
            }
            all_open &= child_has_open_path(child, lock_path);
        }
        if all_open {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "init children did not reach lifecycle lock"
        );
        std::thread::yield_now();
    }
}

fn spawn_init(store: &Path, recipient: &Path) -> Child {
    noirpass_command()
        .arg("--store-dir")
        .arg(store)
        .args(["init", "--recipient"])
        .arg(recipient)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

#[test]
fn cli_serializes_concurrent_fresh_init_before_writing() {
    let first_gnupg = tempfile::tempdir().unwrap();
    setup_gnupg(first_gnupg.path());
    let first_cert = export_public_cert(first_gnupg.path());
    let second_gnupg = tempfile::tempdir().unwrap();
    setup_gnupg(second_gnupg.path());
    let second_cert = export_public_cert(second_gnupg.path());

    let recipients = tempfile::tempdir().unwrap();
    let first_recipient = recipients.path().join("first.asc");
    let second_recipient = recipients.path().join("second.asc");
    fs::write(&first_recipient, &first_cert).unwrap();
    fs::write(&second_recipient, &second_cert).unwrap();

    let store = tempfile::tempdir().unwrap();
    let parent_lock = LifecycleLock::acquire(store.path()).unwrap();
    let mut children = vec![
        spawn_init(store.path(), &first_recipient),
        spawn_init(store.path(), &second_recipient),
    ];
    let lock_path = store.path().join(".noirpass-lifecycle.lock");
    wait_for_children_to_open_lock(&mut children, &lock_path);

    assert!(!store.path().join("config.toml").exists());
    assert!(!store.path().join("keys/recipient.pgp").exists());
    assert!(!store.path().join("index.redb").exists());

    drop(parent_lock);
    let outputs = children
        .into_iter()
        .map(|child| child.wait_with_output().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        outputs
            .iter()
            .filter(|output| output.status.success())
            .count(),
        1
    );
    let rejected = outputs
        .iter()
        .find(|output| !output.status.success())
        .unwrap();
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains("different recipient"),
        "stderr: {}",
        String::from_utf8_lossy(&rejected.stderr)
    );

    let stored_cert = fs::read(store.path().join("keys/recipient.pgp")).unwrap();
    let stored_fingerprint = parse_recipient_cert(&stored_cert)
        .unwrap()
        .fingerprint()
        .to_hex();
    let first_fingerprint = parse_recipient_cert(&first_cert)
        .unwrap()
        .fingerprint()
        .to_hex();
    let second_fingerprint = parse_recipient_cert(&second_cert)
        .unwrap()
        .fingerprint()
        .to_hex();
    assert!(stored_fingerprint == first_fingerprint || stored_fingerprint == second_fingerprint);
    assert_eq!(
        Config::load(store.path()).unwrap().recipient_fingerprint,
        stored_fingerprint
    );
    assert_eq!(
        load_recipient(store.path()).unwrap().fingerprint,
        stored_fingerprint
    );

    let store = Store::open_existing(store.path()).unwrap();
    assert!(store.get_collection("default").is_ok());
    assert!(store.check_integrity().unwrap().is_healthy());
}

#[test]
fn cli_init_rejects_busy_existing_store_before_writing() {
    let gnupg = tempfile::tempdir().unwrap();
    setup_gnupg(gnupg.path());
    let initial_cert = export_public_cert(gnupg.path());
    let store = tempfile::tempdir().unwrap();
    init_noirpass_store(store.path(), &initial_cert);

    add_encryption_subkey(gnupg.path());
    let refreshed_cert = export_public_cert(gnupg.path());
    let recipient_path = store.path().join("recipient-refresh.asc");
    std::fs::write(&recipient_path, &refreshed_cert).unwrap();

    let held_store = Store::open_existing(store.path()).unwrap();
    let collection = held_store.ensure_default().unwrap();
    let item = held_store
        .create_or_replace_item(
            &collection.id,
            "busy init sentinel",
            HashMap::new(),
            "text/plain",
            b"ciphertext",
            false,
        )
        .unwrap()
        .0;
    let config_before = fs::read(store.path().join("config.toml")).unwrap();
    let recipient_before = fs::read(store.path().join("keys/recipient.pgp")).unwrap();
    let index_before = fs::read(store.path().join("index.redb")).unwrap();
    let ciphertext_path = store
        .path()
        .join("secrets")
        .join(format!("{}.gpg", item.id));
    let ciphertext_before = fs::read(&ciphertext_path).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .env_remove("NOIRPASS_STORE")
        .arg("--store-dir")
        .arg(store.path())
        .args(["init", "--recipient"])
        .arg(&recipient_path)
        .output()
        .expect("spawn noirpass init with busy store");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("store is in use"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(store.path().join("config.toml")).unwrap(),
        config_before
    );
    assert_eq!(
        fs::read(store.path().join("keys/recipient.pgp")).unwrap(),
        recipient_before
    );
    assert_eq!(
        fs::read(store.path().join("index.redb")).unwrap(),
        index_before
    );
    assert_eq!(fs::read(ciphertext_path).unwrap(), ciphertext_before);
}

#[test]
fn cli_init_refreshes_unlocked_existing_store() {
    let gnupg = tempfile::tempdir().unwrap();
    setup_gnupg(gnupg.path());
    let initial_cert = export_public_cert(gnupg.path());
    let store = tempfile::tempdir().unwrap();
    init_noirpass_store(store.path(), &initial_cert);
    let recipient_before = fs::read(store.path().join("keys/recipient.pgp")).unwrap();

    add_encryption_subkey(gnupg.path());
    let recipient_path = store.path().join("recipient-refresh.asc");
    fs::write(&recipient_path, export_public_cert(gnupg.path())).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .env_remove("NOIRPASS_STORE")
        .arg("--store-dir")
        .arg(store.path())
        .args(["init", "--recipient"])
        .arg(&recipient_path)
        .output()
        .expect("spawn noirpass init with unlocked store");

    assert!(
        output.status.success(),
        "init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_ne!(
        fs::read(store.path().join("keys/recipient.pgp")).unwrap(),
        recipient_before
    );
    assert!(Store::open_existing(store.path()).is_ok());
}

#[test]
fn cli_init_rejects_different_primary_without_writing() {
    let first_gnupg = tempfile::tempdir().unwrap();
    setup_gnupg(first_gnupg.path());
    let second_gnupg = tempfile::tempdir().unwrap();
    setup_gnupg(second_gnupg.path());
    let store = tempfile::tempdir().unwrap();
    init_noirpass_store(store.path(), &export_public_cert(first_gnupg.path()));
    let config_before = fs::read(store.path().join("config.toml")).unwrap();
    let recipient_before = fs::read(store.path().join("keys/recipient.pgp")).unwrap();
    let recipient_path = store.path().join("different-recipient.asc");
    fs::write(&recipient_path, export_public_cert(second_gnupg.path())).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .env_remove("NOIRPASS_STORE")
        .arg("--store-dir")
        .arg(store.path())
        .args(["init", "--recipient"])
        .arg(&recipient_path)
        .output()
        .expect("spawn noirpass init with different recipient");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("different recipient"));
    assert_eq!(
        fs::read(store.path().join("config.toml")).unwrap(),
        config_before
    );
    assert_eq!(
        fs::read(store.path().join("keys/recipient.pgp")).unwrap(),
        recipient_before
    );
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
    assert!(String::from_utf8_lossy(&live.stdout).contains("initialized: yes"));

    sigterm(daemon.id());
    let _ = wait_with_timeout(&mut daemon, Duration::from_secs(10));
    dbus.kill().expect("kill private dbus-daemon");
    let _ = dbus.wait();
}
