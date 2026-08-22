use std::fs;
use std::os::unix::fs::symlink;

use noirpass::store::Store;
use tempfile::tempdir;

use super::pty::run_tty;
use super::support::{ITEM_ID, run_init, seeded_store, write_recipient};

#[test]
fn deinit_then_init_new_recipient_preserves_unknown_files() {
    let store = seeded_store();

    let deinit_output = run_tty(store.path(), b"y\ny\n");
    assert!(deinit_output.status.success());
    assert!(!store.path().join("config.toml").exists());
    assert!(!store.path().join("index.redb").exists());
    assert_eq!(
        fs::read(store.path().join("secrets/keep.txt")).unwrap(),
        b"unrelated"
    );

    let recipient = write_recipient(store.path(), "recipient-b.pgp", "recipient-b");
    let init_output = run_init(store.path(), &recipient);

    assert!(
        init_output.status.success(),
        "init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&init_output.stdout),
        String::from_utf8_lossy(&init_output.stderr)
    );
    assert!(store.path().join("config.toml").exists());
    assert!(store.path().join("index.redb").exists());
    assert_eq!(
        fs::read(store.path().join("secrets/keep.txt")).unwrap(),
        b"unrelated"
    );
}

#[test]
fn unknown_secrets_directory_without_database_does_not_block_init() {
    let store = tempdir().unwrap();
    fs::create_dir(store.path().join("secrets")).unwrap();
    fs::write(store.path().join("secrets/keep.txt"), b"unrelated").unwrap();
    let recipient = write_recipient(store.path(), "recipient.pgp", "unknown-only");

    let output = run_init(store.path(), &recipient);

    assert!(output.status.success());
    assert_eq!(
        fs::read(store.path().join("secrets/keep.txt")).unwrap(),
        b"unrelated"
    );
    assert!(store.path().join("config.toml").exists());
    assert!(store.path().join("index.redb").exists());
}

#[test]
fn secrets_symlink_without_database_fails_closed() {
    let store = tempdir().unwrap();
    let outside = tempdir().unwrap();
    fs::write(outside.path().join("keep.txt"), b"outside").unwrap();
    symlink(outside.path(), store.path().join("secrets")).unwrap();
    let recipient = write_recipient(store.path(), "recipient.pgp", "secrets-symlink");

    let output = run_init(store.path(), &recipient);

    assert!(!output.status.success());
    assert!(!store.path().join("config.toml").exists());
    assert!(!store.path().join("index.redb").exists());
    assert!(!store.path().join("keys/recipient.pgp").exists());
    assert!(
        fs::symlink_metadata(store.path().join("secrets"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        fs::read(outside.path().join("keep.txt")).unwrap(),
        b"outside"
    );
}

#[test]
fn secrets_regular_file_without_database_fails_closed() {
    let store = tempdir().unwrap();
    fs::write(store.path().join("secrets"), b"not a directory").unwrap();
    let recipient = write_recipient(store.path(), "recipient.pgp", "secrets-file");

    let output = run_init(store.path(), &recipient);

    assert!(!output.status.success());
    assert!(!store.path().join("config.toml").exists());
    assert!(!store.path().join("index.redb").exists());
    assert_eq!(
        fs::read(store.path().join("secrets")).unwrap(),
        b"not a directory"
    );
}

#[test]
fn gpg_symlink_without_database_fails_closed_without_following_target() {
    let store = tempdir().unwrap();
    let outside = tempdir().unwrap();
    let outside_ciphertext = outside.path().join("old.gpg");
    fs::write(&outside_ciphertext, b"outside ciphertext").unwrap();
    fs::create_dir(store.path().join("secrets")).unwrap();
    symlink(&outside_ciphertext, store.path().join("secrets/old.gpg")).unwrap();
    let recipient = write_recipient(store.path(), "recipient.pgp", "gpg-symlink");

    let output = run_init(store.path(), &recipient);

    assert!(!output.status.success());
    assert!(!store.path().join("config.toml").exists());
    assert!(!store.path().join("index.redb").exists());
    assert!(
        fs::symlink_metadata(store.path().join("secrets/old.gpg"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read(outside_ciphertext).unwrap(), b"outside ciphertext");
}

#[test]
fn ambiguous_ciphertext_without_database_fails_closed() {
    let store = tempdir().unwrap();
    fs::create_dir(store.path().join("secrets")).unwrap();
    let ciphertext = store.path().join(format!("secrets/{ITEM_ID}.gpg"));
    fs::write(&ciphertext, b"old ciphertext").unwrap();
    let recipient = write_recipient(store.path(), "recipient.pgp", "ambiguous");

    let output = run_init(store.path(), &recipient);

    assert!(!output.status.success());
    assert!(!store.path().join("config.toml").exists());
    assert!(!store.path().join("index.redb").exists());
    assert_eq!(fs::read(ciphertext).unwrap(), b"old ciphertext");
}

#[test]
fn empty_secrets_directory_without_database_does_not_block_init() {
    let store = tempdir().unwrap();
    fs::create_dir(store.path().join("secrets")).unwrap();
    let recipient = write_recipient(store.path(), "recipient.pgp", "empty-secrets");

    let output = run_init(store.path(), &recipient);

    assert!(output.status.success());
    assert!(store.path().join("config.toml").exists());
    assert!(store.path().join("index.redb").exists());
}

#[test]
fn existing_database_without_config_rejects_init() {
    let store = tempdir().unwrap();
    drop(Store::open(store.path()).unwrap());
    let recipient = write_recipient(store.path(), "recipient.pgp", "existing-db");

    let output = run_init(store.path(), &recipient);

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("config.toml"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("noirpass deinit"));
    assert!(!store.path().join("config.toml").exists());
    assert!(store.path().join("index.redb").exists());
    assert!(!store.path().join("keys/recipient.pgp").exists());
}
