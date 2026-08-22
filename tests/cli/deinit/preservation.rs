use std::fs;
use std::os::unix::fs::symlink;

use tempfile::tempdir;

use super::pty::run_tty;
use super::support::{ITEM_ID, assert_intact, seeded_store, snapshot};

#[test]
fn symlinked_known_state_is_rejected_without_touching_target() {
    let store = seeded_store();
    let outside = tempdir().unwrap();
    let outside_secret = outside.path().join(format!("{ITEM_ID}.gpg"));
    fs::write(&outside_secret, b"outside").unwrap();
    fs::remove_dir_all(store.path().join("secrets")).unwrap();
    symlink(outside.path(), store.path().join("secrets")).unwrap();

    let output = run_tty(store.path(), b"y\ny\n");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("refusing to follow symlink"));
    assert!(store.path().join("config.toml").exists());
    assert!(store.path().join("keys/recipient.pgp").exists());
    assert!(store.path().join("index.redb").exists());
    assert!(outside_secret.exists());
}

#[test]
fn custom_store_directory_only_selected_store_is_deleted() {
    let selected = seeded_store();
    let other = seeded_store();
    let other_before = snapshot(other.path());

    let output = run_tty(selected.path(), b"y\ny\n");

    assert!(output.status.success());
    assert!(!selected.path().join("config.toml").exists());
    assert_intact(&other_before);
}
