use super::pty::{run_tty, run_tty_eof};
use super::support::{CONFIG_TMP, ITEM_ID, RECOVERY, assert_intact, seeded_store, snapshot};

#[test]
fn first_confirmation_declined_preserves_store() {
    let store = seeded_store();
    let before = snapshot(store.path());

    let output = run_tty(store.path(), b"n\n");

    assert!(output.status.success());
    assert_intact(&before);
}

#[test]
fn first_accepted_second_declined_preserves_store() {
    let store = seeded_store();
    let before = snapshot(store.path());

    let output = run_tty(store.path(), b"y\nn\n");

    assert!(output.status.success());
    assert_intact(&before);
}

#[test]
fn both_confirmations_delete_known_store_state() {
    let store = seeded_store();

    let output = run_tty(store.path(), b"y\ny\n");

    assert!(output.status.success());
    assert!(!store.path().join("config.toml").exists());
    assert!(!store.path().join("keys/recipient.pgp").exists());
    assert!(
        !store
            .path()
            .join("keys/.noirpass-tmp-0123456789abcdef")
            .exists()
    );
    assert!(!store.path().join("keys").exists());
    assert!(!store.path().join("index.redb").exists());
    assert!(!store.path().join(format!("secrets/{ITEM_ID}.gpg")).exists());
    assert!(!store.path().join("secrets").join(RECOVERY).exists());
    assert!(!store.path().join(CONFIG_TMP).exists());
    assert!(store.path().join(".noirpass-lifecycle.lock").exists());
    assert!(store.path().join("secrets/keep.txt").exists());
    assert!(store.path().join("keep.txt").exists());
}

#[test]
fn eof_at_first_confirmation_preserves_store() {
    let store = seeded_store();
    let before = snapshot(store.path());

    let _output = run_tty_eof(store.path(), b"");

    assert_intact(&before);
}

#[test]
fn eof_at_second_confirmation_preserves_store() {
    let store = seeded_store();
    let before = snapshot(store.path());

    let _output = run_tty_eof(store.path(), b"y\n");

    assert_intact(&before);
}

#[test]
fn piped_confirmation_is_rejected_and_preserves_store() {
    let store = seeded_store();
    let before = snapshot(store.path());

    let output = super::support::run_piped(store.path(), &["deinit"], b"y\ny\n");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("interactive terminal"));
    assert_intact(&before);
}

#[test]
fn deinit_yes_option_is_rejected_and_preserves_store() {
    let store = seeded_store();
    let before = snapshot(store.path());

    let output = super::support::run_piped(store.path(), &["deinit", "--yes"], b"");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unexpected argument"));
    assert_intact(&before);
}
