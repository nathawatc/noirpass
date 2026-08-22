use noirpass::store::Store;

use super::pty::run_tty;
use super::support::{assert_intact, seeded_store, snapshot};

#[test]
fn busy_store_deinit_preserves_state_before_temp_cleanup() {
    let store = seeded_store();
    let held_store = Store::open_existing(store.path()).unwrap();
    assert!(!store.path().join(".noirpass-lifecycle.lock").exists());
    let before = snapshot(store.path());

    let output = run_tty(store.path(), b"y\ny\n");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("store is in use"));
    assert!(!store.path().join(".noirpass-lifecycle.lock").exists());
    assert_intact(&before);
    drop(held_store);
}
