//! Exercise real mutation paths with instance-local filesystem failures.

use super::*;
use crate::store::files::FileOperation::{self, Remove, Rename, Sync};

fn inject(store: &Store, failures: &[(FileOperation, usize)]) {
    // Warm the derived index before each failure so rollback and poisoning also
    // exercise queries following an already indexed snapshot.
    store.search_items(&HashMap::new()).unwrap();
    *store.file_failures.lock().unwrap() = failures.iter().copied().collect();
}

fn assert_injected(store: &Store) {
    assert!(store.file_failures.lock().unwrap().is_empty());
}

#[test]
fn item_delete_filesystem_failures_preserve_commit_and_recovery_outcomes() {
    for (failures, committed, poisoned) in [
        (vec![(Rename, 1)], false, false),
        (vec![(Sync, 1)], false, false),
        (vec![(Sync, 1), (Rename, 1)], false, true),
        (vec![(Remove, 1)], true, true),
        (vec![(Sync, 2)], true, true),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let collection = store.ensure_default().unwrap();
        let item = store
            .create_item(&collection.id, "item", HashMap::new(), "text/plain", b"old")
            .unwrap();
        let survivor = store
            .create_item(
                &collection.id,
                "survivor",
                HashMap::new(),
                "text/plain",
                b"survivor",
            )
            .unwrap();
        fs::write(store.secrets_dir.join("keep.txt"), b"unrelated").unwrap();
        inject(&store, &failures);
        assert!(
            store
                .delete_item(&item.id)
                .unwrap_err()
                .to_string()
                .contains("injected")
        );
        assert_injected(&store);
        assert_eq!(store.is_poisoned(), poisoned, "{failures:?}");
        if poisoned {
            assert!(store.delete_item(&survivor.id).is_err());
        }
        drop(store);

        let store = Store::open_existing(tmp.path()).unwrap();
        store.recover_interrupted_operations().unwrap();
        if committed {
            assert!(matches!(store.get_item(&item.id), Err(Error::NotFound(_))));
            assert!(!store.secret_path(&item.id).unwrap().exists());
        } else {
            assert_eq!(store.get_item(&item.id).unwrap(), item);
            assert_eq!(store.read_secret_file(&item.id).unwrap(), b"old");
        }
        assert_eq!(
            store.read_item_secret(&survivor.id).unwrap(),
            (survivor, b"survivor".to_vec())
        );
        assert_eq!(
            fs::read(store.secrets_dir.join("keep.txt")).unwrap(),
            b"unrelated"
        );
        assert!(
            store.check_integrity().unwrap().is_healthy(),
            "{failures:?}"
        );
    }
}

#[test]
fn replacement_filesystem_failures_preserve_old_or_committed_ciphertext() {
    for (failures, committed, poisoned) in [
        (vec![(Rename, 1)], false, false),
        (vec![(Rename, 2)], false, false),
        (vec![(Rename, 2), (Rename, 1)], false, true),
        (vec![(Sync, 1)], false, false),
        (vec![(Sync, 2)], false, false),
        (vec![(Sync, 2), (Rename, 1)], false, true),
        (vec![(Remove, 1)], true, true),
        (vec![(Sync, 3)], true, true),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let collection = store.ensure_default().unwrap();
        let item = store
            .create_item(&collection.id, "item", HashMap::new(), "text/plain", b"old")
            .unwrap();
        inject(&store, &failures);
        assert!(
            store
                .update_item(&item.id, Some("updated"), None, None, Some(b"new"))
                .unwrap_err()
                .to_string()
                .contains("injected")
        );
        assert_injected(&store);
        assert_eq!(store.is_poisoned(), poisoned, "{failures:?}");
        drop(store);

        let store = Store::open_existing(tmp.path()).unwrap();
        store.recover_interrupted_operations().unwrap();
        let (metadata, ciphertext) = store.read_item_secret(&item.id).unwrap();
        if committed {
            assert_eq!(metadata.label, "updated");
            assert_eq!(ciphertext, b"new");
        } else {
            assert_eq!(metadata, item);
            assert_eq!(ciphertext, b"old");
        }
        assert!(
            store.check_integrity().unwrap().is_healthy(),
            "{failures:?}"
        );
    }
}

#[test]
fn collection_delete_filesystem_failures_restore_all_or_remove_all() {
    for (failures, committed, poisoned) in [
        (vec![(Rename, 2)], false, false),
        (vec![(Rename, 2), (Rename, 1)], false, true),
        (vec![(Sync, 1)], false, false),
        (vec![(Sync, 1), (Rename, 1)], false, true),
        (vec![(Remove, 2)], true, true),
        (vec![(Sync, 2)], true, true),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let collection = store
            .create_collection("delete", Some("fixture-alias"))
            .unwrap();
        let first = store
            .create_item(
                &collection.id,
                "first",
                HashMap::new(),
                "text/plain",
                b"first",
            )
            .unwrap();
        let second = store
            .create_item(
                &collection.id,
                "second",
                HashMap::new(),
                "text/plain",
                b"second",
            )
            .unwrap();
        inject(&store, &failures);
        assert!(
            store
                .delete_collection(&collection.id)
                .unwrap_err()
                .to_string()
                .contains("injected")
        );
        assert_injected(&store);
        assert_eq!(store.is_poisoned(), poisoned, "{failures:?}");
        drop(store);

        let store = Store::open_existing(tmp.path()).unwrap();
        store.recover_interrupted_operations().unwrap();
        for (item, ciphertext) in [(first, b"first".as_slice()), (second, b"second".as_slice())] {
            if committed {
                assert!(matches!(store.get_item(&item.id), Err(Error::NotFound(_))));
                assert!(!store.secret_path(&item.id).unwrap().exists());
            } else {
                assert_eq!(
                    store.read_item_secret(&item.id).unwrap(),
                    (item, ciphertext.to_vec())
                );
            }
        }
        assert_eq!(store.get_collection(&collection.id).is_err(), committed);
        assert_eq!(
            store.read_alias("fixture-alias").unwrap().is_none(),
            committed
        );
        assert!(
            store.check_integrity().unwrap().is_healthy(),
            "{failures:?}"
        );
    }
}
