use std::io;

use redb::ReadableDatabase;

use super::*;

#[test]
fn replacement_restores_previous_ciphertext_when_commit_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let path = store.secret_path(id).unwrap();
    fs::write(&path, b"old").unwrap();
    let staged = store.stage_secret_file(id, b"new", "test").unwrap();

    let err = store
        .replace_then_commit(
            &path,
            &staged,
            || -> std::result::Result<(), PersistError> {
                Err(PersistError::Definite(Error::Config(
                    "injected commit failure".into(),
                )))
            },
        )
        .unwrap_err();

    assert!(err.to_string().contains("injected commit failure"));
    assert_eq!(fs::read(path).unwrap(), b"old");
    assert_eq!(
        store.check_integrity().unwrap().orphan_secret_files.len(),
        1
    );
}

#[test]
fn deletion_restores_ciphertext_when_commit_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let path = store.secret_path(id).unwrap();
    fs::write(&path, b"ciphertext").unwrap();

    let err = store
        .quarantine_then_commit(&path, || -> std::result::Result<(), PersistError> {
            Err(PersistError::Definite(Error::Config(
                "injected commit failure".into(),
            )))
        })
        .unwrap_err();

    assert!(err.to_string().contains("injected commit failure"));
    assert_eq!(fs::read(path).unwrap(), b"ciphertext");
    assert!(
        store
            .check_integrity()
            .unwrap()
            .recovery_secret_files
            .is_empty()
    );
}

#[test]
fn collection_ciphertexts_restore_when_commit_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let first = store
        .secret_path("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        .unwrap();
    let second = store
        .secret_path("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        .unwrap();
    fs::write(&first, b"first").unwrap();
    fs::write(&second, b"second").unwrap();

    let err = store
        .quarantine_many_then_commit(
            &[first.clone(), second.clone()],
            || -> std::result::Result<(), PersistError> {
                Err(PersistError::Definite(Error::Config(
                    "injected collection commit failure".into(),
                )))
            },
        )
        .unwrap_err();

    assert!(
        err.to_string()
            .contains("injected collection commit failure")
    );
    assert_eq!(fs::read(first).unwrap(), b"first");
    assert_eq!(fs::read(second).unwrap(), b"second");
    assert!(
        store
            .check_integrity()
            .unwrap()
            .recovery_secret_files
            .is_empty()
    );
}

#[test]
fn queued_writer_stops_after_store_is_poisoned() {
    let tmp = tempfile::tempdir().unwrap();
    let store = std::sync::Arc::new(Store::open(tmp.path()).unwrap());
    let active_guard = store.transaction_gate.write().unwrap();
    let active_txn = store.db.begin_write().unwrap();
    let passed_initial_check = std::sync::Arc::new(std::sync::Barrier::new(2));
    let queued_store = std::sync::Arc::clone(&store);
    let queued_barrier = std::sync::Arc::clone(&passed_initial_check);
    let queued_file = store.secrets_dir.join("queued.gpg");
    let queued_file_for_thread = queued_file.clone();

    let queued = std::thread::spawn(move || {
        let txn = queued_store.begin_write_checked_after_initial_check(|| {
            queued_barrier.wait();
        });
        let Ok((_mutation_guard, txn)) = txn else {
            return false;
        };
        fs::write(&queued_file_for_thread, b"mutated").unwrap();
        {
            let mut collections = txn.open_table(COLLECTIONS).unwrap();
            collections.insert("queued", b"mutated".as_slice()).unwrap();
        }
        txn.commit().unwrap();
        true
    });

    passed_initial_check.wait();
    store.poison();
    drop(active_txn);
    drop(active_guard);

    assert!(!queued.join().unwrap());
    let txn = store.db.begin_read().unwrap();
    let collections = txn.open_table(COLLECTIONS).unwrap();
    assert!(collections.get("queued").unwrap().is_none());
    assert!(!queued_file.exists());
}

#[test]
fn item_secret_reader_waits_for_update_rollback() {
    let tmp = tempfile::tempdir().unwrap();
    let store = std::sync::Arc::new(Store::open(tmp.path()).unwrap());
    let collection = store.create_collection("c", None).unwrap();
    let item = store
        .create_item(&collection.id, "item", HashMap::new(), "text/plain", b"old")
        .unwrap();
    let path = store.secret_path(&item.id).unwrap();
    let staged = store.stage_secret_file(&item.id, b"new", "update").unwrap();
    let write_guard = store.write_guard_checked().unwrap();
    let reader_store = std::sync::Arc::clone(&store);
    let reader_id = item.id.clone();
    let passed_initial_check = std::sync::Arc::new(std::sync::Barrier::new(2));
    let reader_barrier = std::sync::Arc::clone(&passed_initial_check);
    let (sender, receiver) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let result = reader_store.read_item_secret_after_initial_check(&reader_id, || {
            reader_barrier.wait();
        });
        sender.send(result).unwrap();
    });

    passed_initial_check.wait();
    let err = store
        .replace_then_commit(&path, &staged, || {
            assert!(matches!(
                receiver.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Empty)
            ));
            Err::<(), _>(PersistError::Definite(Error::Config(
                "injected metadata failure".into(),
            )))
        })
        .unwrap_err();

    assert!(err.to_string().contains("injected metadata failure"));
    assert_eq!(fs::read(&path).unwrap(), b"old");
    assert!(matches!(
        receiver.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    drop(write_guard);

    let (metadata, ciphertext) = receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .unwrap()
        .unwrap();
    reader.join().unwrap();
    assert_eq!(metadata, item);
    assert_eq!(ciphertext, b"old");
}

#[test]
fn raw_ciphertext_reader_waits_for_rollback() {
    let tmp = tempfile::tempdir().unwrap();
    let store = std::sync::Arc::new(Store::open(tmp.path()).unwrap());
    let collection = store.create_collection("c", None).unwrap();
    let item = store
        .create_item(&collection.id, "item", HashMap::new(), "text/plain", b"old")
        .unwrap();
    let path = store.secret_path(&item.id).unwrap();
    let write_guard = store.write_guard_checked().unwrap();
    let reader_store = std::sync::Arc::clone(&store);
    let reader_id = item.id.clone();
    let passed_initial_check = std::sync::Arc::new(std::sync::Barrier::new(2));
    let reader_barrier = std::sync::Arc::clone(&passed_initial_check);
    let (sender, receiver) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let result = reader_store.read_secret_file_after_initial_check(&reader_id, || {
            reader_barrier.wait();
        });
        sender.send(result).unwrap();
    });

    passed_initial_check.wait();
    fs::write(&path, b"uncommitted").unwrap();
    assert!(matches!(
        receiver.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    fs::write(&path, b"old").unwrap();
    drop(write_guard);

    assert_eq!(
        receiver
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap()
            .unwrap(),
        b"old"
    );
    reader.join().unwrap();
}

#[test]
fn create_install_sync_failure_removes_unindexed_ciphertext() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let path = store.secrets_dir.join("unindexed.gpg");
    let marker = store.secrets_dir.join("create-marker.gpg");
    fs::write(&path, b"ciphertext").unwrap();
    fs::write(&marker, b"ciphertext").unwrap();
    let sync_calls = std::cell::Cell::new(0);

    let err = store
        .finish_create_install(
            &path,
            &marker,
            || {
                sync_calls.set(sync_calls.get() + 1);
                if sync_calls.get() == 1 {
                    Err(Error::Io(io::Error::other("injected install sync failure")))
                } else {
                    Ok(())
                }
            },
            |candidate| fs::remove_file(candidate),
        )
        .unwrap_err();

    assert!(err.to_string().contains("injected install sync failure"));
    assert_eq!(sync_calls.get(), 3);
    assert!(!path.exists());
    assert!(!marker.exists());
    assert!(!store.is_poisoned());
}

#[test]
fn create_install_cleanup_failure_poisons_store() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let path = store.secrets_dir.join("unindexed.gpg");
    let marker = store.secrets_dir.join("create-marker.gpg");
    fs::write(&path, b"ciphertext").unwrap();
    fs::write(&marker, b"ciphertext").unwrap();

    let err = store
        .finish_create_install(
            &path,
            &marker,
            || Err(Error::Io(io::Error::other("injected install sync failure"))),
            |_| Err(io::Error::other("injected cleanup failure")),
        )
        .unwrap_err();

    assert!(err.to_string().contains("injected cleanup failure"));
    assert!(path.exists());
    assert!(marker.exists());
    assert!(store.is_poisoned());
    assert!(store.create_collection("blocked", None).is_err());
}

#[test]
fn create_install_cleanup_sync_failure_poisons_store() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let path = store.secrets_dir.join("unindexed.gpg");
    let marker = store.secrets_dir.join("create-marker.gpg");
    fs::write(&path, b"ciphertext").unwrap();
    fs::write(&marker, b"ciphertext").unwrap();

    let err = store
        .finish_create_install(
            &path,
            &marker,
            || {
                Err(Error::Io(io::Error::other(
                    "injected directory sync failure",
                )))
            },
            |candidate| fs::remove_file(candidate),
        )
        .unwrap_err();

    assert!(err.to_string().contains("cleanup directory sync failed"));
    assert!(!path.exists());
    assert!(marker.exists());
    assert!(store.is_poisoned());
    assert!(store.create_collection("blocked", None).is_err());
}

#[test]
fn create_install_marker_cleanup_failure_poisons_store() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let path = store.secrets_dir.join("unindexed.gpg");
    let marker = store.secrets_dir.join("create-marker.gpg");
    fs::write(&path, b"ciphertext").unwrap();
    fs::write(&marker, b"ciphertext").unwrap();
    let sync_calls = std::cell::Cell::new(0);
    let marker_removal_attempted = std::cell::Cell::new(false);

    let err = store
        .finish_create_install(
            &path,
            &marker,
            || {
                let call = sync_calls.get();
                sync_calls.set(call + 1);
                match call {
                    0 => Err(Error::Io(io::Error::other("injected install sync failure"))),
                    1 => Ok(()),
                    _ => panic!("unexpected sync call"),
                }
            },
            |candidate| {
                if candidate == path.as_path() {
                    fs::remove_file(candidate)
                } else if candidate == marker.as_path() {
                    marker_removal_attempted.set(true);
                    Err(io::Error::other("injected marker cleanup failure"))
                } else {
                    Err(io::Error::other("unexpected cleanup path"))
                }
            },
        )
        .unwrap_err();

    assert!(err.to_string().contains("marker cleanup failed"));
    assert!(err.to_string().contains("injected marker cleanup failure"));
    assert_eq!(sync_calls.get(), 2);
    assert!(marker_removal_attempted.get());
    assert!(!path.exists());
    assert!(marker.exists());
    assert!(store.is_poisoned());
    assert!(store.create_collection("blocked", None).is_err());
}

#[test]
fn create_install_final_marker_sync_failure_poisons_store() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let path = store.secrets_dir.join("unindexed.gpg");
    let marker = store.secrets_dir.join("create-marker.gpg");
    fs::write(&path, b"ciphertext").unwrap();
    fs::write(&marker, b"ciphertext").unwrap();
    let sync_calls = std::cell::Cell::new(0);
    let remove_calls = std::cell::Cell::new(0);

    let err = store
        .finish_create_install(
            &path,
            &marker,
            || {
                let call = sync_calls.get();
                sync_calls.set(call + 1);
                match call {
                    0 => Err(Error::Io(io::Error::other("injected install sync failure"))),
                    1 => Ok(()),
                    2 => Err(Error::Io(io::Error::other(
                        "injected final directory sync failure",
                    ))),
                    _ => panic!("unexpected sync call"),
                }
            },
            |candidate| {
                remove_calls.set(remove_calls.get() + 1);
                fs::remove_file(candidate)
            },
        )
        .unwrap_err();

    assert!(
        err.to_string()
            .contains("marker was removed, but directory sync failed")
    );
    assert!(
        err.to_string()
            .contains("injected final directory sync failure")
    );
    assert_eq!(sync_calls.get(), 3);
    assert_eq!(remove_calls.get(), 2);
    assert!(!path.exists());
    assert!(!marker.exists());
    assert!(store.is_poisoned());
    assert!(store.create_collection("blocked", None).is_err());
}
