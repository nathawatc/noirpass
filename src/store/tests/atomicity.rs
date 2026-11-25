use std::io;

use redb::{ReadableDatabase, ReadableTable};

use super::*;

#[test]
fn store_creation_syncs_pinned_root_after_database_commit_and_propagates_failure() {
    let tmp = tempfile::tempdir().unwrap();
    let selected = tmp.path().join("selected");
    fs::create_dir(&selected).unwrap();
    let root = Directory::open(&selected).unwrap();
    let moved = tmp.path().join("moved");
    fs::rename(&selected, &moved).unwrap();
    fs::create_dir(&selected).unwrap();
    let err = Store::open_in_with_sync(&selected, &root, |db| {
        assert!(moved.join("secrets").is_dir());
        let txn = db.begin_read().unwrap();
        txn.open_table(COLLECTIONS).unwrap();
        txn.open_table(ITEMS).unwrap();
        txn.open_table(ALIASES).unwrap();
        assert_eq!(fs::read_dir(&selected).unwrap().count(), 0);
        Err(io::Error::other("injected root sync failure"))
    })
    .unwrap_err();
    assert!(err.to_string().contains("injected root sync failure"));
    let store = Store::open_in(&selected, &root).unwrap();
    store.ensure_default().unwrap();
    assert!(store.check_integrity().unwrap().is_healthy());
    assert_eq!(fs::read_dir(selected).unwrap().count(), 0);
}

#[test]
fn replacement_restores_previous_ciphertext_when_commit_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let path = store.secret_path(id).unwrap();
    fs::write(&path, b"old").unwrap();
    let staged = store
        .stage_secret_file(id, b"new", RecoveryKind::Update)
        .unwrap();

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
    assert_eq!(
        store.check_integrity().unwrap().recovery_secret_files.len(),
        0
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
    assert_eq!(
        store.check_integrity().unwrap().recovery_secret_files.len(),
        0
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
    let staged = store
        .stage_secret_file(&item.id, b"new", RecoveryKind::Update)
        .unwrap();
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
fn create_persist_ciphertext_cleanup_failure_poisons_store() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let path = store.secret_path(id).unwrap();
    let marker = store.recovery_path(RecoveryKind::Create, id);
    fs::create_dir(&path).unwrap();
    fs::write(&marker, b"ciphertext").unwrap();

    let err = store
        .finish_create_persist(
            id,
            &marker,
            Err(PersistError::Definite(Error::Config(
                "injected metadata failure".into(),
            ))),
        )
        .unwrap_err();

    let message = err.to_string();
    assert!(
        message.contains("item metadata write failed: config error: injected metadata failure"),
        "{message}"
    );
    assert!(
        message.contains("unindexed ciphertext cleanup failed"),
        "{message}"
    );
    assert!(fs::symlink_metadata(&path).unwrap().is_dir());
    assert!(marker.exists());
    assert!(store.is_poisoned());
    assert!(store.create_collection("blocked", None).is_err());
}

#[test]
fn create_persist_cleanup_stays_in_pinned_directory_after_path_replacement() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let path = store.secret_path(id).unwrap();
    let marker = store.recovery_path(RecoveryKind::Create, id);
    fs::write(&path, b"ciphertext").unwrap();
    fs::write(&marker, b"ciphertext").unwrap();

    let real_secrets_dir = tmp.path().join("secrets-real");
    fs::rename(&store.secrets_dir, &real_secrets_dir).unwrap();
    std::os::unix::fs::symlink(&real_secrets_dir, &store.secrets_dir).unwrap();

    let err = store
        .finish_create_persist(
            id,
            &marker,
            Err(PersistError::Definite(Error::Config(
                "injected metadata failure".into(),
            ))),
        )
        .unwrap_err();

    // Replacing the pathname no longer injects a sync failure: rollback and sync use the pinned fd.
    assert_eq!(err.to_string(), "config error: injected metadata failure");
    assert!(!real_secrets_dir.join(path.file_name().unwrap()).exists());
    assert!(!real_secrets_dir.join(marker.file_name().unwrap()).exists());
    assert!(
        fs::symlink_metadata(&store.secrets_dir)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert!(!store.is_poisoned());
    assert!(store.create_collection("available", None).is_ok());
}

#[test]
fn create_persist_marker_cleanup_failure_poisons_store() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let path = store.secret_path(id).unwrap();
    let marker = store.recovery_path(RecoveryKind::Create, id);
    fs::write(&path, b"ciphertext").unwrap();
    fs::create_dir(&marker).unwrap();

    let err = store
        .finish_create_persist(
            id,
            &marker,
            Err(PersistError::Definite(Error::Config(
                "injected metadata failure".into(),
            ))),
        )
        .unwrap_err();

    let message = err.to_string();
    assert!(
        message.contains("item metadata write failed: config error: injected metadata failure"),
        "{message}"
    );
    assert!(
        message.contains("create marker cleanup failed"),
        "{message}"
    );
    assert!(!path.exists());
    assert!(fs::symlink_metadata(&marker).unwrap().is_dir());
    assert!(store.is_poisoned());
    assert!(store.create_collection("blocked", None).is_err());
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

#[test]
fn ciphertext_operations_stay_in_pinned_store_after_parent_replacement() {
    use std::os::unix::fs::symlink;
    let tmp = tempfile::tempdir().unwrap();
    let original = tmp.path().join("store");
    let moved = tmp.path().join("moved");
    let outside = tmp.path().join("outside");
    fs::create_dir_all(outside.join("secrets")).unwrap();
    let store = Store::open(&original).unwrap();
    let collection = store.ensure_default().unwrap();
    let item = store
        .create_item(
            &collection.id,
            "first",
            HashMap::new(),
            "text/plain",
            b"old",
        )
        .unwrap();
    let filename = format!("{}.gpg", item.id);
    fs::write(outside.join("secrets").join(&filename), b"unrelated").unwrap();
    fs::rename(&original, &moved).unwrap();
    symlink(&outside, &original).unwrap();
    assert_eq!(store.read_item_secret(&item.id).unwrap().1, b"old");
    store
        .update_item(&item.id, None, None, None, Some(b"new"))
        .unwrap();
    assert_eq!(store.read_item_secret(&item.id).unwrap().1, b"new");
    let added = store
        .create_item(
            &collection.id,
            "second",
            HashMap::new(),
            "text/plain",
            b"second",
        )
        .unwrap();
    store.recover_interrupted_operations().unwrap();
    assert!(store.check_integrity().unwrap().is_healthy());
    store.delete_item(&item.id).unwrap();
    store.delete_item(&added.id).unwrap();
    assert_eq!(
        fs::read(outside.join("secrets").join(filename)).unwrap(),
        b"unrelated"
    );
    assert_eq!(fs::read_dir(outside.join("secrets")).unwrap().count(), 1);
    assert_eq!(fs::read_dir(moved.join("secrets")).unwrap().count(), 0);
    assert!(Store::open_existing(&original).is_err());
}

#[tokio::test]
async fn poison_notification_handles_existing_and_future_waiters() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let waiting = store.wait_until_poisoned();
    tokio::pin!(waiting);
    assert!(
        std::future::poll_fn(|context| {
            assert!(waiting.as_mut().poll(context).is_pending());
            std::task::Poll::Ready(true)
        })
        .await
    );
    store.poison();
    tokio::time::timeout(std::time::Duration::from_secs(2), waiting)
        .await
        .unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        store.wait_until_poisoned(),
    )
    .await
    .unwrap();
}
