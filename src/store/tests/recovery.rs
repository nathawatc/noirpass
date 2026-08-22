use std::io;

use super::*;

#[test]
fn indeterminate_create_commit_keeps_ciphertext_and_poisons_store() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let collection = store.create_collection("c", None).unwrap();
    let item = store
        .create_item(
            &collection.id,
            "item",
            HashMap::new(),
            "text/plain",
            b"ciphertext",
        )
        .unwrap();

    let path = store.secret_path(&item.id).unwrap();
    let create_marker = store.recovery_path("create", &item.id);
    fs::hard_link(&path, &create_marker).unwrap();
    let err = store
        .finish_create_persist(
            &item.id,
            &create_marker,
            Err(PersistError::Indeterminate(Error::Config(
                "injected post-commit error".into(),
            ))),
        )
        .unwrap_err();

    assert!(err.to_string().contains("indeterminate"));
    assert!(store.is_poisoned());
    assert_eq!(fs::read(&path).unwrap(), b"ciphertext");
    assert!(create_marker.exists());
    assert!(store.get_item(&item.id).is_err());
    drop(store);
    let reopened = Store::open(tmp.path()).unwrap();
    reopened.recover_interrupted_operations().unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"ciphertext");
    assert!(!create_marker.exists());
    assert!(reopened.check_integrity().unwrap().is_healthy());
}

#[test]
fn indeterminate_create_without_metadata_is_removed_after_reopen() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let path = store.secret_path(id).unwrap();
    let create_marker = store.write_secret_file(id, b"ciphertext").unwrap();

    let err = store
        .finish_create_persist(
            id,
            &create_marker,
            Err(PersistError::Indeterminate(Error::Config(
                "injected pre-commit outcome".into(),
            ))),
        )
        .unwrap_err();

    assert!(err.to_string().contains("indeterminate"));
    assert!(store.is_poisoned());
    assert!(path.exists());
    assert!(create_marker.exists());
    drop(store);

    let reopened = Store::open(tmp.path()).unwrap();
    reopened.recover_interrupted_operations().unwrap();
    assert!(!path.exists());
    assert!(!create_marker.exists());
    assert!(reopened.check_integrity().unwrap().is_healthy());
}

#[test]
fn indeterminate_update_commit_keeps_artifacts_for_persisted_outcome() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let collection = store.create_collection("c", None).unwrap();
    let item = store
        .create_item(&collection.id, "item", HashMap::new(), "text/plain", b"old")
        .unwrap();
    let path = store.secret_path(&item.id).unwrap();
    let staged = store.stage_secret_file(&item.id, b"new", "update").unwrap();
    let mut updated = item.clone();
    updated.ciphertext_sha256 = Some(ciphertext_sha256(b"new"));
    let bytes = serde_json::to_vec(&updated).unwrap();
    let txn = store.db.begin_write().unwrap();

    let err = store
        .replace_then_commit(
            &path,
            &staged,
            || -> std::result::Result<(), PersistError> {
                {
                    let mut items = txn.open_table(ITEMS).unwrap();
                    items.insert(item.id.as_str(), bytes.as_slice()).unwrap();
                }
                txn.commit().unwrap();
                Err(PersistError::Indeterminate(Error::Config(
                    "injected post-commit error".into(),
                )))
            },
        )
        .unwrap_err();

    assert!(err.to_string().contains("indeterminate"));
    assert!(store.is_poisoned());
    assert_eq!(fs::read(&path).unwrap(), b"new");
    assert_eq!(
        store.check_integrity().unwrap().recovery_secret_files.len(),
        1
    );
    drop(store);
    let reopened = Store::open(tmp.path()).unwrap();
    reopened.recover_interrupted_operations().unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"new");
    assert!(reopened.check_integrity().unwrap().is_healthy());
}

#[test]
fn indeterminate_update_without_metadata_commit_restores_old_ciphertext() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let collection = store.create_collection("c", None).unwrap();
    let item = store
        .create_item(&collection.id, "item", HashMap::new(), "text/plain", b"old")
        .unwrap();
    let path = store.secret_path(&item.id).unwrap();
    let staged = store.stage_secret_file(&item.id, b"new", "update").unwrap();
    let txn = store.db.begin_write().unwrap();

    let err = store
        .replace_then_commit(&path, &staged, || {
            drop(txn);
            Err::<(), _>(PersistError::Indeterminate(Error::Config(
                "injected pre-commit outcome".into(),
            )))
        })
        .unwrap_err();

    assert!(err.to_string().contains("indeterminate"));
    assert!(store.is_poisoned());
    assert_eq!(fs::read(&path).unwrap(), b"new");
    drop(store);

    let reopened = Store::open(tmp.path()).unwrap();
    reopened.recover_interrupted_operations().unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"old");
    assert!(reopened.check_integrity().unwrap().is_healthy());
}

#[test]
fn indeterminate_delete_commit_keeps_quarantine_for_persisted_outcome() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let collection = store.create_collection("c", None).unwrap();
    let item = store
        .create_item(
            &collection.id,
            "item",
            HashMap::new(),
            "text/plain",
            b"ciphertext",
        )
        .unwrap();
    let path = store.secret_path(&item.id).unwrap();
    let txn = store.db.begin_write().unwrap();

    let err = store
        .quarantine_then_commit(&path, || -> std::result::Result<(), PersistError> {
            {
                let mut items = txn.open_table(ITEMS).unwrap();
                items.remove(item.id.as_str()).unwrap();
            }
            txn.commit().unwrap();
            Err(PersistError::Indeterminate(Error::Config(
                "injected post-commit error".into(),
            )))
        })
        .unwrap_err();

    assert!(err.to_string().contains("indeterminate"));
    assert!(store.is_poisoned());
    assert!(!path.exists());
    assert_eq!(
        store.check_integrity().unwrap().recovery_secret_files.len(),
        1
    );
    drop(store);
    let reopened = Store::open(tmp.path()).unwrap();
    reopened.recover_interrupted_operations().unwrap();
    assert!(!path.exists());
    assert!(reopened.check_integrity().unwrap().is_healthy());
}

#[test]
fn indeterminate_delete_without_metadata_commit_restores_ciphertext() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let collection = store.create_collection("c", None).unwrap();
    let item = store
        .create_item(
            &collection.id,
            "item",
            HashMap::new(),
            "text/plain",
            b"ciphertext",
        )
        .unwrap();
    let path = store.secret_path(&item.id).unwrap();
    let txn = store.db.begin_write().unwrap();

    let err = store
        .quarantine_then_commit(&path, || {
            drop(txn);
            Err::<(), _>(PersistError::Indeterminate(Error::Config(
                "injected pre-commit outcome".into(),
            )))
        })
        .unwrap_err();

    assert!(err.to_string().contains("indeterminate"));
    assert!(store.is_poisoned());
    assert!(!path.exists());
    drop(store);

    let reopened = Store::open(tmp.path()).unwrap();
    reopened.recover_interrupted_operations().unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"ciphertext");
    assert!(reopened.check_integrity().unwrap().is_healthy());
}

#[test]
fn indeterminate_collection_delete_without_commit_restores_all_ciphertexts() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let collection = store.create_collection("c", None).unwrap();
    let first = store
        .create_item(
            &collection.id,
            "first",
            HashMap::new(),
            "text/plain",
            b"first ciphertext",
        )
        .unwrap();
    let second = store
        .create_item(
            &collection.id,
            "second",
            HashMap::new(),
            "text/plain",
            b"second ciphertext",
        )
        .unwrap();
    let paths = [
        store.secret_path(&first.id).unwrap(),
        store.secret_path(&second.id).unwrap(),
    ];
    let txn = store.db.begin_write().unwrap();

    let err = store
        .quarantine_many_then_commit(&paths, || {
            drop(txn);
            Err::<(), _>(PersistError::Indeterminate(Error::Config(
                "injected pre-commit outcome".into(),
            )))
        })
        .unwrap_err();

    assert!(err.to_string().contains("indeterminate"));
    assert!(store.is_poisoned());
    assert!(paths.iter().all(|path| !path.exists()));
    drop(store);

    let reopened = Store::open(tmp.path()).unwrap();
    reopened.recover_interrupted_operations().unwrap();
    assert_eq!(fs::read(&paths[0]).unwrap(), b"first ciphertext");
    assert_eq!(fs::read(&paths[1]).unwrap(), b"second ciphertext");
    assert_eq!(reopened.get_collection(&collection.id).unwrap(), collection);
    assert_eq!(reopened.list_items(&collection.id).unwrap().len(), 2);
    assert!(reopened.check_integrity().unwrap().is_healthy());
}

#[test]
fn indeterminate_collection_commit_keeps_quarantines_for_persisted_outcome() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let collection = store.create_collection("c", None).unwrap();
    let item = store
        .create_item(
            &collection.id,
            "item",
            HashMap::new(),
            "text/plain",
            b"ciphertext",
        )
        .unwrap();
    let path = store.secret_path(&item.id).unwrap();
    let txn = store.db.begin_write().unwrap();

    let err = store
        .quarantine_many_then_commit(
            std::slice::from_ref(&path),
            || -> std::result::Result<(), PersistError> {
                {
                    let mut items = txn.open_table(ITEMS).unwrap();
                    items.remove(item.id.as_str()).unwrap();
                    let mut collections = txn.open_table(COLLECTIONS).unwrap();
                    collections.remove(collection.id.as_str()).unwrap();
                }
                txn.commit().unwrap();
                Err(PersistError::Indeterminate(Error::Config(
                    "injected post-commit error".into(),
                )))
            },
        )
        .unwrap_err();

    assert!(err.to_string().contains("indeterminate"));
    assert!(store.is_poisoned());
    assert!(!path.exists());
    assert_eq!(
        store.check_integrity().unwrap().recovery_secret_files.len(),
        1
    );
    drop(store);
    let reopened = Store::open(tmp.path()).unwrap();
    reopened.recover_interrupted_operations().unwrap();
    assert!(!path.exists());
    assert!(reopened.check_integrity().unwrap().is_healthy());
}

#[test]
fn cleanup_failure_keeps_recoverable_file_and_reports_path() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let file = ".noirpass-quarantine-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-1.gpg";
    let path = store.secrets_dir.join(file);
    fs::write(&path, b"ciphertext").unwrap();

    let err = Store::remove_recovery_file(&path, "metadata deletion committed", |_| {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "injected cleanup failure",
        ))
    })
    .unwrap_err();

    assert!(err.to_string().contains("metadata deletion committed"));
    assert!(err.to_string().contains(path.to_string_lossy().as_ref()));
    assert!(path.exists());
    assert_eq!(
        store.check_integrity().unwrap().recovery_secret_files,
        vec![file.to_string()]
    );
}

#[test]
fn recovery_symlink_is_rejected_without_reading_target() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let outside = tempfile::tempdir().unwrap();
    let outside_ciphertext = outside.path().join("ciphertext.gpg");
    fs::write(&outside_ciphertext, b"outside ciphertext").unwrap();
    let outside_before = fs::read(&outside_ciphertext).unwrap();
    let recovery = store
        .secrets_dir
        .join(".noirpass-backup-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-0123456789abcdef.gpg");
    std::os::unix::fs::symlink(&outside_ciphertext, &recovery).unwrap();

    assert!(store.recover_interrupted_operations().is_err());
    assert_eq!(fs::read(&outside_ciphertext).unwrap(), outside_before);
    assert!(
        fs::symlink_metadata(recovery)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn startup_recovery_rejects_symlinked_secrets_directory_without_reading_target() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let outside = tempfile::tempdir().unwrap();
    let outside_marker = outside.path().join("keep.txt");
    fs::write(&outside_marker, b"outside").unwrap();
    let secrets = store.secrets_dir.clone();
    fs::remove_dir(&secrets).unwrap();
    std::os::unix::fs::symlink(outside.path(), &secrets).unwrap();

    assert!(store.recover_interrupted_operations().is_err());
    assert_eq!(fs::read(&outside_marker).unwrap(), b"outside");
    assert!(
        fs::symlink_metadata(secrets)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn startup_recovery_removes_valid_staged_files() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let create = store.stage_secret_file(id, b"create", "create").unwrap();
    let update = store.stage_secret_file(id, b"update", "update").unwrap();

    let report = store.check_integrity().unwrap();
    assert_eq!(report.recovery_secret_files.len(), 2);
    assert!(!report.is_healthy());
    store.recover_interrupted_operations().unwrap();
    assert!(!create.exists());
    assert!(!update.exists());
    assert!(store.check_integrity().unwrap().is_healthy());
}

#[test]
fn startup_recovery_preserves_backup_without_metadata() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let backup = store
        .secrets_dir
        .join(".noirpass-backup-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-0000000000000001.gpg");
    fs::write(&backup, b"only-copy").unwrap();

    let err = store.recover_interrupted_operations().unwrap_err();

    assert!(err.to_string().contains("preserved for manual recovery"));
    assert_eq!(fs::read(backup).unwrap(), b"only-copy");
}

#[test]
fn startup_recovery_keeps_committed_update_and_finishes_committed_delete() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let collection = store.create_collection("c", None).unwrap();
    let updated = store
        .create_item(
            &collection.id,
            "updated",
            HashMap::new(),
            "text/plain",
            b"old",
        )
        .unwrap();
    store
        .update_item(&updated.id, None, None, None, Some(b"new"))
        .unwrap();
    let backup = store.secrets_dir.join(format!(
        ".noirpass-backup-{}-0000000000000001.gpg",
        updated.id
    ));
    fs::write(&backup, b"old").unwrap();

    let deleted = store
        .create_item(
            &collection.id,
            "deleted",
            HashMap::new(),
            "text/plain",
            b"deleted",
        )
        .unwrap();
    let deleted_path = store.secret_path(&deleted.id).unwrap();
    let quarantine = store.secrets_dir.join(format!(
        ".noirpass-quarantine-{}-0000000000000001.gpg",
        deleted.id
    ));
    fs::rename(&deleted_path, &quarantine).unwrap();
    store.delete_item_metadata(&deleted.id).unwrap();

    store.recover_interrupted_operations().unwrap();

    assert_eq!(store.read_secret_file(&updated.id).unwrap(), b"new");
    assert!(!backup.exists());
    assert!(!quarantine.exists());
    assert!(!deleted_path.exists());
}
