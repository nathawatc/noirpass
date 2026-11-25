use super::super::*;

#[test]
fn indeterminate_update_commit_keeps_artifacts_for_persisted_outcome() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let collection = store.create_collection("c", None).unwrap();
    let item = store
        .create_item(&collection.id, "item", HashMap::new(), "text/plain", b"old")
        .unwrap();
    let path = store.secret_path(&item.id).unwrap();
    let staged = store
        .stage_secret_file(&item.id, b"new", RecoveryKind::Update)
        .unwrap();
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
    let staged = store
        .stage_secret_file(&item.id, b"new", RecoveryKind::Update)
        .unwrap();
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
fn backup_recovery_refuses_to_overwrite_when_backup_digest_also_mismatches() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let collection = store.create_collection("c", None).unwrap();
    let item = store
        .create_item(&collection.id, "item", HashMap::new(), "text/plain", b"old")
        .unwrap();
    let canonical = store.secret_path(&item.id).unwrap();
    fs::write(&canonical, b"corrupt canonical").unwrap();
    let backup = store.secrets_dir.join(format!(
        ".noirpass-backup-{}-0000000000000001.gpg",
        item.id
    ));
    fs::write(&backup, b"corrupt backup").unwrap();

    let err = store.recover_interrupted_operations().unwrap_err();
    assert!(
        err.to_string()
            .contains("does not match committed metadata digest")
    );
    assert_eq!(fs::read(&canonical).unwrap(), b"corrupt canonical");
    assert_eq!(fs::read(&backup).unwrap(), b"corrupt backup");
}
