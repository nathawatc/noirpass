use super::super::*;

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
