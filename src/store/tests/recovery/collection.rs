use super::super::*;

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
