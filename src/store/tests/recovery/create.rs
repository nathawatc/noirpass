use super::super::*;

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
