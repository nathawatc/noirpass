use std::collections::HashSet;

use super::*;

#[test]
fn open_creates_dirs_with_0700() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("store");
    let store = Store::open(&root).unwrap();
    assert_eq!(mode(&root), 0o700);
    assert_eq!(mode(&store.secrets_dir), 0o700);
}

#[test]
fn collection_crud() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();

    let c = store
        .create_collection("Personal", Some("personal"))
        .unwrap();
    assert_eq!(c.label, "Personal");
    assert_eq!(store.get_collection(&c.id).unwrap(), c);
    assert_eq!(store.read_alias("personal").unwrap(), Some(c.id.clone()));

    let all = store.list_collections().unwrap();
    assert_eq!(all.len(), 1);

    let relabelled = store.set_collection_label(&c.id, "Work").unwrap();
    assert_eq!(relabelled.label, "Work");
    assert!(relabelled.modified >= c.modified);
    assert_eq!(store.get_collection(&c.id).unwrap().label, "Work");

    store.delete_collection(&c.id).unwrap();
    assert!(matches!(
        store.get_collection(&c.id),
        Err(Error::NotFound(_))
    ));
    assert!(matches!(
        store.delete_collection(&c.id),
        Err(Error::NotFound(_))
    ));
}

#[test]
fn ensure_default_is_idempotent() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let a = store.ensure_default().unwrap();
    let b = store.ensure_default().unwrap();
    assert_eq!(a, b);
    assert_eq!(a.id, DEFAULT_COLLECTION_ID);
    assert_eq!(
        store.read_alias("default").unwrap().as_deref(),
        Some(DEFAULT_COLLECTION_ID)
    );
    assert_eq!(store.list_collections().unwrap().len(), 1);
}

#[test]
fn alias_set_read_remove() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    assert_eq!(store.read_alias("missing").unwrap(), None);

    let collection = store.create_collection("c", None).unwrap();
    store.set_alias("session", Some(&collection.id)).unwrap();
    assert_eq!(
        store.read_alias("session").unwrap().as_deref(),
        Some(collection.id.as_str())
    );
    assert_eq!(
        store.list_aliases().unwrap(),
        vec![("session".to_string(), collection.id)]
    );

    store.set_alias("session", None).unwrap();
    assert_eq!(store.read_alias("session").unwrap(), None);
    assert!(store.list_aliases().unwrap().is_empty());
}

#[test]
fn delete_collection_cascades() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let c = store.create_collection("c", Some("c-alias")).unwrap();
    let other = store.create_collection("other", None).unwrap();

    let i1 = store
        .create_item(&c.id, "a", attrs(&[("k", "v")]), "text/plain", b"1")
        .unwrap();
    let i2 = store
        .create_item(&c.id, "b", attrs(&[("k", "w")]), "text/plain", b"2")
        .unwrap();
    let survivor = store
        .create_item(&other.id, "s", attrs(&[("k", "x")]), "text/plain", b"3")
        .unwrap();

    let p1 = store.secret_path(&i1.id).unwrap();
    let p2 = store.secret_path(&i2.id).unwrap();
    assert!(p1.exists() && p2.exists());

    let deleted = store.delete_collection(&c.id).unwrap();
    assert_eq!(
        deleted.item_ids.into_iter().collect::<HashSet<_>>(),
        HashSet::from([i1.id.clone(), i2.id.clone()])
    );
    assert_eq!(deleted.aliases, vec!["c-alias".to_string()]);

    // Items and secret files gone, alias gone.
    assert!(matches!(store.get_item(&i1.id), Err(Error::NotFound(_))));
    assert!(matches!(store.get_item(&i2.id), Err(Error::NotFound(_))));
    assert!(!p1.exists() && !p2.exists());
    assert_eq!(store.read_alias("c-alias").unwrap(), None);

    // The other collection and its item survive.
    assert!(store.get_collection(&other.id).is_ok());
    assert!(store.get_item(&survivor.id).is_ok());
}

#[test]
fn ensure_default_repairs_missing_alias() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let original = store.ensure_default().unwrap();
    store.set_alias("default", None).unwrap();

    let repaired = store.ensure_default().unwrap();

    assert_eq!(repaired, original);
    assert_eq!(
        store.read_alias("default").unwrap().as_deref(),
        Some(DEFAULT_COLLECTION_ID)
    );
}

#[test]
fn open_existing_refuses_missing_or_locked_store() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("missing");
    assert!(Store::open_existing(&missing).is_err());
    assert!(!missing.exists());

    let store = Store::open(tmp.path()).unwrap();
    let err = Store::open_existing(tmp.path()).unwrap_err();
    assert!(err.to_string().contains("store is in use"));
    drop(store);
    assert!(Store::open_existing(tmp.path()).is_ok());
}
