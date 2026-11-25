use super::*;

#[test]
fn every_item_mutation_updates_parent_in_the_same_transaction() {
    fn reset_modified(store: &Store, id: &str) -> CollectionMeta {
        let mut meta = store.get_collection(id).unwrap();
        meta.modified = 0;
        let txn = store.db.begin_write().unwrap();
        txn.open_table(COLLECTIONS)
            .unwrap()
            .insert(id, serde_json::to_vec(&meta).unwrap().as_slice())
            .unwrap();
        txn.commit().unwrap();
        meta
    }
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let collection = store.create_collection("parent", None).unwrap();
    let other = store.create_collection("unchanged", None).unwrap();
    let original = reset_modified(&store, &collection.id);
    let (item, replaced) = store
        .create_or_replace_item(
            &collection.id,
            "item",
            HashMap::new(),
            "text/plain",
            b"first",
            false,
        )
        .unwrap();
    assert!(!replaced);
    assert_eq!(
        store.get_collection(&collection.id).unwrap().modified,
        item.modified
    );
    reset_modified(&store, &collection.id);
    let (replacement, replaced) = store
        .create_or_replace_item(
            &collection.id,
            "replacement",
            HashMap::new(),
            "text/plain",
            b"second",
            true,
        )
        .unwrap();
    assert!(replaced);
    assert_eq!(replacement.id, item.id);
    assert_eq!(
        store.get_collection(&collection.id).unwrap().modified,
        replacement.modified
    );
    for (label, attributes, secret) in [
        (Some("updated"), None, None),
        (None, Some(attrs(&[("updated", "yes")])), None),
        (None, None, Some(b"third".as_slice())),
    ] {
        reset_modified(&store, &collection.id);
        let updated = store
            .update_item(&item.id, label, attributes, None, secret)
            .unwrap();
        assert_eq!(
            store.get_collection(&collection.id).unwrap().modified,
            updated.modified
        );
    }
    reset_modified(&store, &collection.id);
    // A rejected filesystem mutation must abort the parent timestamp alongside item metadata.
    let path = store.secret_path(&item.id).unwrap();
    fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(tmp.path().join("outside"), &path).unwrap();
    assert!(
        store
            .update_item(&item.id, Some("rejected"), None, None, Some(b"rejected"))
            .is_err()
    );
    assert_eq!(store.get_collection(&collection.id).unwrap(), original);
    assert_eq!(store.get_item(&item.id).unwrap().label, "updated");
    fs::remove_file(&path).unwrap();
    fs::write(path, b"third").unwrap();
    store.delete_item(&item.id).unwrap();
    let parent = store.get_collection(&collection.id).unwrap();
    assert!(parent.modified > 0);
    assert_eq!(parent.created, original.created);
    assert_eq!(parent.label, original.label);
    assert_eq!(store.get_collection(&other.id).unwrap(), other);
    drop(store);
    assert_eq!(
        Store::open_existing(tmp.path())
            .unwrap()
            .get_collection(&collection.id)
            .unwrap(),
        parent
    );
}

#[test]
fn deleting_item_with_corrupt_parent_preserves_parent_for_integrity_repair() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let collection = store.create_collection("parent", None).unwrap();
    let item = store
        .create_item(
            &collection.id,
            "item",
            HashMap::new(),
            "text/plain",
            b"ciphertext",
        )
        .unwrap();
    let txn = store.db.begin_write().unwrap();
    txn.open_table(COLLECTIONS)
        .unwrap()
        .insert(collection.id.as_str(), b"corrupt".as_slice())
        .unwrap();
    txn.commit().unwrap();
    store.delete_item(&item.id).unwrap();
    let report = store.check_integrity().unwrap();
    assert_eq!(report.corrupt_collections.len(), 1);
    assert_eq!(report.items_with_invalid_collection.len(), 0);
    assert_eq!(report.orphan_secret_files.len(), 0);
}

#[test]
fn item_crud_and_secret_perms() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let c = store.create_collection("c", None).unwrap();

    let item = store
        .create_item(
            &c.id,
            "wifi",
            attrs(&[("service", "wifi"), ("user", "me")]),
            "text/plain",
            b"CIPHERTEXT-1",
        )
        .unwrap();

    assert_eq!(store.get_item(&item.id).unwrap(), item);
    assert_eq!(store.read_secret_file(&item.id).unwrap(), b"CIPHERTEXT-1");
    assert_eq!(mode(&store.secret_path(&item.id).unwrap()), 0o600);
    assert_eq!(store.list_items(&c.id).unwrap().len(), 1);

    let updated = store
        .update_item(
            &item.id,
            Some("wifi-home"),
            None,
            None,
            Some(b"CIPHERTEXT-2"),
        )
        .unwrap();
    assert_eq!(updated.label, "wifi-home");
    assert!(updated.modified >= item.modified);
    assert_eq!(store.read_secret_file(&item.id).unwrap(), b"CIPHERTEXT-2");

    store.delete_item(&item.id).unwrap();
    assert!(matches!(store.get_item(&item.id), Err(Error::NotFound(_))));
    assert!(matches!(
        store.read_secret_file(&item.id),
        Err(Error::NotFound(_))
    ));
}

#[test]
fn symlinked_canonical_ciphertext_is_not_read() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let collection = store.create_collection("c", None).unwrap();
    let item = store
        .create_item(
            &collection.id,
            "item",
            HashMap::new(),
            "text/plain",
            b"outside ciphertext",
        )
        .unwrap();
    let canonical = store.secret_path(&item.id).unwrap();
    let outside = tempfile::tempdir().unwrap();
    let outside_ciphertext = outside.path().join("ciphertext.gpg");
    fs::write(&outside_ciphertext, b"outside ciphertext").unwrap();
    let outside_before = fs::read(&outside_ciphertext).unwrap();
    fs::remove_file(&canonical).unwrap();
    std::os::unix::fs::symlink(&outside_ciphertext, &canonical).unwrap();

    assert!(store.read_secret_file(&item.id).is_err());
    assert!(store.read_item_secret(&item.id).is_err());
    assert_eq!(fs::read(&outside_ciphertext).unwrap(), outside_before);
    assert!(
        fs::symlink_metadata(canonical)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn create_item_in_missing_collection_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    assert!(matches!(
        store.create_item("nope", "x", HashMap::new(), "text/plain", b"c"),
        Err(Error::NotFound(_))
    ));
}

#[test]
fn find_item_by_attrs_exact_matches_full_set_only() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let c = store.create_collection("c", None).unwrap();
    let a = attrs(&[("service", "mail"), ("user", "a")]);
    let item = store
        .create_item(&c.id, "mail", a.clone(), "text/plain", b"c")
        .unwrap();

    assert_eq!(
        store
            .find_item_by_attrs_exact(&c.id, &a)
            .unwrap()
            .unwrap()
            .id,
        item.id
    );
    // A strict subset is not an exact match.
    let subset = attrs(&[("service", "mail")]);
    assert!(
        store
            .find_item_by_attrs_exact(&c.id, &subset)
            .unwrap()
            .is_none()
    );
}

#[test]
fn concurrent_exact_replacements_create_one_item() {
    let tmp = tempfile::tempdir().unwrap();
    let store = std::sync::Arc::new(Store::open(tmp.path()).unwrap());
    let collection = store.create_collection("c", None).unwrap();
    let attributes = attrs(&[("service", "mail"), ("user", "me")]);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let mut workers = Vec::new();
    for ciphertext in [b"first".as_slice(), b"second".as_slice()] {
        let worker_store = std::sync::Arc::clone(&store);
        let worker_collection = collection.id.clone();
        let worker_attributes = attributes.clone();
        let worker_barrier = std::sync::Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            worker_store
                .create_or_replace_item_after_initial_check(
                    &worker_collection,
                    "mail",
                    worker_attributes,
                    "text/plain",
                    ciphertext,
                    true,
                    || {
                        worker_barrier.wait();
                    },
                )
                .unwrap()
        }));
    }

    let first = workers.remove(0).join().unwrap();
    let second = workers.remove(0).join().unwrap();
    assert_eq!(first.0.id, second.0.id);
    assert_ne!(first.1, second.1);
    let items = store.list_items(&collection.id).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].attributes, attributes);
    let (metadata, ciphertext) = store.read_item_secret(&items[0].id).unwrap();
    assert_eq!(metadata, items[0]);
    assert!(ciphertext == b"first" || ciphertext == b"second");
}

#[test]
fn search_subset_semantics() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let c = store.create_collection("c", None).unwrap();

    store
        .create_item(
            &c.id,
            "one",
            attrs(&[("service", "mail"), ("user", "a")]),
            "text/plain",
            b"1",
        )
        .unwrap();
    store
        .create_item(
            &c.id,
            "two",
            attrs(&[("service", "mail"), ("user", "b")]),
            "text/plain",
            b"2",
        )
        .unwrap();
    store
        .create_item(
            &c.id,
            "three",
            attrs(&[("service", "chat"), ("user", "a")]),
            "text/plain",
            b"3",
        )
        .unwrap();

    // Empty query matches everything.
    assert_eq!(store.search_items(&HashMap::new()).unwrap().len(), 3);
    // Single attribute subset.
    assert_eq!(
        store
            .search_items(&attrs(&[("service", "mail")]))
            .unwrap()
            .len(),
        2
    );
    // Multiple attributes must all match.
    assert_eq!(
        store
            .search_items(&attrs(&[("service", "mail"), ("user", "a")]))
            .unwrap()
            .len(),
        1
    );
    // No match.
    assert_eq!(
        store
            .search_items(&attrs(&[("service", "vpn")]))
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn invalid_item_ids_never_form_filesystem_paths() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let outside = tmp.path().join("outside.gpg");
    fs::write(&outside, b"keep").unwrap();

    assert!(store.read_secret_file("../outside").is_err());
    assert!(store.delete_item("../outside").is_err());
    assert_eq!(fs::read(outside).unwrap(), b"keep");
}

#[test]
fn collection_search_filters_before_attribute_matching() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let first = store.create_collection("first", None).unwrap();
    let second = store.create_collection("second", None).unwrap();
    let query = attrs(&[("service", "mail")]);
    let item = store
        .create_item(&first.id, "first", query.clone(), "text/plain", b"first")
        .unwrap();
    store
        .create_item(&second.id, "second", query.clone(), "text/plain", b"second")
        .unwrap();
    assert_eq!(
        store.search_collection_items(&first.id, &query).unwrap(),
        vec![item.clone()]
    );
    assert_eq!(
        store
            .search_collection_items(&first.id, &HashMap::new())
            .unwrap(),
        vec![item]
    );
    assert_eq!(
        store
            .search_collection_items(&first.id, &attrs(&[("service", "chat")]))
            .unwrap()
            .len(),
        0
    );
    assert_eq!(store.search_items(&query).unwrap().len(), 2);
}

#[test]
fn search_collection_items_rejects_missing_or_deleted_collection() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let collection = store.create_collection("temp", None).unwrap();
    assert!(matches!(
        store.search_collection_items("missing", &HashMap::new()),
        Err(Error::NotFound(_))
    ));
    store.delete_collection(&collection.id).unwrap();
    assert!(matches!(
        store.search_collection_items(&collection.id, &HashMap::new()),
        Err(Error::NotFound(_))
    ));
}
