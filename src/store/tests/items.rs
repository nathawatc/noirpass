use super::*;

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
