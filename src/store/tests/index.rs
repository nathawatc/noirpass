//! Derived lookup indexes must agree with persistent state through all mutations.

use super::*;

fn sorted(mut items: Vec<ItemMeta>) -> Vec<ItemMeta> {
    items.sort_by(|a, b| a.id.cmp(&b.id));
    items
}

#[test]
fn indexed_queries_preserve_order_superset_matching_and_attribute_boundaries() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let first = store.ensure_default().unwrap();
    let second = store.create_collection("second", None).unwrap();
    let a = store
        .create_item(
            &first.id,
            "a",
            attrs(&[
                ("service", "mail"),
                ("account", "a"),
                ("a", "b:c"),
                ("empty", ""),
            ]),
            "text/plain",
            b"a",
        )
        .unwrap();
    let b = store
        .create_item(
            &second.id,
            "b",
            attrs(&[("service", "mail"), ("account", "b"), ("a:b", "c")]),
            "text/plain",
            b"b",
        )
        .unwrap();
    let c = store
        .create_item(
            &first.id,
            "c",
            attrs(&[("service", "vpn"), ("ผู้ใช้", "猫")]),
            "text/plain",
            b"c",
        )
        .unwrap();
    // A missing collection must still build and validate the complete index.
    assert!(store.list_items("missing").unwrap().is_empty());
    assert_eq!(
        store.list_items(&first.id).unwrap(),
        sorted(vec![a.clone(), c.clone()])
    );
    assert_eq!(store.list_items(&second.id).unwrap(), vec![b.clone()]);
    for (query, expected) in [
        (HashMap::new(), vec![a.clone(), b.clone(), c.clone()]),
        (attrs(&[("service", "mail")]), vec![a.clone(), b.clone()]),
        (
            attrs(&[("service", "mail"), ("account", "a")]),
            vec![a.clone()],
        ),
        (attrs(&[("service", "vpn"), ("account", "a")]), vec![]),
        (attrs(&[("a", "b:c")]), vec![a.clone()]),
        (attrs(&[("a:b", "c")]), vec![b]),
        (attrs(&[("empty", "")]), vec![a.clone()]),
        (attrs(&[("ผู้ใช้", "猫")]), vec![c]),
        (attrs(&[("missing", "value")]), vec![]),
        (attrs(&[("service", "missing")]), vec![]),
    ] {
        assert_eq!(
            store.search_items(&query).unwrap(),
            sorted(expected),
            "{query:?}"
        );
    }
    assert_eq!(
        store
            .search_collection_items(&first.id, &attrs(&[("service", "mail")]))
            .unwrap(),
        vec![a]
    );
    assert!(
        store
            .search_collection_items(&second.id, &attrs(&[("account", "a")]))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn warm_index_follows_create_update_replace_delete_and_reopen() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let collection = store.ensure_default().unwrap();
    let old = attrs(&[("service", "old")]);
    let new = attrs(&[("service", "new")]);
    assert!(store.search_items(&old).unwrap().is_empty());
    let a = store
        .create_item(&collection.id, "a", old.clone(), "text/plain", b"a")
        .unwrap();
    assert_eq!(store.search_items(&old).unwrap(), vec![a.clone()]);
    assert_eq!(store.list_items(&collection.id).unwrap(), vec![a.clone()]);
    let a = store
        .update_item(&a.id, None, Some(new.clone()), None, None)
        .unwrap();
    assert!(store.search_items(&old).unwrap().is_empty());
    assert_eq!(store.search_items(&new).unwrap(), vec![a]);
    let (a, replaced) = store
        .create_or_replace_item(
            &collection.id,
            "replacement",
            new.clone(),
            "text/plain",
            b"replacement",
            true,
        )
        .unwrap();
    assert!(replaced);
    assert_eq!(store.search_items(&new).unwrap(), vec![a.clone()]);
    let b = store
        .create_item(&collection.id, "b", old.clone(), "text/plain", b"b")
        .unwrap();
    assert_eq!(
        store.list_items(&collection.id).unwrap(),
        sorted(vec![a.clone(), b.clone()])
    );
    store.delete_item(&a.id).unwrap();
    assert!(store.search_items(&new).unwrap().is_empty());
    assert_eq!(store.list_items(&collection.id).unwrap(), vec![b.clone()]);
    store.delete_item_metadata(&b.id).unwrap();
    assert!(store.search_items(&old).unwrap().is_empty());
    // Metadata-only deletion deliberately leaves ciphertext for integrity tools.
    fs::remove_file(store.secret_path(&b.id).unwrap()).unwrap();
    let survivor = store
        .create_item(
            &collection.id,
            "survivor",
            old.clone(),
            "text/plain",
            b"survivor",
        )
        .unwrap();
    assert_eq!(store.search_items(&old).unwrap(), vec![survivor.clone()]);
    drop(store);
    let store = Store::open_existing(tmp.path()).unwrap();
    assert_eq!(store.search_items(&old).unwrap(), vec![survivor]);
    store.delete_collection(&collection.id).unwrap();
    assert!(store.list_items(&collection.id).unwrap().is_empty());
    assert!(store.search_items(&old).unwrap().is_empty());
    assert!(store.check_integrity().unwrap().is_healthy());
}

#[test]
fn invalid_metadata_blocks_even_empty_candidates_and_repair_discards_partial_index() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let collection = store.ensure_default().unwrap();
    let item = store
        .create_item(
            &collection.id,
            "valid",
            HashMap::new(),
            "text/plain",
            b"valid",
        )
        .unwrap();
    assert_eq!(
        store.list_items(&collection.id).unwrap(),
        vec![item.clone()]
    );
    let (guard, txn) = store.begin_write_checked().unwrap();
    txn.open_table(ITEMS)
        .unwrap()
        .insert("bad-key", b"corrupt".as_slice())
        .unwrap();
    txn.commit().unwrap();
    drop(guard);
    // Every retry must fail: a failed build must never publish partial candidates.
    for _ in 0..2 {
        assert!(store.list_items("missing").is_err());
        assert!(
            store
                .search_items(&attrs(&[("unknown", "unknown")]))
                .is_err()
        );
    }
    store.delete_item_metadata("bad-key").unwrap();
    assert_eq!(store.list_items(&collection.id).unwrap(), vec![item]);
    assert!(
        store
            .search_items(&attrs(&[("unknown", "unknown")]))
            .unwrap()
            .is_empty()
    );
    store.poison();
    assert!(store.list_items(&collection.id).is_err());
    assert!(store.search_items(&HashMap::new()).is_err());
}
