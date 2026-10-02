//! Derived lookup indexes must agree with persistent state through all mutations.

use super::*;
use redb::ReadableTable;

pub(super) fn assert_warm_index(store: &Store) {
    let cache = store.item_index.read().unwrap();
    let index = cache
        .as_ref()
        .expect("successful mutation preserves the warm index");
    let txn = store.db.begin_read().unwrap();
    let mut expected = crate::store::items::ItemIndex::default();
    for entry in txn.open_table(ITEMS).unwrap().iter().unwrap() {
        let (key, value) = entry.unwrap();
        expected.insert(&decode_item(key.value(), value.value()).unwrap());
    }
    assert_eq!(index, &expected);
}

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
    assert_eq!(store.list_items("missing").unwrap().len(), 0);
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
    assert_eq!(
        store
            .search_collection_items(&second.id, &attrs(&[("account", "a")]))
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn warm_index_follows_create_update_replace_delete_and_reopen() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let collection = store.ensure_default().unwrap();
    let old = attrs(&[("service", "old")]);
    let new = attrs(&[("service", "new")]);
    assert_eq!(store.search_items(&old).unwrap().len(), 0);
    let a = store
        .create_item(&collection.id, "a", old.clone(), "text/plain", b"a")
        .unwrap();
    assert_warm_index(&store);
    assert_eq!(store.search_items(&old).unwrap(), vec![a.clone()]);
    assert_eq!(store.list_items(&collection.id).unwrap(), vec![a.clone()]);
    let a = store
        .update_item(&a.id, None, Some(new.clone()), None, None)
        .unwrap();
    assert_warm_index(&store);
    assert_eq!(store.search_items(&old).unwrap().len(), 0);
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
    assert_warm_index(&store);
    assert!(replaced);
    assert_eq!(store.search_items(&new).unwrap(), vec![a.clone()]);
    let b = store
        .create_item(&collection.id, "b", old.clone(), "text/plain", b"b")
        .unwrap();
    assert_warm_index(&store);
    assert_eq!(
        store.list_items(&collection.id).unwrap(),
        sorted(vec![a.clone(), b.clone()])
    );
    store.delete_item(&a.id).unwrap();
    assert_warm_index(&store);
    assert_eq!(store.search_items(&new).unwrap().len(), 0);
    assert_eq!(store.list_items(&collection.id).unwrap(), vec![b.clone()]);
    store.delete_item_metadata(&b.id).unwrap();
    assert!(store.item_index.read().unwrap().is_none());
    assert_eq!(store.search_items(&old).unwrap().len(), 0);
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
    assert_warm_index(&store);
    assert_eq!(store.list_items(&collection.id).unwrap().len(), 0);
    assert_warm_index(&store);
    assert_eq!(store.search_items(&old).unwrap().len(), 0);
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
    assert_eq!(
        store
            .search_items(&attrs(&[("unknown", "unknown")]))
            .unwrap()
            .len(),
        0
    );
    store.poison();
    assert!(store.list_items(&collection.id).is_err());
    assert!(store.search_items(&HashMap::new()).is_err());
}

#[test]
fn collection_and_alias_writes_preserve_index_after_rejected_writes() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let collection = store.ensure_default().unwrap();
    let item = store
        .create_item(
            &collection.id,
            "item",
            attrs(&[("key", "value")]),
            "text/plain",
            b"item",
        )
        .unwrap();
    store.list_items(&collection.id).unwrap();
    store.ensure_default().unwrap();
    assert_warm_index(&store);
    let other = store.create_collection("other", Some("other")).unwrap();
    assert_warm_index(&store);
    store.set_collection_label(&other.id, "renamed").unwrap();
    assert_warm_index(&store);
    store.set_alias("other", Some(&collection.id)).unwrap();
    assert_warm_index(&store);
    store.set_alias("other", None).unwrap();
    assert_warm_index(&store);
    let updated = store
        .update_item(
            &item.id,
            Some("renamed"),
            None,
            Some("application/octet-stream"),
            Some(b"updated"),
        )
        .unwrap();
    assert_warm_index(&store);
    assert_eq!(store.search_items(&item.attributes).unwrap(), vec![updated]);
    assert!(store.set_alias("bad", Some("missing")).is_err());
    assert_warm_index(&store);
    store.list_items(&collection.id).unwrap();
    assert_warm_index(&store);
    store.recover_interrupted_operations().unwrap();
    assert!(store.item_index.read().unwrap().is_none());
}

#[test]
fn warm_mutations_use_exact_attributes_and_preserve_other_collections() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let collection = store.ensure_default().unwrap();
    let other = store.create_collection("other", Some("other")).unwrap();
    let exact = attrs(&[("service", "mail")]);
    let extra = attrs(&[("service", "mail"), ("account", "extra")]);
    let survivor = store
        .create_item(
            &other.id,
            "survivor",
            exact.clone(),
            "text/plain",
            b"survivor",
        )
        .unwrap();
    let superset = store
        .create_item(&collection.id, "superset", extra, "text/plain", b"superset")
        .unwrap();
    store.search_items(&exact).unwrap();
    let (created, replaced) = store
        .create_or_replace_item(
            &collection.id,
            "exact",
            exact.clone(),
            "text/plain",
            b"exact",
            true,
        )
        .unwrap();
    assert!(!replaced);
    assert_warm_index(&store);
    let (updated, replaced) = store
        .create_or_replace_item(
            &collection.id,
            "updated",
            exact,
            "text/plain",
            b"updated",
            true,
        )
        .unwrap();
    assert!(replaced);
    assert_eq!(updated.id, created.id);
    assert_warm_index(&store);
    let deleted = store.delete_collection(&collection.id).unwrap();
    let mut expected = vec![updated.id, superset.id];
    expected.sort();
    assert_eq!(deleted.item_ids, expected);
    assert_warm_index(&store);
    assert_eq!(
        store.search_items(&HashMap::new()).unwrap(),
        vec![survivor.clone()]
    );
    assert_eq!(store.read_item_secret(&survivor.id).unwrap().1, b"survivor");
    assert_eq!(store.read_alias("other").unwrap(), Some(other.id));
    assert!(store.check_integrity().unwrap().is_healthy());
}

#[test]
fn explicit_abort_preserves_index_but_raw_commit_discards_it() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let collection = store.ensure_default().unwrap();
    let item = store
        .create_item(
            &collection.id,
            "item",
            HashMap::new(),
            "text/plain",
            b"item",
        )
        .unwrap();
    store.list_items(&collection.id).unwrap();
    {
        let (_guard, txn) = store.begin_write_checked().unwrap();
        txn.open_table(ITEMS)
            .unwrap()
            .remove(item.id.as_str())
            .unwrap();
        // Dropping an uncommitted transaction explicitly aborts it before the
        // checked write guard can preserve the original index.
    }
    assert_warm_index(&store);
    assert_eq!(store.get_item(&item.id).unwrap(), item);
    let (guard, txn) = store.begin_write_checked().unwrap();
    txn.open_table(ITEMS)
        .unwrap()
        .remove(item.id.as_str())
        .unwrap();
    txn.commit().unwrap();
    drop(guard);
    assert!(store.item_index.read().unwrap().is_none());
    assert_eq!(store.list_items(&collection.id).unwrap().len(), 0);
}
