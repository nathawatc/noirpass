use super::*;

#[test]
fn collection_reads_and_updates_reject_embedded_id_mismatch() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let valid_b = store.create_collection("valid-b", None).unwrap();
    let key_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let corrupt = CollectionMeta {
        label: "corrupt-a".to_string(),
        ..valid_b.clone()
    };
    let txn = store.db.begin_write().unwrap();
    {
        let mut collections = txn.open_table(COLLECTIONS).unwrap();
        let bytes = serde_json::to_vec(&corrupt).unwrap();
        collections.insert(key_a, bytes.as_slice()).unwrap();
    }
    txn.commit().unwrap();

    assert!(store.get_collection(key_a).is_err());
    assert!(store.set_collection_label(key_a, "changed").is_err());
    assert_eq!(store.get_collection(&valid_b.id).unwrap(), valid_b);
    let report = store.check_integrity().unwrap();
    assert_eq!(report.corrupt_collections.len(), 1);
    assert_eq!(report.corrupt_collections[0].table_key, key_a);
}

#[test]
fn readonly_integrity_probe_preserves_busy_store_behavior() {
    let tmp = tempfile::tempdir().unwrap();
    let setup = Store::open(tmp.path()).unwrap();
    setup.ensure_default().unwrap();
    drop(setup);
    let _store = Store::open(tmp.path()).unwrap();
    let index_before = fs::read(tmp.path().join("index.redb")).unwrap();

    let report = Store::probe_integrity(tmp.path()).unwrap();

    assert!(report.is_healthy());
    assert_eq!(
        fs::read(tmp.path().join("index.redb")).unwrap(),
        index_before
    );
}

#[test]
fn readonly_integrity_probe_rejects_invalid_secrets_path_while_store_is_busy() {
    let tmp = tempfile::tempdir().unwrap();
    let setup = Store::open(tmp.path()).unwrap();
    setup.ensure_default().unwrap();
    drop(setup);
    let _store = Store::open(tmp.path()).unwrap();
    let secrets_dir = tmp.path().join("secrets");
    let outside = tempfile::tempdir().unwrap();
    let outside_file = outside.path().join("keep.txt");
    fs::write(&outside_file, b"outside").unwrap();
    fs::remove_dir(&secrets_dir).unwrap();
    std::os::unix::fs::symlink(outside.path(), &secrets_dir).unwrap();

    let err = Store::probe_integrity(tmp.path()).unwrap_err();

    assert!(
        err.to_string()
            .contains("store secrets path is not a directory")
    );
    assert_eq!(fs::read(outside_file).unwrap(), b"outside");
}

#[test]
fn integrity_reports_missing_item_owner_and_dangling_alias() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let collection = store.create_collection("owner", None).unwrap();
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
    {
        let mut items = txn.open_table(ITEMS).unwrap();
        let mut metadata = item.clone();
        metadata.collection = "cccccccccccccccccccccccccccccccc".to_string();
        let bytes = serde_json::to_vec(&metadata).unwrap();
        items.insert(item.id.as_str(), bytes.as_slice()).unwrap();
        let mut aliases = txn.open_table(ALIASES).unwrap();
        aliases
            .insert("dangling", metadata.collection.as_str())
            .unwrap();
    }
    txn.commit().unwrap();

    let report = store.check_integrity().unwrap();
    assert!(report.corrupt_items.is_empty());
    assert_eq!(report.items_with_invalid_collection.len(), 1);
    assert!(
        report.items_with_invalid_collection[0]
            .error
            .contains("missing collection")
    );
    assert_eq!(
        report.corrupt_aliases,
        vec![(
            "dangling".to_string(),
            "cccccccccccccccccccccccccccccccc".to_string()
        )]
    );
}

#[test]
fn ensure_default_preserves_dangling_default_alias_and_integrity_blocks_serve() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    store.ensure_default().unwrap();
    let dangling = "cccccccccccccccccccccccccccccccc";
    let txn = store.db.begin_write().unwrap();
    {
        let mut aliases = txn.open_table(ALIASES).unwrap();
        aliases.insert("default", dangling).unwrap();
    }
    txn.commit().unwrap();

    store.ensure_default().unwrap();

    assert_eq!(
        store.read_alias("default").unwrap().as_deref(),
        Some(dangling)
    );
    let report = store.check_integrity().unwrap();
    assert_eq!(
        report.corrupt_aliases,
        vec![("default".to_string(), dangling.to_string())]
    );
    assert!(store.ensure_safe_to_serve().is_err());
}

#[test]
fn integrity_reports_missing_and_orphan_ciphertext() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let collection = store.create_collection("c", None).unwrap();
    let missing = store
        .create_item(
            &collection.id,
            "missing",
            attrs(&[("k", "v")]),
            "text/plain",
            b"ciphertext",
        )
        .unwrap();
    let present = store
        .create_item(
            &collection.id,
            "present",
            attrs(&[("k", "w")]),
            "text/plain",
            b"ciphertext",
        )
        .unwrap();
    fs::remove_file(store.secret_path(&missing.id).unwrap()).unwrap();
    fs::write(store.secrets_dir.join("orphan.gpg"), b"ciphertext").unwrap();

    let report = store.check_integrity().unwrap();

    assert_eq!(
        report.missing_secret_items,
        vec![IndexedItem {
            table_key: missing.id.clone(),
            metadata: missing.clone(),
        }]
    );
    assert_eq!(report.orphan_secret_files, vec!["orphan.gpg".to_string()]);
    assert!(!report.is_healthy());
    assert!(store.read_secret_file(&present.id).is_ok());

    store.delete_item(&missing.id).unwrap();
    fs::remove_file(store.secrets_dir.join("orphan.gpg")).unwrap();
    assert!(store.check_integrity().unwrap().is_healthy());
}

#[test]
fn integrity_uses_table_keys_and_isolates_corrupt_records() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let collection = store.create_collection("c", None).unwrap();
    let valid_b = store
        .create_item(
            &collection.id,
            "valid-b",
            attrs(&[("k", "b")]),
            "text/plain",
            b"b",
        )
        .unwrap();
    let key_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let mut mismatched = valid_b.clone();
    mismatched.label = "corrupt-a".to_string();
    let txn = store.db.begin_write().unwrap();
    {
        let mut items = txn.open_table(ITEMS).unwrap();
        let bytes = serde_json::to_vec(&mismatched).unwrap();
        items.insert(key_a, bytes.as_slice()).unwrap();
    }
    txn.commit().unwrap();

    let report = store.check_integrity().unwrap();
    assert_eq!(report.corrupt_items.len(), 1);
    assert_eq!(report.corrupt_items[0].table_key, key_a);
    assert_eq!(
        report.corrupt_items[0].metadata.as_ref().unwrap().id,
        valid_b.id
    );

    store.delete_item(key_a).unwrap();
    assert_eq!(store.get_item(&valid_b.id).unwrap(), valid_b);
    assert_eq!(store.read_secret_file(&valid_b.id).unwrap(), b"b");
    assert!(store.check_integrity().unwrap().is_healthy());
}

#[test]
fn integrity_reports_malformed_metadata_by_table_key() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let txn = store.db.begin_write().unwrap();
    {
        let mut items = txn.open_table(ITEMS).unwrap();
        items.insert(key, b"not-json".as_slice()).unwrap();
    }
    txn.commit().unwrap();

    let report = store.check_integrity().unwrap();
    assert_eq!(report.corrupt_items.len(), 1);
    assert_eq!(report.corrupt_items[0].table_key, key);
    assert!(report.corrupt_items[0].metadata.is_none());
    store.delete_item(key).unwrap();
    assert!(store.check_integrity().unwrap().is_healthy());
}

#[test]
fn integrity_blocks_ciphertext_digest_mismatch() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let collection = store.create_collection("c", None).unwrap();
    let item = store
        .create_item(
            &collection.id,
            "item",
            HashMap::new(),
            "text/plain",
            b"expected",
        )
        .unwrap();
    fs::write(store.secret_path(&item.id).unwrap(), b"wrong").unwrap();

    let report = store.check_integrity().unwrap();
    assert_eq!(report.ciphertext_mismatches.len(), 1);
    assert_eq!(report.ciphertext_mismatches[0].table_key, item.id);
    assert!(!report.is_healthy());
    assert!(store.ensure_safe_to_serve().is_err());
}

#[test]
fn integrity_reports_recoverable_quarantine_files() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let file = ".noirpass-quarantine-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-1.gpg";
    fs::write(store.secrets_dir.join(file), b"ciphertext").unwrap();

    let report = store.check_integrity().unwrap();
    assert_eq!(report.recovery_secret_files, vec![file.to_string()]);
    assert!(!report.is_healthy());
}

#[test]
fn integrity_rejects_non_regular_ciphertext_paths() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let collection = store.create_collection("c", None).unwrap();
    let item = store
        .create_item(
            &collection.id,
            "item",
            attrs(&[("k", "v")]),
            "text/plain",
            b"ciphertext",
        )
        .unwrap();
    let path = store.secret_path(&item.id).unwrap();
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();

    let err = store.check_integrity().unwrap_err();

    assert!(err.to_string().contains("not a regular file"));
}
