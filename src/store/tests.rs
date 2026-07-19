//! Store unit tests.

use std::collections::HashSet;
use std::io;

use super::*;

fn attrs(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

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
fn replacement_restores_previous_ciphertext_when_commit_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let path = store.secret_path(id).unwrap();
    fs::write(&path, b"old").unwrap();
    let staged = store.stage_secret_file(id, b"new", "test").unwrap();

    let err = store
        .replace_then_commit(
            &path,
            &staged,
            || -> std::result::Result<(), PersistError> {
                Err(PersistError::Definite(Error::Config(
                    "injected commit failure".into(),
                )))
            },
        )
        .unwrap_err();

    assert!(err.to_string().contains("injected commit failure"));
    assert_eq!(fs::read(path).unwrap(), b"old");
    assert_eq!(
        store.check_integrity().unwrap().orphan_secret_files.len(),
        1
    );
}

#[test]
fn deletion_restores_ciphertext_when_commit_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let path = store.secret_path(id).unwrap();
    fs::write(&path, b"ciphertext").unwrap();

    let err = store
        .quarantine_then_commit(&path, || -> std::result::Result<(), PersistError> {
            Err(PersistError::Definite(Error::Config(
                "injected commit failure".into(),
            )))
        })
        .unwrap_err();

    assert!(err.to_string().contains("injected commit failure"));
    assert_eq!(fs::read(path).unwrap(), b"ciphertext");
    assert!(
        store
            .check_integrity()
            .unwrap()
            .recovery_secret_files
            .is_empty()
    );
}

#[test]
fn collection_ciphertexts_restore_when_commit_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let first = store
        .secret_path("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        .unwrap();
    let second = store
        .secret_path("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        .unwrap();
    fs::write(&first, b"first").unwrap();
    fs::write(&second, b"second").unwrap();

    let err = store
        .quarantine_many_then_commit(
            &[first.clone(), second.clone()],
            || -> std::result::Result<(), PersistError> {
                Err(PersistError::Definite(Error::Config(
                    "injected collection commit failure".into(),
                )))
            },
        )
        .unwrap_err();

    assert!(
        err.to_string()
            .contains("injected collection commit failure")
    );
    assert_eq!(fs::read(first).unwrap(), b"first");
    assert_eq!(fs::read(second).unwrap(), b"second");
    assert!(
        store
            .check_integrity()
            .unwrap()
            .recovery_secret_files
            .is_empty()
    );
}

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

#[test]
fn queued_writer_stops_after_store_is_poisoned() {
    let tmp = tempfile::tempdir().unwrap();
    let store = std::sync::Arc::new(Store::open(tmp.path()).unwrap());
    let active_guard = store.transaction_gate.write().unwrap();
    let active_txn = store.db.begin_write().unwrap();
    let passed_initial_check = std::sync::Arc::new(std::sync::Barrier::new(2));
    let queued_store = std::sync::Arc::clone(&store);
    let queued_barrier = std::sync::Arc::clone(&passed_initial_check);
    let queued_file = store.secrets_dir.join("queued.gpg");
    let queued_file_for_thread = queued_file.clone();

    let queued = std::thread::spawn(move || {
        let txn = queued_store.begin_write_checked_after_initial_check(|| {
            queued_barrier.wait();
        });
        let Ok((_mutation_guard, txn)) = txn else {
            return false;
        };
        fs::write(&queued_file_for_thread, b"mutated").unwrap();
        {
            let mut collections = txn.open_table(COLLECTIONS).unwrap();
            collections.insert("queued", b"mutated".as_slice()).unwrap();
        }
        txn.commit().unwrap();
        true
    });

    passed_initial_check.wait();
    store.poison();
    drop(active_txn);
    drop(active_guard);

    assert!(!queued.join().unwrap());
    let txn = store.db.begin_read().unwrap();
    let collections = txn.open_table(COLLECTIONS).unwrap();
    assert!(collections.get("queued").unwrap().is_none());
    assert!(!queued_file.exists());
}

#[test]
fn item_secret_reader_waits_for_update_rollback() {
    let tmp = tempfile::tempdir().unwrap();
    let store = std::sync::Arc::new(Store::open(tmp.path()).unwrap());
    let collection = store.create_collection("c", None).unwrap();
    let item = store
        .create_item(&collection.id, "item", HashMap::new(), "text/plain", b"old")
        .unwrap();
    let path = store.secret_path(&item.id).unwrap();
    let staged = store.stage_secret_file(&item.id, b"new", "update").unwrap();
    let write_guard = store.write_guard_checked().unwrap();
    let reader_store = std::sync::Arc::clone(&store);
    let reader_id = item.id.clone();
    let passed_initial_check = std::sync::Arc::new(std::sync::Barrier::new(2));
    let reader_barrier = std::sync::Arc::clone(&passed_initial_check);
    let (sender, receiver) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let result = reader_store.read_item_secret_after_initial_check(&reader_id, || {
            reader_barrier.wait();
        });
        sender.send(result).unwrap();
    });

    passed_initial_check.wait();
    let err = store
        .replace_then_commit(&path, &staged, || {
            assert!(matches!(
                receiver.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Empty)
            ));
            Err::<(), _>(PersistError::Definite(Error::Config(
                "injected metadata failure".into(),
            )))
        })
        .unwrap_err();

    assert!(err.to_string().contains("injected metadata failure"));
    assert_eq!(fs::read(&path).unwrap(), b"old");
    assert!(matches!(
        receiver.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    drop(write_guard);

    let (metadata, ciphertext) = receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .unwrap()
        .unwrap();
    reader.join().unwrap();
    assert_eq!(metadata, item);
    assert_eq!(ciphertext, b"old");
}

#[test]
fn raw_ciphertext_reader_waits_for_rollback() {
    let tmp = tempfile::tempdir().unwrap();
    let store = std::sync::Arc::new(Store::open(tmp.path()).unwrap());
    let collection = store.create_collection("c", None).unwrap();
    let item = store
        .create_item(&collection.id, "item", HashMap::new(), "text/plain", b"old")
        .unwrap();
    let path = store.secret_path(&item.id).unwrap();
    let write_guard = store.write_guard_checked().unwrap();
    let reader_store = std::sync::Arc::clone(&store);
    let reader_id = item.id.clone();
    let passed_initial_check = std::sync::Arc::new(std::sync::Barrier::new(2));
    let reader_barrier = std::sync::Arc::clone(&passed_initial_check);
    let (sender, receiver) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let result = reader_store.read_secret_file_after_initial_check(&reader_id, || {
            reader_barrier.wait();
        });
        sender.send(result).unwrap();
    });

    passed_initial_check.wait();
    fs::write(&path, b"uncommitted").unwrap();
    assert!(matches!(
        receiver.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    fs::write(&path, b"old").unwrap();
    drop(write_guard);

    assert_eq!(
        receiver
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap()
            .unwrap(),
        b"old"
    );
    reader.join().unwrap();
}

#[test]
fn create_install_sync_failure_removes_unindexed_ciphertext() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let path = store.secrets_dir.join("unindexed.gpg");
    let marker = store.secrets_dir.join("create-marker.gpg");
    fs::write(&path, b"ciphertext").unwrap();
    fs::write(&marker, b"ciphertext").unwrap();
    let sync_calls = std::cell::Cell::new(0);

    let err = store
        .finish_create_install(
            &path,
            &marker,
            || {
                sync_calls.set(sync_calls.get() + 1);
                if sync_calls.get() == 1 {
                    Err(Error::Io(io::Error::other("injected install sync failure")))
                } else {
                    Ok(())
                }
            },
            |candidate| fs::remove_file(candidate),
        )
        .unwrap_err();

    assert!(err.to_string().contains("injected install sync failure"));
    assert_eq!(sync_calls.get(), 3);
    assert!(!path.exists());
    assert!(!marker.exists());
    assert!(!store.is_poisoned());
}

#[test]
fn create_install_cleanup_failure_poisons_store() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let path = store.secrets_dir.join("unindexed.gpg");
    let marker = store.secrets_dir.join("create-marker.gpg");
    fs::write(&path, b"ciphertext").unwrap();
    fs::write(&marker, b"ciphertext").unwrap();

    let err = store
        .finish_create_install(
            &path,
            &marker,
            || Err(Error::Io(io::Error::other("injected install sync failure"))),
            |_| Err(io::Error::other("injected cleanup failure")),
        )
        .unwrap_err();

    assert!(err.to_string().contains("injected cleanup failure"));
    assert!(path.exists());
    assert!(marker.exists());
    assert!(store.is_poisoned());
    assert!(store.create_collection("blocked", None).is_err());
}

#[test]
fn create_install_cleanup_sync_failure_poisons_store() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let path = store.secrets_dir.join("unindexed.gpg");
    let marker = store.secrets_dir.join("create-marker.gpg");
    fs::write(&path, b"ciphertext").unwrap();
    fs::write(&marker, b"ciphertext").unwrap();

    let err = store
        .finish_create_install(
            &path,
            &marker,
            || {
                Err(Error::Io(io::Error::other(
                    "injected directory sync failure",
                )))
            },
            |candidate| fs::remove_file(candidate),
        )
        .unwrap_err();

    assert!(err.to_string().contains("cleanup directory sync failed"));
    assert!(!path.exists());
    assert!(marker.exists());
    assert!(store.is_poisoned());
    assert!(store.create_collection("blocked", None).is_err());
}

#[test]
fn indeterminate_update_commit_keeps_artifacts_for_persisted_outcome() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let collection = store.create_collection("c", None).unwrap();
    let item = store
        .create_item(&collection.id, "item", HashMap::new(), "text/plain", b"old")
        .unwrap();
    let path = store.secret_path(&item.id).unwrap();
    let staged = store.stage_secret_file(&item.id, b"new", "update").unwrap();
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
    let staged = store.stage_secret_file(&item.id, b"new", "update").unwrap();
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

#[test]
fn cleanup_failure_keeps_recoverable_file_and_reports_path() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let file = ".noirpass-quarantine-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-1.gpg";
    let path = store.secrets_dir.join(file);
    fs::write(&path, b"ciphertext").unwrap();

    let err = Store::remove_recovery_file(&path, "metadata deletion committed", |_| {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "injected cleanup failure",
        ))
    })
    .unwrap_err();

    assert!(err.to_string().contains("metadata deletion committed"));
    assert!(err.to_string().contains(path.to_string_lossy().as_ref()));
    assert!(path.exists());
    assert_eq!(
        store.check_integrity().unwrap().recovery_secret_files,
        vec![file.to_string()]
    );
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
fn startup_recovery_removes_valid_staged_files() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let create = store.stage_secret_file(id, b"create", "create").unwrap();
    let update = store.stage_secret_file(id, b"update", "update").unwrap();

    let report = store.check_integrity().unwrap();
    assert_eq!(report.recovery_secret_files.len(), 2);
    assert!(!report.is_healthy());
    store.recover_interrupted_operations().unwrap();
    assert!(!create.exists());
    assert!(!update.exists());
    assert!(store.check_integrity().unwrap().is_healthy());
}

#[test]
fn startup_recovery_preserves_backup_without_metadata() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let backup = store
        .secrets_dir
        .join(".noirpass-backup-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-0000000000000001.gpg");
    fs::write(&backup, b"only-copy").unwrap();

    let err = store.recover_interrupted_operations().unwrap_err();

    assert!(err.to_string().contains("preserved for manual recovery"));
    assert_eq!(fs::read(backup).unwrap(), b"only-copy");
}

#[test]
fn startup_recovery_keeps_committed_update_and_finishes_committed_delete() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let collection = store.create_collection("c", None).unwrap();
    let updated = store
        .create_item(
            &collection.id,
            "updated",
            HashMap::new(),
            "text/plain",
            b"old",
        )
        .unwrap();
    store
        .update_item(&updated.id, None, None, None, Some(b"new"))
        .unwrap();
    let backup = store.secrets_dir.join(format!(
        ".noirpass-backup-{}-0000000000000001.gpg",
        updated.id
    ));
    fs::write(&backup, b"old").unwrap();

    let deleted = store
        .create_item(
            &collection.id,
            "deleted",
            HashMap::new(),
            "text/plain",
            b"deleted",
        )
        .unwrap();
    let deleted_path = store.secret_path(&deleted.id).unwrap();
    let quarantine = store.secrets_dir.join(format!(
        ".noirpass-quarantine-{}-0000000000000001.gpg",
        deleted.id
    ));
    fs::rename(&deleted_path, &quarantine).unwrap();
    store.delete_item_metadata(&deleted.id).unwrap();

    store.recover_interrupted_operations().unwrap();

    assert_eq!(store.read_secret_file(&updated.id).unwrap(), b"new");
    assert!(!backup.exists());
    assert!(!quarantine.exists());
    assert!(!deleted_path.exists());
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
