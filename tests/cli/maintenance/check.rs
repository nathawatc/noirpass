use std::collections::HashMap;
use std::process::Command;

use noirpass::store::{ItemMeta, Store};
use redb::{Database, ReadableDatabase, ReadableTableMetadata, TableDefinition};

#[test]
fn cli_lists_deletes_and_repairs_stale_items() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let collection = store.ensure_default().unwrap();
    let present = store
        .create_or_replace_item(
            &collection.id,
            "present secret",
            HashMap::from([("service".to_string(), "present".to_string())]),
            "text/plain",
            b"ciphertext",
            false,
        )
        .unwrap()
        .0;
    let missing = store
        .create_or_replace_item(
            &collection.id,
            "missing secret",
            HashMap::from([("service".to_string(), "missing".to_string())]),
            "text/plain",
            b"ciphertext",
            false,
        )
        .unwrap()
        .0;
    std::fs::remove_file(
        dir.path()
            .join("secrets")
            .join(format!("{}.gpg", missing.id)),
    )
    .unwrap();
    drop(store);

    let listed = Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .env_remove("NOIRPASS_STORE")
        .arg("--store-dir")
        .arg(dir.path())
        .arg("list")
        .output()
        .expect("spawn noirpass list");
    assert!(
        listed.status.success(),
        "list failed: stdout={} stderr={}",
        String::from_utf8_lossy(&listed.stdout),
        String::from_utf8_lossy(&listed.stderr)
    );
    let stdout = String::from_utf8_lossy(&listed.stdout);
    assert!(stdout.contains(&present.id));
    assert!(stdout.contains(&missing.id));
    assert!(stdout.contains("ciphertext: missing"));

    let checked = Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .env_remove("NOIRPASS_STORE")
        .arg("--store-dir")
        .arg(dir.path())
        .args(["check", "--yes"])
        .output()
        .expect("spawn noirpass check");
    assert!(
        checked.status.success(),
        "check failed: stdout={} stderr={}",
        String::from_utf8_lossy(&checked.stdout),
        String::from_utf8_lossy(&checked.stderr)
    );
    assert!(String::from_utf8_lossy(&checked.stdout).contains("store health: repaired"));

    let store = Store::open_existing(dir.path()).unwrap();
    assert!(store.get_item(&present.id).is_ok());
    assert!(store.get_item(&missing.id).is_err());
    drop(store);

    let deleted = Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .env_remove("NOIRPASS_STORE")
        .arg("--store-dir")
        .arg(dir.path())
        .arg("delete")
        .arg(&present.id)
        .arg("--yes")
        .output()
        .expect("spawn noirpass delete");
    assert!(
        deleted.status.success(),
        "delete failed: stdout={} stderr={}",
        String::from_utf8_lossy(&deleted.stdout),
        String::from_utf8_lossy(&deleted.stderr)
    );
    assert!(String::from_utf8_lossy(&deleted.stdout).contains(&present.id));

    let store = Store::open_existing(dir.path()).unwrap();
    assert!(store.search_items(&HashMap::new()).unwrap().is_empty());
    assert!(store.check_integrity().unwrap().is_healthy());
}

#[test]
fn cli_rejects_mismatched_item_id_without_deleting_valid_item() {
    const ITEMS: TableDefinition<&str, &[u8]> = TableDefinition::new("items");
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let collection = store.ensure_default().unwrap();
    let valid_b = store
        .create_or_replace_item(
            &collection.id,
            "valid-b",
            HashMap::new(),
            "text/plain",
            b"ciphertext-b",
            false,
        )
        .unwrap()
        .0;
    let key_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let corrupt = ItemMeta {
        label: "corrupt-a".to_string(),
        ..valid_b.clone()
    };
    drop(store);
    let db = Database::open(dir.path().join("index.redb")).unwrap();
    let txn = db.begin_write().unwrap();
    {
        let mut items = txn.open_table(ITEMS).unwrap();
        let bytes = serde_json::to_vec(&corrupt).unwrap();
        items.insert(key_a, bytes.as_slice()).unwrap();
    }
    txn.commit().unwrap();
    drop(db);

    let listed = Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .env_remove("NOIRPASS_STORE")
        .arg("--store-dir")
        .arg(dir.path())
        .arg("list")
        .output()
        .expect("spawn noirpass list");
    assert!(
        !listed.status.success(),
        "list must reject mismatched item ids"
    );

    let deleted = Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .env_remove("NOIRPASS_STORE")
        .arg("--store-dir")
        .arg(dir.path())
        .arg("delete")
        .arg(key_a)
        .arg("--yes")
        .output()
        .expect("spawn noirpass delete");

    assert!(!deleted.status.success());
    let store = Store::open_existing(dir.path()).unwrap();
    assert_eq!(store.get_item(&valid_b.id).unwrap(), valid_b);
    assert_eq!(
        store.read_secret_file(&valid_b.id).unwrap(),
        b"ciphertext-b"
    );
    assert_eq!(store.check_integrity().unwrap().corrupt_items.len(), 1);
}

#[test]
fn cli_check_repairs_noncanonical_item_key() {
    const ITEMS: TableDefinition<&str, &[u8]> = TableDefinition::new("items");
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let collection = store.ensure_default().unwrap();
    let metadata = ItemMeta {
        id: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        collection: collection.id,
        label: "bad-key".to_string(),
        attributes: HashMap::new(),
        content_type: "text/plain".to_string(),
        ciphertext_sha256: None,
        created: 1,
        modified: 1,
    };
    drop(store);
    let db = Database::open(dir.path().join("index.redb")).unwrap();
    let txn = db.begin_write().unwrap();
    {
        let mut items = txn.open_table(ITEMS).unwrap();
        let bytes = serde_json::to_vec(&metadata).unwrap();
        items.insert("bad-key", bytes.as_slice()).unwrap();
    }
    txn.commit().unwrap();
    drop(db);

    let checked = Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .env_remove("NOIRPASS_STORE")
        .arg("--store-dir")
        .arg(dir.path())
        .args(["check", "--yes"])
        .output()
        .expect("spawn noirpass check");

    assert!(
        checked.status.success(),
        "check failed: stdout={} stderr={}",
        String::from_utf8_lossy(&checked.stdout),
        String::from_utf8_lossy(&checked.stderr)
    );
    let store = Store::open_existing(dir.path()).unwrap();
    assert!(store.check_integrity().unwrap().is_healthy());
}

#[test]
fn cli_check_recovers_quarantined_ciphertext_before_repair() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let collection = store.ensure_default().unwrap();
    let item = store
        .create_or_replace_item(
            &collection.id,
            "recoverable",
            HashMap::new(),
            "text/plain",
            b"recoverable-ciphertext",
            false,
        )
        .unwrap()
        .0;
    let canonical = dir.path().join("secrets").join(format!("{}.gpg", item.id));
    let quarantine = dir.path().join("secrets").join(format!(
        ".noirpass-quarantine-{}-0000000000000001.gpg",
        item.id
    ));
    std::fs::rename(&canonical, &quarantine).unwrap();
    drop(store);

    let checked = Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .env_remove("NOIRPASS_STORE")
        .arg("--store-dir")
        .arg(dir.path())
        .args(["check", "--yes"])
        .output()
        .expect("spawn noirpass check");

    assert!(
        checked.status.success(),
        "check failed: stdout={} stderr={}",
        String::from_utf8_lossy(&checked.stdout),
        String::from_utf8_lossy(&checked.stderr)
    );
    let store = Store::open_existing(dir.path()).unwrap();
    assert_eq!(store.get_item(&item.id).unwrap(), item);
    assert_eq!(
        store.read_secret_file(&item.id).unwrap(),
        b"recoverable-ciphertext"
    );
    assert!(!quarantine.exists());
    assert!(store.check_integrity().unwrap().is_healthy());
}

#[test]
fn cli_delete_removes_rows_files_and_preserves_other_items() {
    const ITEMS: TableDefinition<&str, &[u8]> = TableDefinition::new("items");
    for missing_ciphertext in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let collection = store.ensure_default().unwrap();
        let target = store
            .create_or_replace_item(
                &collection.id,
                "deleted item",
                HashMap::from([("service".into(), "deleted".into())]),
                "text/plain",
                b"fixture target ciphertext",
                false,
            )
            .unwrap()
            .0;
        let survivor = store
            .create_or_replace_item(
                &collection.id,
                "survivor",
                HashMap::new(),
                "text/plain",
                b"fixture survivor ciphertext",
                false,
            )
            .unwrap()
            .0;
        let target_file = dir
            .path()
            .join("secrets")
            .join(format!("{}.gpg", target.id));
        if missing_ciphertext {
            std::fs::remove_file(&target_file).unwrap();
        }
        drop(store);
        let output = Command::new(env!("CARGO_BIN_EXE_noirpass"))
            .env_remove("NOIRPASS_STORE")
            .arg("--store-dir")
            .arg(dir.path())
            .args(["delete", &target.id, "--yes"])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let store = Store::open_existing(dir.path()).unwrap();
        assert!(matches!(
            store.get_item(&target.id),
            Err(noirpass::Error::NotFound(_))
        ));
        assert_eq!(
            store.read_item_secret(&survivor.id).unwrap().1,
            b"fixture survivor ciphertext"
        );
        assert_eq!(
            store.search_items(&HashMap::new()).unwrap(),
            vec![survivor.clone()]
        );
        assert_eq!(
            store.get_collection(&collection.id).unwrap().id,
            collection.id
        );
        assert_eq!(
            store.read_alias("default").unwrap(),
            Some(collection.id.clone())
        );
        assert!(store.check_integrity().unwrap().is_healthy());
        assert!(!target_file.exists());
        assert_eq!(
            std::fs::read_dir(dir.path().join("secrets"))
                .unwrap()
                .count(),
            1
        );
        drop(store);
        let db = Database::open(dir.path().join("index.redb")).unwrap();
        {
            let txn = db.begin_read().unwrap();
            let table = txn.open_table(ITEMS).unwrap();
            assert!(table.get(target.id.as_str()).unwrap().is_none());
            assert_eq!(table.len().unwrap(), 1);
        }
        drop(db);
        let output = Command::new(env!("CARGO_BIN_EXE_noirpass"))
            .env_remove("NOIRPASS_STORE")
            .arg("--store-dir")
            .arg(dir.path())
            .args(["delete", &survivor.id, "--yes"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let db = Database::open(dir.path().join("index.redb")).unwrap();
        let txn = db.begin_read().unwrap();
        assert_eq!(txn.open_table(ITEMS).unwrap().len().unwrap(), 0);
        assert_eq!(
            std::fs::read_dir(dir.path().join("secrets"))
                .unwrap()
                .count(),
            0
        );
    }
}
