use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use std::process::{Output, Stdio};

use crate::common::noirpass_command;

use noirpass::store::{ItemMeta, Store};
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};

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

    let listed = noirpass_command()
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

    let checked = noirpass_command()
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

    let deleted = noirpass_command()
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
    assert_eq!(store.search_items(&HashMap::new()).unwrap().len(), 0);
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

    let listed = noirpass_command()
        .arg("--store-dir")
        .arg(dir.path())
        .arg("list")
        .output()
        .expect("spawn noirpass list");
    assert!(
        !listed.status.success(),
        "list must reject mismatched item ids"
    );

    let deleted = noirpass_command()
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
        store.read_item_secret(&valid_b.id).unwrap().1,
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

    let checked = noirpass_command()
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

    let checked = noirpass_command()
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
        store.read_item_secret(&item.id).unwrap().1,
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
        let output = noirpass_command()
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
        let output = noirpass_command()
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

#[test]
fn cli_list_checks_ciphertext_presence_without_full_integrity_scan() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let collection = store.ensure_default().unwrap();
    let item = store
        .create_or_replace_item(
            &collection.id,
            "present",
            HashMap::new(),
            "text/plain",
            b"original ciphertext",
            false,
        )
        .unwrap()
        .0;
    drop(store);
    // An unrelated directory in secrets/ would fail a full check_integrity scan,
    // but `list` only checks presence of indexed items' ciphertext files.
    std::fs::create_dir(dir.path().join("secrets").join("unrelated.gpg")).unwrap();

    let listed = noirpass_command()
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
    assert!(stdout.contains(&item.id));
    assert!(stdout.contains("ciphertext: present"));
}

fn run_cli_tty(store: &Path, args: &[&str], input: &[u8]) -> Output {
    let (mut master, slave) = crate::deinit::pty::open_pty();
    let child = noirpass_command()
        .arg("--store-dir")
        .arg(store)
        .args(args)
        .stdin(Stdio::from(slave))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    master.write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    drop(master);
    output
}

#[test]
fn cli_check_reports_healthy_store() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let collection = store.ensure_default().unwrap();
    store
        .create_or_replace_item(
            &collection.id,
            "healthy",
            HashMap::new(),
            "text/plain",
            b"healthy-ciphertext",
            false,
        )
        .unwrap();
    drop(store);

    let checked = noirpass_command()
        .arg("--store-dir")
        .arg(dir.path())
        .arg("check")
        .stdin(Stdio::null())
        .output()
        .expect("spawn noirpass check");
    assert!(
        checked.status.success(),
        "check failed: stdout={} stderr={}",
        String::from_utf8_lossy(&checked.stdout),
        String::from_utf8_lossy(&checked.stderr)
    );
    assert!(String::from_utf8_lossy(&checked.stdout).contains("store health: ok"));
}

#[test]
fn cli_check_repairs_corrupt_alias_and_requires_tty_without_yes() {
    const ALIASES: TableDefinition<&str, &str> = TableDefinition::new("aliases");
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    store.ensure_default().unwrap();
    drop(store);

    let db = Database::open(dir.path().join("index.redb")).unwrap();
    let txn = db.begin_write().unwrap();
    {
        let mut aliases = txn.open_table(ALIASES).unwrap();
        aliases.insert("dangling", "missing_collection").unwrap();
    }
    txn.commit().unwrap();
    drop(db);

    let non_tty = noirpass_command()
        .arg("--store-dir")
        .arg(dir.path())
        .arg("check")
        .stdin(Stdio::null())
        .output()
        .expect("spawn noirpass check without tty");
    assert!(!non_tty.status.success());
    let non_tty_stderr = String::from_utf8_lossy(&non_tty.stderr);
    assert!(
        non_tty_stderr
            .contains("corrupt alias: dangling targets missing collection missing_collection"),
        "stderr was: {non_tty_stderr}"
    );
    assert!(
        non_tty_stderr.contains("interactive confirmation requires a terminal"),
        "stderr was: {non_tty_stderr}"
    );
    let db = Database::open(dir.path().join("index.redb")).unwrap();
    {
        let txn = db.begin_read().unwrap();
        let aliases = txn.open_table(ALIASES).unwrap();
        assert_eq!(
            aliases
                .get("dangling")
                .unwrap()
                .map(|v| v.value().to_string()),
            Some("missing_collection".to_string())
        );
    }
    drop(db);

    let repaired = noirpass_command()
        .arg("--store-dir")
        .arg(dir.path())
        .args(["check", "--yes"])
        .output()
        .expect("spawn noirpass check --yes");
    assert!(
        repaired.status.success(),
        "check --yes failed: stdout={} stderr={}",
        String::from_utf8_lossy(&repaired.stdout),
        String::from_utf8_lossy(&repaired.stderr)
    );
    let repaired_stdout = String::from_utf8_lossy(&repaired.stdout);
    assert!(repaired_stdout.contains("deleted corrupt alias: dangling"));
    assert!(repaired_stdout.contains("store health: repaired"));
    let store = Store::open_existing(dir.path()).unwrap();
    assert!(store.check_integrity().unwrap().is_healthy());
}

#[test]
fn cli_check_declined_repair_exits_nonzero() {
    let declined_dir = tempfile::tempdir().unwrap();
    let store = Store::open(declined_dir.path()).unwrap();
    let collection = store.ensure_default().unwrap();
    let item = store
        .create_or_replace_item(
            &collection.id,
            "missing-secret",
            HashMap::new(),
            "text/plain",
            b"ciphertext",
            false,
        )
        .unwrap()
        .0;
    std::fs::remove_file(
        declined_dir
            .path()
            .join("secrets")
            .join(format!("{}.gpg", item.id)),
    )
    .unwrap();
    drop(store);

    let declined = run_cli_tty(declined_dir.path(), &["check"], b"n\n");
    assert!(!declined.status.success());
    let declined_stderr = String::from_utf8_lossy(&declined.stderr);
    assert!(
        declined_stderr.contains("missing ciphertext:"),
        "{declined_stderr}"
    );
    assert!(
        declined_stderr.contains("1 repair declined"),
        "{declined_stderr}"
    );
    let store = Store::open_existing(declined_dir.path()).unwrap();
    assert!(store.get_item(&item.id).is_ok());
}

#[test]
fn cli_check_unrepairable_defects_exit_nonzero() {
    const COLLECTIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("collections");
    const ITEMS: TableDefinition<&str, &[u8]> = TableDefinition::new("items");
    const ALIASES: TableDefinition<&str, &str> = TableDefinition::new("aliases");

    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let collection = store.ensure_default().unwrap();
    let mismatch_item = store
        .create_or_replace_item(
            &collection.id,
            "mismatch",
            HashMap::from([("kind".into(), "mismatch".into())]),
            "text/plain",
            b"original-ciphertext",
            false,
        )
        .unwrap()
        .0;
    let bad_col_item = store
        .create_or_replace_item(
            &collection.id,
            "bad-collection-item",
            HashMap::from([("kind".into(), "bad-col".into())]),
            "text/plain",
            b"item-ciphertext",
            false,
        )
        .unwrap()
        .0;
    drop(store);

    std::fs::write(
        dir.path()
            .join("secrets")
            .join(format!("{}.gpg", mismatch_item.id)),
        b"tampered-ciphertext",
    )
    .unwrap();
    std::fs::write(dir.path().join("secrets").join("orphan.gpg"), b"orphan").unwrap();

    let invalid_col_meta = ItemMeta {
        collection: "missing_col".to_string(),
        ..bad_col_item
    };
    let invalid_col_bytes = serde_json::to_vec(&invalid_col_meta).unwrap();

    let db = Database::open(dir.path().join("index.redb")).unwrap();
    let txn = db.begin_write().unwrap();
    {
        let mut collections = txn.open_table(COLLECTIONS).unwrap();
        collections
            .insert("bad_col", b"not-json".as_slice())
            .unwrap();
        let mut aliases = txn.open_table(ALIASES).unwrap();
        aliases.insert("bad_alias", "bad_col").unwrap();
        let mut items = txn.open_table(ITEMS).unwrap();
        items
            .insert(invalid_col_meta.id.as_str(), invalid_col_bytes.as_slice())
            .unwrap();
    }
    txn.commit().unwrap();
    drop(db);

    let output = noirpass_command()
        .arg("--store-dir")
        .arg(dir.path())
        .args(["check", "--yes"])
        .output()
        .expect("spawn noirpass check --yes");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    for expected in [
        "corrupt collection entry: bad_col",
        "ciphertext digest mismatch:",
        "item with invalid collection:",
        "alias with corrupt collection: bad_alias targets bad_col (kept)",
        "orphan ciphertext: orphan.gpg",
        "store health: needs attention",
    ] {
        assert!(
            stderr.contains(expected),
            "missing `{expected}` in {stderr}"
        );
    }

    let store = Store::open_existing(dir.path()).unwrap();
    let report = store.check_integrity().unwrap();
    assert_eq!(report.corrupt_collections.len(), 1);
    assert_eq!(report.ciphertext_mismatches.len(), 1);
    assert_eq!(report.items_with_invalid_collection.len(), 1);
    assert_eq!(report.aliases_with_corrupt_collection.len(), 1);
    assert_eq!(report.orphan_secret_files, vec!["orphan.gpg"]);
}

#[test]
fn cli_delete_declines_via_pty_and_requires_tty_without_yes() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let collection = store.ensure_default().unwrap();
    let item = store
        .create_or_replace_item(
            &collection.id,
            "interactive-delete",
            HashMap::new(),
            "text/plain",
            b"ciphertext",
            false,
        )
        .unwrap()
        .0;
    drop(store);

    let non_tty = noirpass_command()
        .arg("--store-dir")
        .arg(dir.path())
        .args(["delete", &item.id])
        .stdin(Stdio::null())
        .output()
        .expect("spawn noirpass delete without tty");
    assert!(!non_tty.status.success());
    assert!(
        String::from_utf8_lossy(&non_tty.stderr)
            .contains("interactive confirmation requires a terminal")
    );
    let store = Store::open_existing(dir.path()).unwrap();
    assert!(store.get_item(&item.id).is_ok());
    drop(store);

    let declined = run_cli_tty(dir.path(), &["delete", &item.id], b"n\n");
    assert!(
        declined.status.success(),
        "declined delete failed: stdout={} stderr={}",
        String::from_utf8_lossy(&declined.stdout),
        String::from_utf8_lossy(&declined.stderr)
    );
    assert!(
        String::from_utf8_lossy(&declined.stdout).contains(&format!("not deleted: {}", item.id))
    );
    let store = Store::open_existing(dir.path()).unwrap();
    assert!(store.get_item(&item.id).is_ok());
    drop(store);

    let accepted = run_cli_tty(dir.path(), &["delete", &item.id], b"y\n");
    assert!(
        accepted.status.success(),
        "accepted delete failed: stdout={} stderr={}",
        String::from_utf8_lossy(&accepted.stdout),
        String::from_utf8_lossy(&accepted.stderr)
    );
    assert!(String::from_utf8_lossy(&accepted.stdout).contains(&format!("deleted: {}", item.id)));
    let store = Store::open_existing(dir.path()).unwrap();
    assert!(matches!(
        store.get_item(&item.id),
        Err(noirpass::Error::NotFound(_))
    ));
}
