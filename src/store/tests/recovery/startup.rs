use super::super::*;

#[test]
fn startup_recovery_removes_valid_staged_files() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let create = store
        .stage_secret_file(id, b"create", RecoveryKind::Create)
        .unwrap();
    let update = store
        .stage_secret_file(id, b"update", RecoveryKind::Update)
        .unwrap();

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
