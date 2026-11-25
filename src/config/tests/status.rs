use super::super::{INDEX_FILE, config_path, init_from_bytes, recipient_cert_path, status};
use super::support::{
    assert_status_rejects_integrity_defect, generated_recipient, initialized_store_with_item,
};
use crate::gpg::test_support::TestGnupg;
use crate::store::Store;
use redb::{Database, TableDefinition};
use std::fs;
use std::os::unix::fs::symlink;

#[test]
fn status_reports_healthy_integrity_store() {
    let (tmp, _) = initialized_store_with_item();

    let status = status(tmp.path());

    assert!(status.usable(), "{status:?}");
}

#[test]
fn status_reports_uninitialized_store() {
    let tmp = tempfile::tempdir().unwrap();
    let status = status(tmp.path());

    assert!(!status.usable());
    assert!(!status.config_present);
    assert!(
        status
            .errors
            .iter()
            .any(|e| e.contains("run noirpass init"))
    );
}

#[test]
fn status_reports_usable_initialized_store() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    init_from_bytes(tmp.path(), &gnupg.export_public_binary()).unwrap();
    Store::open(tmp.path()).unwrap().ensure_default().unwrap();

    let status = status(tmp.path());
    assert!(status.usable(), "{:?}", status.errors);
    assert_eq!(
        status.configured_fingerprint.as_deref(),
        Some(gnupg.fingerprint())
    );
    assert_eq!(
        status.actual_fingerprint.as_deref(),
        Some(gnupg.fingerprint())
    );
}

#[test]
fn status_rejects_missing_ciphertext() {
    let (tmp, item) = initialized_store_with_item();
    let index_before = fs::read(tmp.path().join("index.redb")).unwrap();
    let config_before = fs::read(config_path(tmp.path())).unwrap();
    fs::remove_file(tmp.path().join(format!("secrets/{}.gpg", item.id))).unwrap();
    let secrets_before = fs::read_dir(tmp.path().join("secrets"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();

    assert_status_rejects_integrity_defect(&tmp);

    assert_eq!(
        fs::read(tmp.path().join("index.redb")).unwrap(),
        index_before
    );
    assert_eq!(fs::read(config_path(tmp.path())).unwrap(), config_before);
    let mut secrets_after = fs::read_dir(tmp.path().join("secrets"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    let mut secrets_before = secrets_before;
    secrets_before.sort();
    secrets_after.sort();
    assert_eq!(secrets_after, secrets_before);
}

#[test]
fn status_rejects_ciphertext_digest_mismatch() {
    let (tmp, item) = initialized_store_with_item();
    fs::write(
        tmp.path().join(format!("secrets/{}.gpg", item.id)),
        b"wrong ciphertext",
    )
    .unwrap();

    assert_status_rejects_integrity_defect(&tmp);
}

#[test]
fn status_rejects_corrupt_item_metadata() {
    const ITEMS: TableDefinition<&str, &[u8]> = TableDefinition::new("items");
    let (tmp, item) = initialized_store_with_item();
    let db = Database::open(tmp.path().join("index.redb")).unwrap();
    let txn = db.begin_write().unwrap();
    {
        let mut items = txn.open_table(ITEMS).unwrap();
        items
            .insert(item.id.as_str(), b"not-json".as_slice())
            .unwrap();
    }
    txn.commit().unwrap();
    drop(db);

    assert_status_rejects_integrity_defect(&tmp);
}

#[test]
fn status_rejects_broken_alias() {
    const ALIASES: TableDefinition<&str, &str> = TableDefinition::new("aliases");
    let (tmp, _) = initialized_store_with_item();
    let db = Database::open(tmp.path().join("index.redb")).unwrap();
    let txn = db.begin_write().unwrap();
    {
        let mut aliases = txn.open_table(ALIASES).unwrap();
        aliases.insert("broken", "missing-collection").unwrap();
    }
    txn.commit().unwrap();
    drop(db);

    assert_status_rejects_integrity_defect(&tmp);
}

#[test]
fn status_rejects_symlinked_index_without_reading_target() {
    let (recipient, _) = generated_recipient();
    let tmp = tempfile::tempdir().unwrap();
    init_from_bytes(tmp.path(), &recipient).unwrap();
    drop(Store::open(tmp.path()).unwrap());
    let outside = tempfile::tempdir().unwrap();
    let outside_index = outside.path().join(INDEX_FILE);
    drop(Store::open(outside.path()).unwrap());
    let outside_before = fs::read(&outside_index).unwrap();
    fs::remove_file(tmp.path().join(INDEX_FILE)).unwrap();
    symlink(&outside_index, tmp.path().join(INDEX_FILE)).unwrap();

    let status = status(tmp.path());

    assert!(!status.usable());
    assert!(
        status
            .errors
            .iter()
            .any(|error| error.contains("integrity"))
    );
    assert_eq!(fs::read(outside_index).unwrap(), outside_before);
}

#[test]
fn status_rejects_unsupported_config_version() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    init_from_bytes(tmp.path(), &gnupg.export_public_binary()).unwrap();
    fs::write(
            config_path(tmp.path()),
            format!(
                "version = 99\nrecipient_fingerprint = \"{}\"\nrecipient_cert = \"keys/recipient.pgp\"\n",
                gnupg.fingerprint()
            ),
        )
        .unwrap();

    let status = status(tmp.path());
    assert!(!status.usable());
    assert!(
        status
            .errors
            .iter()
            .any(|e| e.contains("unsupported config version"))
    );
}

#[test]
fn status_detects_missing_recipient_cert() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    init_from_bytes(tmp.path(), &gnupg.export_public_binary()).unwrap();
    fs::remove_file(recipient_cert_path(tmp.path())).unwrap();

    let status = status(tmp.path());
    assert!(!status.usable());
    assert!(
        status
            .errors
            .iter()
            .any(|e| e.contains("recipient certificate missing"))
    );
}

#[test]
fn status_detects_fingerprint_mismatch() {
    let one = TestGnupg::new();
    let two = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    init_from_bytes(tmp.path(), &one.export_public_binary()).unwrap();
    fs::write(recipient_cert_path(tmp.path()), two.export_public_binary()).unwrap();

    let status = status(tmp.path());
    assert!(!status.usable());
    assert!(
        status
            .errors
            .iter()
            .any(|e| e.contains("fingerprint mismatch"))
    );
}

#[test]
fn status_detects_corrupted_index() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    init_from_bytes(tmp.path(), &gnupg.export_public_binary()).unwrap();
    drop(Store::open(tmp.path()).unwrap());
    fs::write(tmp.path().join("index.redb"), b"not a database").unwrap();

    let status = status(tmp.path());
    assert!(!status.usable());
    assert!(status.errors.iter().any(|e| e.contains("store integrity")));
}

#[test]
fn status_detects_broken_secrets_dir() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    init_from_bytes(tmp.path(), &gnupg.export_public_binary()).unwrap();
    drop(Store::open(tmp.path()).unwrap());
    fs::remove_dir(tmp.path().join("secrets")).unwrap();
    fs::write(tmp.path().join("secrets"), b"not a dir").unwrap();

    let status = status(tmp.path());
    assert!(!status.usable());
    assert!(status.errors.iter().any(|e| e.contains("store integrity")));
}

#[test]
fn status_succeeds_with_readonly_index_file() {
    use std::os::unix::fs::PermissionsExt;

    let (tmp, _) = initialized_store_with_item();
    let index = tmp.path().join(INDEX_FILE);
    fs::set_permissions(&index, fs::Permissions::from_mode(0o400)).unwrap();

    let (status, cert) = super::super::status_with_recipient(tmp.path());
    // Restore write mode before tempdir drop.
    fs::set_permissions(&index, fs::Permissions::from_mode(0o600)).unwrap();

    assert!(status.usable(), "{status:?}");
    assert!(cert.is_some());
}
