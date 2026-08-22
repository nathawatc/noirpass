use super::super::{init_from_bytes, status};
use crate::store::{ItemMeta, Store};
use sequoia_openpgp::cert::CertBuilder;
use sequoia_openpgp::serialize::Serialize;
use std::collections::HashMap;

pub(super) fn generated_recipient() -> (Vec<u8>, String) {
    let (cert, _) = CertBuilder::new()
        .add_userid("symlink regression")
        .add_storage_encryption_subkey()
        .generate()
        .unwrap();
    let fingerprint = cert.fingerprint().to_hex();
    let mut bytes = Vec::new();
    cert.serialize(&mut bytes).unwrap();
    (bytes, fingerprint)
}

pub(super) fn initialized_store_with_item() -> (tempfile::TempDir, ItemMeta) {
    let (cert, _) = CertBuilder::new()
        .add_userid("status-integrity")
        .add_storage_encryption_subkey()
        .generate()
        .unwrap();
    let mut cert_bytes = Vec::new();
    cert.serialize(&mut cert_bytes).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    init_from_bytes(tmp.path(), &cert_bytes).unwrap();
    let store = Store::open(tmp.path()).unwrap();
    store.ensure_default().unwrap();
    let item = store
        .create_item(
            "default",
            "status item",
            HashMap::new(),
            "text/plain",
            b"ciphertext",
        )
        .unwrap();
    drop(store);
    (tmp, item)
}

pub(super) fn assert_status_rejects_integrity_defect(tmp: &tempfile::TempDir) {
    let status = status(tmp.path());
    assert!(!status.usable(), "{status:?}");
    assert!(
        status
            .errors
            .iter()
            .any(|error| error.contains("store integrity")),
        "{:?}",
        status.errors
    );
}
