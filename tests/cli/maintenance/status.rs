use std::collections::HashMap;
use std::fs;
use std::process::Command;

use noirpass::store::Store;

use crate::common::{export_public_cert, init_noirpass_store, setup_gnupg};

#[test]
fn cli_status_rejects_missing_ciphertext_without_repairing() {
    let gnupg = tempfile::tempdir().unwrap();
    setup_gnupg(gnupg.path());
    let cert = export_public_cert(gnupg.path());
    let dir = tempfile::tempdir().unwrap();
    init_noirpass_store(dir.path(), &cert);

    let store = Store::open(dir.path()).unwrap();
    let collection = store.ensure_default().unwrap();
    let item = store
        .create_or_replace_item(
            &collection.id,
            "missing ciphertext",
            HashMap::new(),
            "text/plain",
            b"ciphertext",
            false,
        )
        .unwrap()
        .0;
    drop(store);

    let index_before = fs::read(dir.path().join("index.redb")).unwrap();
    let ciphertext = dir.path().join(format!("secrets/{}.gpg", item.id));
    fs::remove_file(&ciphertext).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .env_remove("NOIRPASS_STORE")
        .arg("--store-dir")
        .arg(dir.path())
        .arg("status")
        .env("GNUPGHOME", gnupg.path())
        .output()
        .expect("spawn noirpass status with missing ciphertext");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("store integrity"));
    assert_eq!(
        fs::read(dir.path().join("index.redb")).unwrap(),
        index_before
    );
    assert!(!ciphertext.exists());
}
