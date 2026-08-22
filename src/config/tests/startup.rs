use super::super::{config_path, init_from_bytes, load_recipient, recipient_cert_path};
use crate::gpg::test_support::TestGnupg;
use std::fs;

#[test]
fn startup_loads_recipient_from_config_without_gpg_binary() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    init_from_bytes(tmp.path(), &gnupg.export_public_binary()).unwrap();

    let recipient = load_recipient(tmp.path()).unwrap();
    assert_eq!(recipient.fingerprint, gnupg.fingerprint());
}

#[test]
fn startup_fails_clearly_when_not_initialized() {
    let tmp = tempfile::tempdir().unwrap();
    let err = load_recipient(tmp.path()).unwrap_err();
    assert!(err.to_string().contains("run noirpass init --recipient"));
}

#[test]
fn startup_rejects_missing_recipient_cert() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    init_from_bytes(tmp.path(), &gnupg.export_public_binary()).unwrap();
    fs::remove_file(recipient_cert_path(tmp.path())).unwrap();

    let err = load_recipient(tmp.path()).unwrap_err();
    assert!(err.to_string().contains("recipient certificate missing"));
}

#[test]
fn startup_rejects_fingerprint_mismatch() {
    let one = TestGnupg::new();
    let two = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    init_from_bytes(tmp.path(), &one.export_public_binary()).unwrap();
    fs::write(recipient_cert_path(tmp.path()), two.export_public_binary()).unwrap();

    let err = load_recipient(tmp.path()).unwrap_err();
    assert!(err.to_string().contains("fingerprint mismatch"));
}

#[test]
fn startup_rejects_recipient_path_outside_store() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        config_path(tmp.path()),
        format!(
            "version = 1\nrecipient_fingerprint = \"{}\"\nrecipient_cert = \"../escape.pgp\"\n",
            gnupg.fingerprint()
        ),
    )
    .unwrap();

    let err = load_recipient(tmp.path()).unwrap_err();
    assert!(
        err.to_string()
            .contains("path must stay inside noirpass data directory")
    );
}
