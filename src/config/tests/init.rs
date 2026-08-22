use super::super::{
    Config, INDEX_FILE, KEYS_DIR, config_path, init_from_bytes, load_recipient,
    recipient_cert_path, status,
};
use super::support::generated_recipient;
use crate::gpg::test_support::TestGnupg;
use crate::store::Store;
use sequoia_openpgp::cert::CertBuilder;
use sequoia_openpgp::serialize::Serialize;
use std::fs;
use std::os::unix::fs::symlink;

#[test]
fn init_imports_armored_recipient_cert() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let config = init_from_bytes(tmp.path(), &gnupg.export_public_armored()).unwrap();

    assert_eq!(config.recipient_fingerprint, gnupg.fingerprint());
    assert!(config_path(tmp.path()).exists());
    assert!(recipient_cert_path(tmp.path()).exists());
    assert!(load_recipient(tmp.path()).is_ok());
}

#[test]
fn init_imports_binary_recipient_cert() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let config = init_from_bytes(tmp.path(), &gnupg.export_public_binary()).unwrap();

    assert_eq!(config.recipient_fingerprint, gnupg.fingerprint());
    assert!(load_recipient(tmp.path()).is_ok());
}

#[test]
fn fresh_generated_recipient_init_and_existing_store_work() {
    let (recipient, fingerprint) = generated_recipient();
    let tmp = tempfile::tempdir().unwrap();

    let config = init_from_bytes(tmp.path(), &recipient).unwrap();
    assert_eq!(config.recipient_fingerprint, fingerprint);
    let store = Store::open(tmp.path()).unwrap();
    store.ensure_default().unwrap();
    drop(store);

    assert!(Store::open_existing(tmp.path()).is_ok());
    assert!(load_recipient(tmp.path()).is_ok());
    assert!(status(tmp.path()).usable());
}

#[test]
fn init_rejects_symlinked_keys_before_writing() {
    let (recipient, _) = generated_recipient();
    let tmp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let outside_marker = outside.path().join("keep.txt");
    fs::write(&outside_marker, b"outside").unwrap();
    symlink(outside.path(), tmp.path().join(KEYS_DIR)).unwrap();

    let err = init_from_bytes(tmp.path(), &recipient).unwrap_err();

    assert!(err.to_string().contains("symlink"));
    assert!(!config_path(tmp.path()).exists());
    assert!(!tmp.path().join(INDEX_FILE).exists());
    assert_eq!(fs::read(outside_marker).unwrap(), b"outside");
    assert!(
        fs::symlink_metadata(tmp.path().join(KEYS_DIR))
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn symlinked_config_is_rejected_without_reading_target() {
    let (recipient, fingerprint) = generated_recipient();
    let tmp = tempfile::tempdir().unwrap();
    drop(Store::open(tmp.path()).unwrap());
    let outside = tempfile::tempdir().unwrap();
    let outside_config = outside.path().join("config.toml");
    fs::write(
            &outside_config,
            format!(
                "version = 1\nrecipient_fingerprint = \"{fingerprint}\"\nrecipient_cert = \"keys/recipient.pgp\"\n"
            ),
        )
        .unwrap();
    symlink(&outside_config, config_path(tmp.path())).unwrap();
    let outside_before = fs::read(&outside_config).unwrap();

    assert!(Config::load(tmp.path()).is_err());
    let err = init_from_bytes(tmp.path(), &recipient).unwrap_err();
    let status = status(tmp.path());

    assert!(err.to_string().contains("existing recipient fingerprint"));
    assert!(!status.usable());
    assert_eq!(fs::read(&outside_config).unwrap(), outside_before);
    assert!(
        fs::symlink_metadata(config_path(tmp.path()))
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn symlinked_recipient_is_rejected_by_load_and_status() {
    let (recipient, _) = generated_recipient();
    let tmp = tempfile::tempdir().unwrap();
    init_from_bytes(tmp.path(), &recipient).unwrap();
    drop(Store::open(tmp.path()).unwrap());
    let outside = tempfile::tempdir().unwrap();
    let outside_cert = outside.path().join("recipient.pgp");
    fs::write(&outside_cert, &recipient).unwrap();
    let outside_before = fs::read(&outside_cert).unwrap();
    fs::remove_file(recipient_cert_path(tmp.path())).unwrap();
    symlink(&outside_cert, recipient_cert_path(tmp.path())).unwrap();

    assert!(load_recipient(tmp.path()).is_err());
    let status = status(tmp.path());

    assert!(!status.usable());
    assert_eq!(fs::read(&outside_cert).unwrap(), outside_before);
    assert!(
        fs::symlink_metadata(recipient_cert_path(tmp.path()))
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn configured_recipient_path_component_symlink_is_rejected() {
    let (recipient, fingerprint) = generated_recipient();
    let tmp = tempfile::tempdir().unwrap();
    drop(Store::open(tmp.path()).unwrap());
    let outside = tempfile::tempdir().unwrap();
    let outside_cert = outside.path().join("recipient.pgp");
    fs::write(&outside_cert, &recipient).unwrap();
    let outside_before = fs::read(&outside_cert).unwrap();
    symlink(outside.path(), tmp.path().join("linked")).unwrap();
    fs::write(
            config_path(tmp.path()),
            format!(
                "version = 1\nrecipient_fingerprint = \"{fingerprint}\"\nrecipient_cert = \"linked/recipient.pgp\"\n"
            ),
        )
        .unwrap();

    assert!(load_recipient(tmp.path()).is_err());
    assert!(!status(tmp.path()).usable());
    assert_eq!(fs::read(outside_cert).unwrap(), outside_before);
}

#[test]
fn init_rejects_invalid_openpgp_input() {
    let tmp = tempfile::tempdir().unwrap();
    let err = init_from_bytes(tmp.path(), b"not openpgp").unwrap_err();
    assert!(err.to_string().contains("openpgp"));
}

#[test]
fn init_rejects_cert_without_encryption_capability() {
    let (cert, _) = CertBuilder::new()
        .add_userid("sign-only")
        .generate()
        .unwrap();
    let mut bytes = Vec::new();
    cert.serialize(&mut bytes).unwrap();
    let tmp = tempfile::tempdir().unwrap();

    let err = init_from_bytes(tmp.path(), &bytes).unwrap_err();
    assert!(err.to_string().contains("no usable encryption"));
}
