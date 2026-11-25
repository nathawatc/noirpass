use super::super::{
    Config, DEFAULT_IDLE_EXIT_SECONDS, INDEX_FILE, config_path, init_from_bytes, load_recipient,
    recipient_cert_path,
};
use crate::gpg::{parse_recipient, test_support::TestGnupg};
use crate::store::Store;
use sequoia_openpgp::cert::CertBuilder;
use sequoia_openpgp::serialize::Serialize;
use std::fs;

#[test]
fn reinit_preserves_configured_idle_exit() {
    let gnupg = TestGnupg::new();

    for idle_exit in [-1, 600] {
        let tmp = tempfile::tempdir().unwrap();
        let mut config = init_from_bytes(tmp.path(), &gnupg.export_public_binary()).unwrap();
        drop(Store::open(tmp.path()).unwrap());
        config.idle_exit = idle_exit;
        config.write(tmp.path()).unwrap();

        let reinitialized = init_from_bytes(tmp.path(), &gnupg.export_public_binary()).unwrap();

        assert_eq!(reinitialized.idle_exit, idle_exit);
        assert_eq!(Config::load(tmp.path()).unwrap().idle_exit, idle_exit);
    }
}

#[test]
fn reinit_config_without_idle_exit_uses_default() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    init_from_bytes(tmp.path(), &gnupg.export_public_binary()).unwrap();
    drop(Store::open(tmp.path()).unwrap());
    let path = config_path(tmp.path());
    let config = fs::read_to_string(&path)
        .unwrap()
        .lines()
        .filter(|line| !line.starts_with("idle_exit = "))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(path, config).unwrap();

    let reinitialized = init_from_bytes(tmp.path(), &gnupg.export_public_binary()).unwrap();

    assert_eq!(reinitialized.idle_exit, DEFAULT_IDLE_EXIT_SECONDS);
    assert_eq!(
        Config::load(tmp.path()).unwrap().idle_exit,
        DEFAULT_IDLE_EXIT_SECONDS
    );
}

#[test]
fn reinit_same_recipient_succeeds_with_existing_secret_files() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    init_from_bytes(tmp.path(), &gnupg.export_public_binary()).unwrap();
    drop(Store::open(tmp.path()).unwrap());
    fs::create_dir_all(tmp.path().join("secrets")).unwrap();
    fs::write(tmp.path().join("secrets/existing.gpg"), b"ciphertext").unwrap();

    let config = init_from_bytes(tmp.path(), &gnupg.export_public_binary()).unwrap();

    assert_eq!(config.recipient_fingerprint, gnupg.fingerprint());
    assert_eq!(
        load_recipient(tmp.path()).unwrap().fingerprint,
        gnupg.fingerprint()
    );
}

#[test]
fn reinit_rejects_existing_index_with_missing_config_before_writing() {
    let one = TestGnupg::new();
    let two = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    init_from_bytes(tmp.path(), &one.export_public_binary()).unwrap();
    drop(Store::open(tmp.path()).unwrap());
    let old_recipient = fs::read(recipient_cert_path(tmp.path())).unwrap();
    let old_index = fs::read(tmp.path().join(INDEX_FILE)).unwrap();
    fs::remove_file(config_path(tmp.path())).unwrap();

    let err = init_from_bytes(tmp.path(), &two.export_public_binary()).unwrap_err();

    let message = err.to_string();
    assert!(message.contains("config.toml"));
    assert!(message.contains("noirpass deinit"));
    assert!(!config_path(tmp.path()).exists());
    assert_eq!(
        fs::read(recipient_cert_path(tmp.path())).unwrap(),
        old_recipient
    );
    assert_eq!(fs::read(tmp.path().join(INDEX_FILE)).unwrap(), old_index);
}

#[test]
fn reinit_rejects_existing_index_with_missing_recipient_before_writing() {
    let one = TestGnupg::new();
    let two = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    init_from_bytes(tmp.path(), &one.export_public_binary()).unwrap();
    drop(Store::open(tmp.path()).unwrap());
    let old_config = fs::read(config_path(tmp.path())).unwrap();
    let old_index = fs::read(tmp.path().join(INDEX_FILE)).unwrap();
    fs::remove_file(recipient_cert_path(tmp.path())).unwrap();

    let err = init_from_bytes(tmp.path(), &two.export_public_binary()).unwrap_err();

    assert!(err.to_string().contains("cannot be verified"));
    assert_eq!(fs::read(config_path(tmp.path())).unwrap(), old_config);
    assert!(!recipient_cert_path(tmp.path()).exists());
    assert_eq!(fs::read(tmp.path().join(INDEX_FILE)).unwrap(), old_index);
}

#[test]
fn reinit_rejects_existing_index_with_corrupt_config_before_writing() {
    let one = TestGnupg::new();
    let two = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    init_from_bytes(tmp.path(), &one.export_public_binary()).unwrap();
    drop(Store::open(tmp.path()).unwrap());
    let old_recipient = fs::read(recipient_cert_path(tmp.path())).unwrap();
    let old_index = fs::read(tmp.path().join(INDEX_FILE)).unwrap();
    fs::write(config_path(tmp.path()), b"not toml").unwrap();

    let err = init_from_bytes(tmp.path(), &two.export_public_binary()).unwrap_err();

    let message = err.to_string();
    assert!(message.contains("already initialized store"));
    assert!(message.contains("cannot be verified"));
    assert_eq!(fs::read(config_path(tmp.path())).unwrap(), b"not toml");
    assert_eq!(
        fs::read(recipient_cert_path(tmp.path())).unwrap(),
        old_recipient
    );
    assert_eq!(fs::read(tmp.path().join(INDEX_FILE)).unwrap(), old_index);
}

#[test]
fn reinit_rejects_existing_index_with_corrupt_recipient_before_writing() {
    let one = TestGnupg::new();
    let two = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    init_from_bytes(tmp.path(), &one.export_public_binary()).unwrap();
    drop(Store::open(tmp.path()).unwrap());
    let old_config = fs::read(config_path(tmp.path())).unwrap();
    let old_index = fs::read(tmp.path().join(INDEX_FILE)).unwrap();
    fs::write(recipient_cert_path(tmp.path()), b"not openpgp").unwrap();

    let err = init_from_bytes(tmp.path(), &two.export_public_binary()).unwrap_err();

    assert!(err.to_string().contains("cannot be verified"));
    assert_eq!(fs::read(config_path(tmp.path())).unwrap(), old_config);
    assert_eq!(
        fs::read(recipient_cert_path(tmp.path())).unwrap(),
        b"not openpgp"
    );
    assert_eq!(fs::read(tmp.path().join(INDEX_FILE)).unwrap(), old_index);
}

#[test]
fn reinit_configured_store_fails_when_index_missing() {
    let (cert, _) = CertBuilder::new()
        .add_userid("missing-index")
        .add_storage_encryption_subkey()
        .generate()
        .unwrap();
    let mut bytes = Vec::new();
    cert.serialize(&mut bytes).unwrap();
    let tmp = tempfile::tempdir().unwrap();

    init_from_bytes(tmp.path(), &bytes).unwrap();
    drop(Store::open(tmp.path()).unwrap());
    let old_config = fs::read(config_path(tmp.path())).unwrap();
    let old_cert = fs::read(recipient_cert_path(tmp.path())).unwrap();
    fs::remove_file(tmp.path().join(INDEX_FILE)).unwrap();

    let err = init_from_bytes(tmp.path(), &bytes).unwrap_err();
    let message = err.to_string();
    assert!(message.contains("already initialized"));
    assert!(message.contains("index.redb"));
    assert!(!tmp.path().join(INDEX_FILE).exists());
    assert_eq!(fs::read(config_path(tmp.path())).unwrap(), old_config);
    assert_eq!(fs::read(recipient_cert_path(tmp.path())).unwrap(), old_cert);
}

#[test]
fn reinit_different_recipient_fails_even_when_store_has_no_secret_files() {
    let one = TestGnupg::new();
    let two = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    init_from_bytes(tmp.path(), &one.export_public_binary()).unwrap();
    drop(Store::open(tmp.path()).unwrap());
    let old_config = fs::read(config_path(tmp.path())).unwrap();
    let old_cert = fs::read(recipient_cert_path(tmp.path())).unwrap();
    let old_index = fs::read(tmp.path().join(INDEX_FILE)).unwrap();

    let err = init_from_bytes(tmp.path(), &two.export_public_binary()).unwrap_err();

    assert!(
        err.to_string()
            .contains("Noirpass is initialized with a different recipient")
    );
    assert!(err.to_string().contains("noirpass deinit"));
    assert_eq!(fs::read(config_path(tmp.path())).unwrap(), old_config);
    assert_eq!(fs::read(recipient_cert_path(tmp.path())).unwrap(), old_cert);
    assert_eq!(fs::read(tmp.path().join(INDEX_FILE)).unwrap(), old_index);
    assert_eq!(
        load_recipient(tmp.path()).unwrap().fingerprint,
        one.fingerprint()
    );
}

#[test]
fn reinit_different_recipient_fails_with_existing_secret_files() {
    let one = TestGnupg::new();
    let two = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    init_from_bytes(tmp.path(), &one.export_public_binary()).unwrap();
    drop(Store::open(tmp.path()).unwrap());
    fs::create_dir_all(tmp.path().join("secrets")).unwrap();
    fs::write(tmp.path().join("secrets/existing.gpg"), b"ciphertext").unwrap();

    let err = init_from_bytes(tmp.path(), &two.export_public_binary()).unwrap_err();

    assert!(
        err.to_string()
            .contains("Noirpass is initialized with a different recipient")
    );
    assert_eq!(
        load_recipient(tmp.path()).unwrap().fingerprint,
        one.fingerprint()
    );
    let stored = parse_recipient(&fs::read(recipient_cert_path(tmp.path())).unwrap()).unwrap();
    assert_eq!(stored.fingerprint().to_hex(), one.fingerprint());
}

#[test]
fn reinit_non_empty_store_fails_when_config_missing() {
    let one = TestGnupg::new();
    let two = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    init_from_bytes(tmp.path(), &one.export_public_binary()).unwrap();
    drop(Store::open(tmp.path()).unwrap());
    fs::create_dir_all(tmp.path().join("secrets")).unwrap();
    fs::write(tmp.path().join("secrets/existing.gpg"), b"ciphertext").unwrap();
    let old_cert = fs::read(recipient_cert_path(tmp.path())).unwrap();
    fs::remove_file(config_path(tmp.path())).unwrap();

    let err = init_from_bytes(tmp.path(), &two.export_public_binary()).unwrap_err();

    assert!(err.to_string().contains("config.toml"));
    assert!(err.to_string().contains("noirpass deinit"));
    assert!(!config_path(tmp.path()).exists());
    assert_eq!(fs::read(recipient_cert_path(tmp.path())).unwrap(), old_cert);
}

#[test]
fn reinit_non_empty_store_fails_when_config_corrupt() {
    let one = TestGnupg::new();
    let two = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    init_from_bytes(tmp.path(), &one.export_public_binary()).unwrap();
    drop(Store::open(tmp.path()).unwrap());
    fs::create_dir_all(tmp.path().join("secrets")).unwrap();
    fs::write(tmp.path().join("secrets/existing.gpg"), b"ciphertext").unwrap();
    let old_cert = fs::read(recipient_cert_path(tmp.path())).unwrap();
    fs::write(config_path(tmp.path()), "not toml").unwrap();

    let err = init_from_bytes(tmp.path(), &two.export_public_binary()).unwrap_err();

    let message = err.to_string();
    assert!(message.contains("already initialized store"));
    assert!(message.contains("existing recipient fingerprint cannot be verified"));
    assert_eq!(
        fs::read_to_string(config_path(tmp.path())).unwrap(),
        "not toml"
    );
    assert_eq!(fs::read(recipient_cert_path(tmp.path())).unwrap(), old_cert);
}

#[test]
fn reinit_preserves_existing_cert_when_config_write_fails() {
    let one = TestGnupg::new();
    let two = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    init_from_bytes(tmp.path(), &one.export_public_binary()).unwrap();
    drop(Store::open(tmp.path()).unwrap());

    fs::remove_file(config_path(tmp.path())).unwrap();
    fs::create_dir(config_path(tmp.path())).unwrap();

    let _err = init_from_bytes(tmp.path(), &two.export_public_binary()).unwrap_err();

    let stored = parse_recipient(&fs::read(recipient_cert_path(tmp.path())).unwrap()).unwrap();
    assert_eq!(stored.fingerprint().to_hex(), one.fingerprint());
}
