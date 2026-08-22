//! Persistent noirpass configuration, recipient lifecycle, and deinitialization.

use std::path::PathBuf;

use sequoia_openpgp::Cert;

const CONFIG_FILE: &str = "config.toml";
const INDEX_FILE: &str = "index.redb";
const KEYS_DIR: &str = "keys";
const RECIPIENT_REL: &str = "keys/recipient.pgp";
const SECRETS_DIR: &str = "secrets";
const CONFIG_VERSION: i64 = 1;
const RECOVERY_KINDS: [&str; 4] = ["create", "update", "quarantine", "backup"];
/// Default daemon inactivity timeout in seconds.
pub const DEFAULT_IDLE_EXIT_SECONDS: i64 = 300;
const INIT_HINT: &str = "run noirpass init --recipient ...";
const DIFFERENT_RECIPIENT_ERROR: &str = "Noirpass is initialized with a different recipient.\n\nChanging recipient requires deleting the existing Noirpass store first.\n\nRun:\n    noirpass deinit\n\nThen run init again with the new recipient.";

mod deinit;
mod format;
mod init;
mod status;

pub use deinit::deinit;
pub use format::{config_path, recipient_cert_path};
pub use init::{init_from_bytes, init_from_path, init_from_reader};
pub use status::{load_recipient, status};

/// Minimal persisted config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Config format version.
    pub version: i64,
    /// Expected primary fingerprint of the recipient certificate.
    pub recipient_fingerprint: String,
    /// Relative path to the stored binary recipient certificate.
    pub recipient_cert: PathBuf,
    /// Daemon inactivity timeout in seconds; zero exits after activity, -1 disables idle exit.
    pub idle_exit: i64,
}

/// Full recipient material loaded from disk.
#[derive(Debug)]
pub struct Recipient {
    /// Parsed `OpenPGP` certificate.
    pub cert: Cert,
    /// Fingerprint configured in `config.toml`.
    pub fingerprint: String,
}

/// Status details printed by `noirpass status`.
#[derive(Debug)]
pub struct Status {
    /// Store/config root.
    pub data_dir: PathBuf,
    /// `config.toml` exists.
    pub config_present: bool,
    /// Config parsed successfully.
    pub config_valid: bool,
    /// Stored cert file exists.
    pub recipient_cert_present: bool,
    /// Configured fingerprint, if readable.
    pub configured_fingerprint: Option<String>,
    /// Actual cert fingerprint, if readable.
    pub actual_fingerprint: Option<String>,
    /// Configured and actual fingerprints match.
    pub fingerprint_matches: Option<bool>,
    /// Cert has at least one usable encryption key.
    pub cert_has_encryption_key: Option<bool>,
    /// Actionable errors.
    pub errors: Vec<String>,
}

impl Status {
    /// Store usable by daemon.
    #[must_use]
    pub fn usable(&self) -> bool {
        self.errors.is_empty()
            && self.config_present
            && self.config_valid
            && self.recipient_cert_present
            && self.fingerprint_matches == Some(true)
            && self.cert_has_encryption_key == Some(true)
    }
}

#[cfg(test)]
mod tests {
    use super::format::parse_config;
    use super::*;
    use crate::gpg::{parse_recipient_cert, test_support::TestGnupg};
    use crate::store::{ItemMeta, Store};
    use redb::{Database, TableDefinition};
    use sequoia_openpgp::cert::CertBuilder;
    use sequoia_openpgp::serialize::Serialize;
    use std::collections::HashMap;
    use std::fs;
    use std::os::unix::fs::symlink;

    fn generated_recipient() -> (Vec<u8>, String) {
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

    fn initialized_store_with_item() -> (tempfile::TempDir, ItemMeta) {
        let (cert, _) = CertBuilder::new()
            .add_userid("status-integrity")
            .add_storage_encryption_subkey()
            .generate()
            .unwrap();
        let mut cert_bytes = Vec::new();
        cert.serialize(&mut cert_bytes).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        Store::open(tmp.path()).unwrap().ensure_default().unwrap();
        init_from_bytes(tmp.path(), &cert_bytes).unwrap();
        let store = Store::open(tmp.path()).unwrap();
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

    fn assert_status_rejects_integrity_defect(tmp: &tempfile::TempDir) {
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

    #[test]
    fn status_reports_healthy_integrity_store() {
        let (tmp, _) = initialized_store_with_item();

        let status = status(tmp.path());

        assert!(status.usable(), "{status:?}");
    }

    #[test]
    fn config_idle_exit_defaults_and_accepts_override() {
        let base = "version = 1\nrecipient_fingerprint = \"fingerprint\"\nrecipient_cert = \"keys/recipient.pgp\"\n";

        assert_eq!(
            parse_config(base).unwrap().idle_exit,
            DEFAULT_IDLE_EXIT_SECONDS
        );
        assert_eq!(
            parse_config(&format!("{base}idle_exit = 42\n"))
                .unwrap()
                .idle_exit,
            42
        );
    }

    #[test]
    fn generated_config_idle_exit_matches_parser_fallback() {
        let gnupg = TestGnupg::new();
        let tmp = tempfile::tempdir().unwrap();
        init_from_bytes(tmp.path(), &gnupg.export_public_binary()).unwrap();
        let generated = fs::read_to_string(config_path(tmp.path())).unwrap();
        assert!(generated.contains(&format!("idle_exit = {DEFAULT_IDLE_EXIT_SECONDS}")));
        let without_idle_exit = generated
            .lines()
            .filter(|line| !line.starts_with("idle_exit = "))
            .collect::<Vec<_>>()
            .join("\n");

        assert_eq!(
            Config::load(tmp.path()).unwrap().idle_exit,
            parse_config(&without_idle_exit).unwrap().idle_exit
        );
    }

    #[test]
    fn config_idle_exit_accepts_minus_one_and_rejects_lower_values() {
        let base = "version = 1\nrecipient_fingerprint = \"fingerprint\"\nrecipient_cert = \"keys/recipient.pgp\"\n";

        assert_eq!(
            parse_config(&format!("{base}idle_exit = -1\n"))
                .unwrap()
                .idle_exit,
            -1
        );
        let err = parse_config(&format!("{base}idle_exit = -2\n")).unwrap_err();
        assert!(err.to_string().contains("must be -1 or greater"));
    }

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
        Store::open(tmp.path()).unwrap().ensure_default().unwrap();
        init_from_bytes(tmp.path(), &recipient).unwrap();
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
    fn status_rejects_symlinked_index_without_reading_target() {
        let (recipient, _) = generated_recipient();
        let tmp = tempfile::tempdir().unwrap();
        Store::open(tmp.path()).unwrap().ensure_default().unwrap();
        init_from_bytes(tmp.path(), &recipient).unwrap();
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
    fn deinit_removes_known_state_and_preserves_unknown_files() {
        let gnupg = TestGnupg::new();
        let tmp = tempfile::tempdir().unwrap();
        init_from_bytes(tmp.path(), &gnupg.export_public_binary()).unwrap();

        let item_id = "0123456789abcdef0123456789abcdef";
        let recovery = format!(".noirpass-create-{item_id}-0123456789abcdef.gpg");
        drop(Store::open(tmp.path()).unwrap());
        fs::create_dir_all(tmp.path().join(SECRETS_DIR)).unwrap();
        fs::write(
            tmp.path().join(SECRETS_DIR).join(format!("{item_id}.gpg")),
            b"secret",
        )
        .unwrap();
        fs::write(tmp.path().join(SECRETS_DIR).join(recovery), b"recovery").unwrap();
        fs::write(tmp.path().join(SECRETS_DIR).join("keep.txt"), b"unrelated").unwrap();
        fs::write(
            tmp.path()
                .join(KEYS_DIR)
                .join(".noirpass-tmp-0123456789abcdef"),
            b"temporary",
        )
        .unwrap();
        fs::write(
            tmp.path().join(".noirpass-tmp-0123456789abcdef"),
            b"temporary",
        )
        .unwrap();
        fs::write(tmp.path().join("keep.txt"), b"unrelated").unwrap();

        deinit(tmp.path()).unwrap();

        assert!(!config_path(tmp.path()).exists());
        assert!(!recipient_cert_path(tmp.path()).exists());
        assert!(!tmp.path().join("index.redb").exists());
        assert!(
            !tmp.path()
                .join(SECRETS_DIR)
                .join(format!("{item_id}.gpg"))
                .exists()
        );
        assert!(
            !tmp.path()
                .join(SECRETS_DIR)
                .join(format!(".noirpass-create-{item_id}-0123456789abcdef.gpg"))
                .exists()
        );
        assert!(tmp.path().join(SECRETS_DIR).join("keep.txt").exists());
        assert!(tmp.path().join("keep.txt").exists());
        assert!(
            !tmp.path()
                .join(KEYS_DIR)
                .join(".noirpass-tmp-0123456789abcdef")
                .exists()
        );
        assert!(!tmp.path().join(".noirpass-tmp-0123456789abcdef").exists());
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

        let err = init_from_bytes(tmp.path(), &two.export_public_binary()).unwrap_err();

        assert!(
            err.to_string()
                .contains("Noirpass is initialized with a different recipient")
        );
        assert!(err.to_string().contains("noirpass deinit"));
        assert_eq!(fs::read(config_path(tmp.path())).unwrap(), old_config);
        assert_eq!(fs::read(recipient_cert_path(tmp.path())).unwrap(), old_cert);
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
        let stored =
            parse_recipient_cert(&fs::read(recipient_cert_path(tmp.path())).unwrap()).unwrap();
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

        assert!(
            err.to_string()
                .contains("cannot initialize non-empty store")
        );
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
        Store::open(tmp.path()).unwrap().ensure_default().unwrap();
        init_from_bytes(tmp.path(), &gnupg.export_public_binary()).unwrap();

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
        Store::open(tmp.path()).unwrap().ensure_default().unwrap();
        init_from_bytes(tmp.path(), &gnupg.export_public_binary()).unwrap();
        fs::write(tmp.path().join("index.redb"), b"not a database").unwrap();

        let status = status(tmp.path());
        assert!(!status.usable());
        assert!(status.errors.iter().any(|e| e.contains("store integrity")));
    }

    #[test]
    fn status_detects_broken_secrets_dir() {
        let gnupg = TestGnupg::new();
        let tmp = tempfile::tempdir().unwrap();
        Store::open(tmp.path()).unwrap().ensure_default().unwrap();
        init_from_bytes(tmp.path(), &gnupg.export_public_binary()).unwrap();
        fs::remove_dir(tmp.path().join("secrets")).unwrap();
        fs::write(tmp.path().join("secrets"), b"not a dir").unwrap();

        let status = status(tmp.path());
        assert!(!status.usable());
        assert!(status.errors.iter().any(|e| e.contains("store integrity")));
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

        let stored =
            parse_recipient_cert(&fs::read(recipient_cert_path(tmp.path())).unwrap()).unwrap();
        assert_eq!(stored.fingerprint().to_hex(), one.fingerprint());
    }
}
