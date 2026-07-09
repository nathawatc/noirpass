//! Persistent noirpass configuration and recipient certificate import/status.

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use sequoia_openpgp::Cert;
use toml_edit::{DocumentMut, value};

use crate::error::{Error, Result};
use crate::gpg::{cert_to_binary, has_usable_encryption_key, parse_recipient_cert};
use crate::store::Store;

const CONFIG_FILE: &str = "config.toml";
const KEYS_DIR: &str = "keys";
const RECIPIENT_REL: &str = "keys/recipient.pgp";
const CONFIG_VERSION: i64 = 1;
const INIT_HINT: &str = "run noirpass init --recipient ...";

/// Minimal persisted config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Config format version.
    pub version: i64,
    /// Expected primary fingerprint of the recipient certificate.
    pub recipient_fingerprint: String,
    /// Relative path to the stored binary recipient certificate.
    pub recipient_cert: PathBuf,
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

impl Config {
    /// Load `config.toml`.
    pub fn load(data_dir: &Path) -> Result<Self> {
        let text = fs::read_to_string(config_path(data_dir)).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                Error::Config(format!("noirpass is not initialized; {INIT_HINT}"))
            } else {
                Error::Io(e)
            }
        })?;
        parse_config(&text)
    }

    /// Write `config.toml`.
    pub fn write(&self, data_dir: &Path) -> Result<()> {
        validate_recipient_cert_path(&self.recipient_cert)?;
        fs::create_dir_all(data_dir)?;
        fs::set_permissions(data_dir, fs::Permissions::from_mode(0o700))?;

        let mut doc = DocumentMut::new();
        doc["version"] = value(self.version);
        doc["recipient_fingerprint"] = value(self.recipient_fingerprint.as_str());
        doc["recipient_cert"] = value(self.recipient_cert.to_string_lossy().as_ref());
        let text = doc.to_string();
        atomic_write(&config_path(data_dir), text.as_bytes(), 0o600)?;
        Ok(())
    }
}

/// Path to `config.toml`.
#[must_use]
pub fn config_path(data_dir: &Path) -> PathBuf {
    data_dir.join(CONFIG_FILE)
}

/// Path to stored recipient certificate.
#[must_use]
pub fn recipient_cert_path(data_dir: &Path) -> PathBuf {
    data_dir.join(RECIPIENT_REL)
}

fn validate_recipient_cert_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(Error::Config(
            "config.toml has invalid `recipient_cert`; path must stay inside noirpass data directory"
                .into(),
        ));
    }
    Ok(())
}

fn recipient_cert_path_from_config(data_dir: &Path, path: &Path) -> Result<PathBuf> {
    validate_recipient_cert_path(path)?;
    Ok(data_dir.join(path))
}

fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        Error::Config(format!(
            "cannot determine parent directory for {}",
            path.display()
        ))
    })?;
    for _ in 0..16 {
        let tmp = parent.join(format!(".noirpass-tmp-{:016x}", rand::random::<u64>()));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)
        {
            Ok(mut file) => {
                let write_result = (|| -> io::Result<()> {
                    file.write_all(bytes)?;
                    file.sync_all()?;
                    Ok(())
                })();
                if let Err(err) = write_result {
                    let _ = fs::remove_file(&tmp);
                    return Err(Error::Io(err));
                }
                if let Err(err) = fs::rename(&tmp, path) {
                    let _ = fs::remove_file(&tmp);
                    return Err(Error::Io(err));
                }
                return Ok(());
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
            Err(err) => return Err(Error::Io(err)),
        }
    }
    Err(Error::Config(format!(
        "failed to create temporary file for {}",
        path.display()
    )))
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(Error::Io(err)),
    }
}

fn restore_recipient_cert(path: &Path, previous: Option<&[u8]>) -> Result<()> {
    if let Some(bytes) = previous {
        atomic_write(path, bytes, 0o600)
    } else {
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(Error::Io(err)),
        }
    }
}

fn has_encrypted_secret_files(data_dir: &Path) -> Result<bool> {
    let secrets_dir = data_dir.join("secrets");
    let entries = match fs::read_dir(&secrets_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(Error::Io(err)),
    };
    for entry in entries {
        let entry = entry?;
        if entry.file_type()?.is_file()
            && entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "gpg")
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Import an armored or binary recipient cert from `reader`.
pub fn init_from_reader(data_dir: &Path, mut reader: impl Read) -> Result<Config> {
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    init_from_bytes(data_dir, &bytes)
}

/// Import an armored or binary recipient cert from `path`, or stdin for `-`.
pub fn init_from_path(data_dir: &Path, path: &str) -> Result<Config> {
    if path == "-" {
        init_from_reader(data_dir, io::stdin().lock())
    } else {
        init_from_reader(data_dir, fs::File::open(path)?)
    }
}

/// Import an armored or binary recipient cert from bytes.
pub fn init_from_bytes(data_dir: &Path, bytes: &[u8]) -> Result<Config> {
    let cert = parse_recipient_cert(bytes)?;
    if !has_usable_encryption_key(&cert) {
        return Err(Error::Config(
            "recipient certificate has no usable encryption-capable key".into(),
        ));
    }
    let new_fingerprint = cert.fingerprint().to_hex();

    if has_encrypted_secret_files(data_dir)? {
        let existing = load_recipient(data_dir).map_err(|err| {
            Error::Config(format!(
                "cannot initialize non-empty store because existing recipient fingerprint cannot be verified: {err}"
            ))
        })?;
        if existing.fingerprint != new_fingerprint {
            return Err(Error::Config(
                "recipient rotation on a non-empty store is unsafe; migrate or re-encrypt existing secrets first"
                    .into(),
            ));
        }
    }

    fs::create_dir_all(data_dir.join(KEYS_DIR))?;
    fs::set_permissions(data_dir, fs::Permissions::from_mode(0o700))?;
    fs::set_permissions(data_dir.join(KEYS_DIR), fs::Permissions::from_mode(0o700))?;

    let cert_path = recipient_cert_path(data_dir);
    let previous_cert = read_optional(&cert_path)?;
    let binary = cert_to_binary(&cert)?;
    atomic_write(&cert_path, &binary, 0o600)?;

    let config = Config {
        version: CONFIG_VERSION,
        recipient_fingerprint: new_fingerprint,
        recipient_cert: PathBuf::from(RECIPIENT_REL),
    };
    if let Err(err) = config.write(data_dir) {
        if let Err(restore_err) = restore_recipient_cert(&cert_path, previous_cert.as_deref()) {
            return Err(Error::Config(format!(
                "failed to write config: {err}; failed to restore previous recipient cert: {restore_err}"
            )));
        }
        return Err(err);
    }
    Ok(config)
}

/// Load config and recipient certificate, validating consistency.
pub fn load_recipient(data_dir: &Path) -> Result<Recipient> {
    let config = Config::load(data_dir)?;
    if config.version != CONFIG_VERSION {
        return Err(Error::Config(format!(
            "unsupported config version {}; expected {CONFIG_VERSION}",
            config.version
        )));
    }

    let path = recipient_cert_path_from_config(data_dir, &config.recipient_cert)?;
    let bytes = fs::read(&path).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            Error::Config(format!(
                "recipient certificate missing at {}; {INIT_HINT}",
                path.display()
            ))
        } else {
            Error::Io(e)
        }
    })?;
    let cert = parse_recipient_cert(&bytes)?;
    let actual = cert.fingerprint().to_hex();
    if actual != config.recipient_fingerprint {
        return Err(Error::Config(format!(
            "recipient fingerprint mismatch: config has {}, cert has {}",
            config.recipient_fingerprint, actual
        )));
    }
    if !has_usable_encryption_key(&cert) {
        return Err(Error::Config(
            "recipient certificate has no usable encryption-capable key".into(),
        ));
    }
    Ok(Recipient {
        cert,
        fingerprint: actual,
    })
}

/// Compute status without mutating store.
#[must_use]
pub fn status(data_dir: &Path) -> Status {
    let mut out = Status {
        data_dir: data_dir.to_path_buf(),
        config_present: config_path(data_dir).exists(),
        config_valid: false,
        recipient_cert_present: false,
        configured_fingerprint: None,
        actual_fingerprint: None,
        fingerprint_matches: None,
        cert_has_encryption_key: None,
        errors: Vec::new(),
    };

    let config = match Config::load(data_dir) {
        Ok(config) => {
            out.config_valid = true;
            out.configured_fingerprint = Some(config.recipient_fingerprint.clone());
            if config.version != CONFIG_VERSION {
                out.errors.push(format!(
                    "unsupported config version {}; expected {CONFIG_VERSION}",
                    config.version
                ));
            }
            Some(config)
        }
        Err(err) => {
            out.errors.push(err.to_string());
            None
        }
    };

    if let Some(config) = config {
        match recipient_cert_path_from_config(data_dir, &config.recipient_cert) {
            Ok(cert_path) => {
                out.recipient_cert_present = cert_path.exists();
                match fs::read(&cert_path) {
                    Ok(bytes) => match parse_recipient_cert(&bytes) {
                        Ok(cert) => {
                            let actual = cert.fingerprint().to_hex();
                            let has_key = has_usable_encryption_key(&cert);
                            out.actual_fingerprint = Some(actual.clone());
                            out.fingerprint_matches = Some(actual == config.recipient_fingerprint);
                            out.cert_has_encryption_key = Some(has_key);
                            if out.fingerprint_matches != Some(true) {
                                out.errors.push(format!(
                                    "recipient fingerprint mismatch: config has {}, cert has {}",
                                    config.recipient_fingerprint, actual
                                ));
                            }
                            if !has_key {
                                out.errors.push(
                                    "recipient certificate has no usable encryption-capable key"
                                        .into(),
                                );
                            }
                        }
                        Err(err) => out.errors.push(err.to_string()),
                    },
                    Err(err) if err.kind() == io::ErrorKind::NotFound => out.errors.push(format!(
                        "recipient certificate missing at {}",
                        cert_path.display()
                    )),
                    Err(err) => out.errors.push(err.to_string()),
                }
            }
            Err(err) => out.errors.push(err.to_string()),
        }
    }

    if out.config_valid
        && out.recipient_cert_present
        && out.fingerprint_matches == Some(true)
        && out.cert_has_encryption_key == Some(true)
        && let Err(err) = Store::probe_health(data_dir)
    {
        out.errors.push(format!("store is not usable: {err}"));
    }

    out
}

fn parse_config(text: &str) -> Result<Config> {
    let doc = text
        .parse::<DocumentMut>()
        .map_err(|e| Error::Config(format!("invalid config.toml: {e}")))?;
    let version = doc
        .get("version")
        .and_then(toml_edit::Item::as_integer)
        .ok_or_else(|| Error::Config("config.toml missing integer `version`".into()))?;
    let recipient_fingerprint = doc
        .get("recipient_fingerprint")
        .and_then(toml_edit::Item::as_str)
        .ok_or_else(|| Error::Config("config.toml missing string `recipient_fingerprint`".into()))?
        .to_string();
    let recipient_cert = doc
        .get("recipient_cert")
        .and_then(toml_edit::Item::as_str)
        .ok_or_else(|| Error::Config("config.toml missing string `recipient_cert`".into()))?;
    let recipient_cert = PathBuf::from(recipient_cert);
    validate_recipient_cert_path(&recipient_cert)?;
    Ok(Config {
        version,
        recipient_fingerprint,
        recipient_cert,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gpg::test_support::TestGnupg;
    use sequoia_openpgp::cert::CertBuilder;
    use sequoia_openpgp::serialize::Serialize;

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
    fn reinit_same_recipient_succeeds_with_existing_secret_files() {
        let gnupg = TestGnupg::new();
        let tmp = tempfile::tempdir().unwrap();
        init_from_bytes(tmp.path(), &gnupg.export_public_binary()).unwrap();
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
    fn reinit_different_recipient_succeeds_when_store_has_no_secret_files() {
        let one = TestGnupg::new();
        let two = TestGnupg::new();
        let tmp = tempfile::tempdir().unwrap();
        init_from_bytes(tmp.path(), &one.export_public_binary()).unwrap();

        let config = init_from_bytes(tmp.path(), &two.export_public_binary()).unwrap();

        assert_eq!(config.recipient_fingerprint, two.fingerprint());
        assert_eq!(
            load_recipient(tmp.path()).unwrap().fingerprint,
            two.fingerprint()
        );
    }

    #[test]
    fn reinit_different_recipient_fails_with_existing_secret_files() {
        let one = TestGnupg::new();
        let two = TestGnupg::new();
        let tmp = tempfile::tempdir().unwrap();
        init_from_bytes(tmp.path(), &one.export_public_binary()).unwrap();
        fs::create_dir_all(tmp.path().join("secrets")).unwrap();
        fs::write(tmp.path().join("secrets/existing.gpg"), b"ciphertext").unwrap();

        let err = init_from_bytes(tmp.path(), &two.export_public_binary()).unwrap_err();

        assert!(err.to_string().contains("recipient rotation"));
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
        fs::create_dir_all(tmp.path().join("secrets")).unwrap();
        fs::write(tmp.path().join("secrets/existing.gpg"), b"ciphertext").unwrap();
        let old_cert = fs::read(recipient_cert_path(tmp.path())).unwrap();
        fs::write(config_path(tmp.path()), "not toml").unwrap();

        let err = init_from_bytes(tmp.path(), &two.export_public_binary()).unwrap_err();

        assert!(
            err.to_string()
                .contains("cannot initialize non-empty store")
        );
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
        assert!(
            status
                .errors
                .iter()
                .any(|e| e.contains("store is not usable"))
        );
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
        assert!(
            status
                .errors
                .iter()
                .any(|e| e.contains("store is not usable"))
        );
    }

    #[test]
    fn reinit_preserves_existing_cert_when_config_write_fails() {
        let one = TestGnupg::new();
        let two = TestGnupg::new();
        let tmp = tempfile::tempdir().unwrap();
        init_from_bytes(tmp.path(), &one.export_public_binary()).unwrap();

        fs::remove_file(config_path(tmp.path())).unwrap();
        fs::create_dir(config_path(tmp.path())).unwrap();

        let _err = init_from_bytes(tmp.path(), &two.export_public_binary()).unwrap_err();

        let stored =
            parse_recipient_cert(&fs::read(recipient_cert_path(tmp.path())).unwrap()).unwrap();
        assert_eq!(stored.fingerprint().to_hex(), one.fingerprint());
    }
}
