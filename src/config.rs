//! Persistent noirpass configuration, recipient lifecycle, and deinitialization.

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
        validate_idle_exit(self.idle_exit)?;
        fs::create_dir_all(data_dir)?;
        fs::set_permissions(data_dir, fs::Permissions::from_mode(0o700))?;

        let mut doc = DocumentMut::new();
        doc["version"] = value(self.version);
        doc["recipient_fingerprint"] = value(self.recipient_fingerprint.as_str());
        doc["recipient_cert"] = value(self.recipient_cert.to_string_lossy().as_ref());
        doc["idle_exit"] = value(self.idle_exit);
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
                fs::File::open(parent)?.sync_all()?;
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
    let secrets_dir = data_dir.join(SECRETS_DIR);
    match fs::symlink_metadata(&secrets_dir) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(Error::Config(format!(
                "cannot initialize with symlinked secrets path: {}",
                secrets_dir.display()
            )));
        }
        Ok(metadata) if !metadata.is_dir() => {
            return Err(Error::Config(format!(
                "cannot initialize with non-directory secrets path: {}",
                secrets_dir.display()
            )));
        }
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(Error::Io(err)),
    }

    for entry in fs::read_dir(&secrets_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_some_and(|extension| extension == "gpg") {
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                return Err(Error::Config(format!(
                    "cannot initialize with symlinked possible ciphertext: {}",
                    path.display()
                )));
            }
            if !metadata.is_file() {
                return Err(Error::Config(format!(
                    "cannot initialize with unsupported possible ciphertext path: {}",
                    path.display()
                )));
            }
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
    let has_encrypted_files = has_encrypted_secret_files(data_dir)?;

    if config_path(data_dir).exists() {
        let (_, _, existing_fingerprint) = load_configured_recipient(data_dir).map_err(|err| {
            Error::Config(format!(
                "cannot initialize an already initialized store because existing recipient fingerprint cannot be verified: {err}"
            ))
        })?;
        if existing_fingerprint != new_fingerprint {
            return Err(Error::Config(DIFFERENT_RECIPIENT_ERROR.into()));
        }
    } else if has_encrypted_files {
        let _existing = load_recipient(data_dir).map_err(|err| {
            Error::Config(format!(
                "cannot initialize non-empty store because existing recipient fingerprint cannot be verified: {err}"
            ))
        })?;
    }

    let idle_exit =
        Config::load(data_dir).map_or(DEFAULT_IDLE_EXIT_SECONDS, |config| config.idle_exit);

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
        idle_exit,
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

fn is_lower_hex(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn is_canonical_secret_name(name: &str) -> bool {
    name.strip_suffix(".gpg")
        .is_some_and(|id| id.len() == 32 && is_lower_hex(id.as_bytes()))
}

fn is_recovery_secret_name(name: &str) -> bool {
    RECOVERY_KINDS.iter().any(|kind| {
        let prefix = format!(".noirpass-{kind}-");
        let Some(rest) = name.strip_prefix(&prefix) else {
            return false;
        };
        let Some((id, suffix)) = rest.split_once('-') else {
            return false;
        };
        suffix.strip_suffix(".gpg").is_some_and(|token| {
            id.len() == 32
                && is_lower_hex(id.as_bytes())
                && token.len() == 16
                && token.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    })
}

fn is_config_temporary_name(name: &str) -> bool {
    name.strip_prefix(".noirpass-tmp-").is_some_and(|token| {
        token.len() == 16 && token.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn existing_directory(path: &Path, description: &str) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(Error::Config(format!(
            "cannot deinitialize {description} at {}; refusing to follow symlink",
            path.display()
        ))),
        Ok(metadata) if !metadata.is_dir() => Err(Error::Config(format!(
            "cannot deinitialize {description} at {}; expected a directory",
            path.display()
        ))),
        Ok(_) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err.into()),
    }
}

fn safe_relative_path(data_dir: &Path, relative: &Path, description: &str) -> Result<PathBuf> {
    validate_recipient_cert_path(relative)?;
    let component_count = relative.components().count();
    let mut path = data_dir.to_path_buf();
    for (index, component) in relative.components().enumerate() {
        let Component::Normal(name) = component else {
            return Err(Error::Config(format!(
                "cannot deinitialize {description}; path is not relative to the noirpass store"
            )));
        };
        path.push(name);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(Error::Config(format!(
                    "cannot deinitialize {description} at {}; refusing to follow symlink",
                    path.display()
                )));
            }
            Ok(metadata) if index + 1 < component_count && !metadata.is_dir() => {
                return Err(Error::Config(format!(
                    "cannot deinitialize {description} at {}; expected a directory",
                    path.display()
                )));
            }
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => break,
            Err(err) => return Err(err.into()),
        }
    }
    Ok(path)
}

fn checked_owned_file(
    data_dir: &Path,
    relative: &Path,
    description: &str,
) -> Result<Option<PathBuf>> {
    let path = safe_relative_path(data_dir, relative, description)?;
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(Error::Config(format!(
            "cannot deinitialize {description} at {}; refusing to follow symlink",
            path.display()
        ))),
        Ok(metadata) if !metadata.is_file() => Err(Error::Config(format!(
            "cannot deinitialize {description} at {}; expected a regular file",
            path.display()
        ))),
        Ok(_) => Ok(Some(path)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err.into()),
    }
}

fn remove_owned_file(data_dir: &Path, relative: &Path, description: &str) -> Result<()> {
    if let Some(path) = checked_owned_file(data_dir, relative, description)? {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn remove_empty_directory(data_dir: &Path, relative: &Path, description: &str) -> Result<()> {
    let path = safe_relative_path(data_dir, relative, description)?;
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(Error::Config(format!(
            "cannot deinitialize {description} at {}; refusing to follow symlink",
            path.display()
        ))),
        Ok(metadata) if !metadata.is_dir() => Err(Error::Config(format!(
            "cannot deinitialize {description} at {}; expected a directory",
            path.display()
        ))),
        Ok(_) => match fs::remove_dir(&path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::DirectoryNotEmpty => Ok(()),
            Err(err) => Err(err.into()),
        },
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn remove_known_secret_files(data_dir: &Path) -> Result<()> {
    let secrets = data_dir.join(SECRETS_DIR);
    if !existing_directory(&secrets, "the secrets directory")? {
        return Ok(());
    }
    for entry in fs::read_dir(&secrets)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if is_canonical_secret_name(&name) || is_recovery_secret_name(&name) {
            remove_owned_file(
                data_dir,
                &Path::new(SECRETS_DIR).join(&name),
                "a known secret file",
            )?;
        }
    }
    fs::File::open(&secrets)?.sync_all()?;
    remove_empty_directory(data_dir, Path::new(SECRETS_DIR), "the secrets directory")
}

fn remove_config_temporary_files_in(
    data_dir: &Path,
    directory: &Path,
    relative_directory: &Path,
) -> Result<()> {
    if !existing_directory(directory, "a configuration temporary-file directory")? {
        return Ok(());
    }
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if is_config_temporary_name(&name) {
            remove_owned_file(
                data_dir,
                &relative_directory.join(&name),
                "a known configuration temporary file",
            )?;
        }
    }
    Ok(())
}

fn load_deinit_config(data_dir: &Path) -> Result<Option<Config>> {
    let path = config_path(data_dir);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(Error::Config(format!(
            "cannot deinitialize configuration at {}; refusing to follow symlink",
            path.display()
        ))),
        Ok(metadata) if !metadata.is_file() => Err(Error::Config(format!(
            "cannot deinitialize configuration at {}; expected a regular file",
            path.display()
        ))),
        Ok(_) => Ok(Some(parse_config(&fs::read_to_string(path)?)?)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err.into()),
    }
}

fn preflight_known_secret_files(data_dir: &Path) -> Result<()> {
    let secrets = data_dir.join(SECRETS_DIR);
    if !existing_directory(&secrets, "the secrets directory")? {
        return Ok(());
    }
    for entry in fs::read_dir(&secrets)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if is_canonical_secret_name(&name) || is_recovery_secret_name(&name) {
            checked_owned_file(
                data_dir,
                &Path::new(SECRETS_DIR).join(&name),
                "a known secret file",
            )?;
        }
    }
    Ok(())
}

fn preflight_deinit(data_dir: &Path, recipient_rel: &Path) -> Result<()> {
    checked_owned_file(data_dir, recipient_rel, "the recipient certificate")?;
    checked_owned_file(data_dir, Path::new(INDEX_FILE), "the metadata database")?;
    checked_owned_file(data_dir, Path::new(CONFIG_FILE), "the configuration")?;
    preflight_known_secret_files(data_dir)?;
    remove_config_temporary_files_in(data_dir, data_dir, Path::new(""))?;
    remove_config_temporary_files_in(data_dir, &data_dir.join(KEYS_DIR), Path::new(KEYS_DIR))?;
    Ok(())
}

fn open_complete_store(data_dir: &Path) -> Result<Option<Store>> {
    let has_index =
        checked_owned_file(data_dir, Path::new(INDEX_FILE), "the metadata database")?.is_some();
    let has_secrets = existing_directory(&data_dir.join(SECRETS_DIR), "the secrets directory")?;
    if has_index && has_secrets {
        Ok(Some(Store::open_existing(data_dir)?))
    } else {
        Ok(None)
    }
}

/// Remove Noirpass-owned state without following symlinks or touching unknown files.
pub fn deinit(data_dir: &Path) -> Result<()> {
    if !existing_directory(data_dir, "the selected store")? {
        return Ok(());
    }

    let config = load_deinit_config(data_dir)?;
    let recipient_rel = config.as_ref().map_or_else(
        || PathBuf::from(RECIPIENT_REL),
        |config| config.recipient_cert.clone(),
    );
    preflight_deinit(data_dir, &recipient_rel)?;
    let _store_guard = open_complete_store(data_dir)?;

    remove_owned_file(data_dir, &recipient_rel, "the recipient certificate")?;
    remove_known_secret_files(data_dir)?;
    remove_owned_file(data_dir, Path::new(INDEX_FILE), "the metadata database")?;
    remove_config_temporary_files_in(data_dir, data_dir, Path::new(""))?;
    remove_config_temporary_files_in(data_dir, &data_dir.join(KEYS_DIR), Path::new(KEYS_DIR))?;
    remove_empty_directory(data_dir, Path::new(KEYS_DIR), "the keys directory")?;
    remove_owned_file(data_dir, Path::new(CONFIG_FILE), "the configuration")?;
    fs::File::open(data_dir)?.sync_all()?;
    Ok(())
}

fn load_configured_recipient(data_dir: &Path) -> Result<(Config, Cert, String)> {
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
    Ok((config, cert, actual))
}

/// Load config and recipient certificate, validating consistency and key usability.
pub fn load_recipient(data_dir: &Path) -> Result<Recipient> {
    let (_, cert, fingerprint) = load_configured_recipient(data_dir)?;
    if !has_usable_encryption_key(&cert) {
        return Err(Error::Config(
            "recipient certificate has no usable encryption-capable key".into(),
        ));
    }
    Ok(Recipient { cert, fingerprint })
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

fn validate_idle_exit(idle_exit: i64) -> Result<()> {
    if idle_exit < -1 {
        return Err(Error::Config(
            "config.toml `idle_exit` must be -1 or greater".into(),
        ));
    }
    Ok(())
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
    let idle_exit = doc
        .get("idle_exit")
        .map(|item| {
            item.as_integer()
                .ok_or_else(|| Error::Config("config.toml `idle_exit` must be an integer".into()))
        })
        .transpose()?
        .unwrap_or(DEFAULT_IDLE_EXIT_SECONDS);
    validate_idle_exit(idle_exit)?;
    Ok(Config {
        version,
        recipient_fingerprint,
        recipient_cert,
        idle_exit,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gpg::test_support::TestGnupg;
    use sequoia_openpgp::cert::CertBuilder;
    use sequoia_openpgp::serialize::Serialize;

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
    fn reinit_preserves_configured_idle_exit() {
        let gnupg = TestGnupg::new();

        for idle_exit in [-1, 600] {
            let tmp = tempfile::tempdir().unwrap();
            let mut config = init_from_bytes(tmp.path(), &gnupg.export_public_binary()).unwrap();
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
