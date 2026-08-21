//! Initialization and recipient lifecycle preflight.

use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::gpg::{cert_to_binary, has_usable_encryption_key, parse_recipient_cert};

use super::format::{
    atomic_write, config_path, read_optional, recipient_cert_path, restore_recipient_cert,
};
use super::status::{load_configured_recipient, load_recipient};
use super::{
    CONFIG_VERSION, Config, DEFAULT_IDLE_EXIT_SECONDS, DIFFERENT_RECIPIENT_ERROR, INDEX_FILE,
    KEYS_DIR, RECIPIENT_REL, SECRETS_DIR,
};

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

fn path_entry_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err.into()),
    }
}

fn reject_missing_index_for_initialized_store(data_dir: &Path) -> Result<()> {
    let initialized = path_entry_exists(&config_path(data_dir))?
        || path_entry_exists(&recipient_cert_path(data_dir))?;
    if initialized && !path_entry_exists(&data_dir.join(INDEX_FILE))? {
        return Err(Error::Config(
            "cannot initialize an already initialized store because metadata database `index.redb` is missing; run `noirpass deinit` before initializing again".into(),
        ));
    }
    Ok(())
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
    reject_missing_index_for_initialized_store(data_dir)?;
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
