//! Initialization and recipient lifecycle preflight.

use std::fs::{self, Permissions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::filesystem::{Directory, validate_no_symlink_components};
use crate::gpg::{cert_to_binary, has_usable_encryption_key, parse_recipient_cert};
use crate::store::Store;
use sequoia_openpgp::Cert;

use super::format::{atomic_write_in, read_optional_in, restore_optional_in, validate_regular_in};
use super::status::load_configured_recipient_in;
use super::{
    CONFIG_VERSION, Config, DEFAULT_IDLE_EXIT_SECONDS, DIFFERENT_RECIPIENT_ERROR, INDEX_FILE,
    KEYS_DIR, RECIPIENT_REL, SECRETS_DIR,
};

fn has_encrypted_secret_files(root: &Directory) -> Result<bool> {
    let secrets_dir = Path::new(SECRETS_DIR);
    match root.metadata(secrets_dir) {
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

    let directory = root.child(secrets_dir)?;
    for entry in directory.read_dir()? {
        let entry = entry?;
        let path = secrets_dir.join(entry.file_name());
        if path.extension().is_some_and(|extension| extension == "gpg") {
            let metadata = directory.metadata(Path::new(&entry.file_name()))?;
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

fn reject_missing_index_for_initialized_store(root: &Directory) -> Result<()> {
    let index_path = Path::new(INDEX_FILE);
    validate_regular_in(root, index_path)?;
    let has_index = root.entry_exists(index_path)?;
    if has_index {
        root.open_regular(index_path, libc::O_RDWR, 0)?;
    }
    let initialized = root.entry_exists(Path::new(super::CONFIG_FILE))?
        || root.entry_exists(Path::new(RECIPIENT_REL))?;
    if initialized && !has_index {
        return Err(Error::Config(
            "cannot initialize an already initialized store because metadata database `index.redb` is missing; run `noirpass deinit` before initializing again".into(),
        ));
    }
    if has_index && !root.entry_exists(Path::new(super::CONFIG_FILE))? {
        return Err(Error::Config(
            "cannot initialize an already initialized store because `config.toml` is missing; run `noirpass deinit` before initializing again".into(),
        ));
    }
    Ok(())
}

fn parse_usable_recipient(bytes: &[u8]) -> Result<Cert> {
    let cert = parse_recipient_cert(bytes)?;
    if !has_usable_encryption_key(&cert) {
        return Err(Error::Config(
            "recipient certificate has no usable encryption-capable key".into(),
        ));
    }
    Ok(cert)
}

/// Claim one root for the CLI's complete initialization operation.
pub fn init_store_from_path(data_dir: &Path, path: &str) -> Result<Config> {
    init_store_with(data_dir, || {
        let mut bytes = Vec::new();
        if path == "-" {
            io::stdin().lock().read_to_end(&mut bytes)?;
        } else {
            fs::File::open(path)?.read_to_end(&mut bytes)?;
        }
        parse_usable_recipient(&bytes)
    })
}

pub(super) fn init_store_with(
    data_dir: &Path,
    read_recipient: impl FnOnce() -> Result<Cert>,
) -> Result<Config> {
    let root = super::open_lifecycle_directory(data_dir)?;
    let preopened = if root.entry_exists(Path::new(INDEX_FILE))? {
        Some(Store::open_existing_in(data_dir, &root)?)
    } else {
        None
    };
    let had_existing = preopened.is_some();
    let _lifecycle = super::LifecycleLock::acquire_in(&root)?;
    let store = if root.entry_exists(Path::new(INDEX_FILE))? {
        match preopened {
            Some(store) => Some(store),
            None => Some(Store::open_existing_in(data_dir, &root)?),
        }
    } else if had_existing {
        return Err(Error::Config(
            "store disappeared while acquiring lifecycle lock".into(),
        ));
    } else {
        None
    };
    let cert = read_recipient()?;
    let config = init_from_cert_in_with_hooks(
        data_dir,
        &root,
        &cert,
        |keys, bytes| atomic_write_in(keys, Path::new("recipient.pgp"), bytes, 0o600),
        || {},
    )?;
    let store = match store {
        Some(store) => store,
        None => Store::open_in(data_dir, &root)?,
    };
    store.ensure_default()?;
    Ok(config)
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
    validate_no_symlink_components(data_dir)?;
    let cert = parse_usable_recipient(bytes)?;
    let root = super::open_lifecycle_directory(data_dir)?;
    init_from_cert_in_with_hooks(
        data_dir,
        &root,
        &cert,
        |keys, bytes| atomic_write_in(keys, Path::new("recipient.pgp"), bytes, 0o600),
        || {},
    )
}

pub(super) fn init_from_cert_in_with_hooks(
    data_dir: &Path,
    root: &Directory,
    cert: &Cert,
    write_certificate: impl FnOnce(&Directory, &[u8]) -> Result<()>,
    after_certificate: impl FnOnce(),
) -> Result<Config> {
    let new_fingerprint = cert.fingerprint().to_hex();
    reject_missing_index_for_initialized_store(root)?;
    let has_encrypted_files = has_encrypted_secret_files(root)?;

    if root.entry_exists(Path::new(super::CONFIG_FILE))? {
        let (_, _, existing_fingerprint) = load_configured_recipient_in(data_dir, root).map_err(|err| {
            Error::Config(format!(
                "cannot initialize an already initialized store because existing recipient fingerprint cannot be verified: {err}"
            ))
        })?;
        if existing_fingerprint != new_fingerprint {
            return Err(Error::Config(DIFFERENT_RECIPIENT_ERROR.into()));
        }
    } else if has_encrypted_files {
        let _existing = load_configured_recipient_in(data_dir, root).map_err(|err| {
            Error::Config(format!(
                "cannot initialize non-empty store because existing recipient fingerprint cannot be verified: {err}"
            ))
        })?;
    }

    let idle_exit =
        Config::load_in(root).map_or(DEFAULT_IDLE_EXIT_SECONDS, |config| config.idle_exit);

    // Create and pin keys beneath the already selected root. Keep both handles
    // through publication and rollback rather than reopening their pathnames.
    match root.metadata(Path::new(KEYS_DIR)) {
        Ok(metadata) if !metadata.is_dir() => {
            return Err(Error::Config(
                "keys path is not a directory; refusing symlink".into(),
            ));
        }
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    validate_regular_in(root, Path::new(RECIPIENT_REL))?;
    validate_regular_in(root, Path::new(super::CONFIG_FILE))?;
    root.set_permissions(Permissions::from_mode(0o700))?;
    let keys = root.create_child(Path::new(KEYS_DIR), 0o700)?;
    keys.set_permissions(Permissions::from_mode(0o700))?;
    let name = Path::new("recipient.pgp");
    let previous_cert = read_optional_in(&keys, name)?;
    let previous_config = read_optional_in(root, Path::new(super::CONFIG_FILE))?;
    let binary = cert_to_binary(cert)?;
    let config = Config {
        version: CONFIG_VERSION,
        recipient_fingerprint: new_fingerprint,
        recipient_cert: PathBuf::from(RECIPIENT_REL),
        idle_exit,
    };
    let mut configuration_attempted = false;
    let write_result = (|| -> Result<()> {
        write_certificate(&keys, &binary)?;
        after_certificate();
        let current = root.metadata(Path::new(KEYS_DIR))?;
        let owned = keys.metadata(Path::new("."))?;
        if (current.dev(), current.ino()) != (owned.dev(), owned.ino()) {
            return Err(Error::Config(
                "recipient directory changed during initialization".into(),
            ));
        }
        configuration_attempted = true;
        config.write_in(root)
    })();
    if let Err(err) = write_result {
        let certificate_restore = restore_optional_in(&keys, name, previous_cert.as_deref());
        let config_restore = if configuration_attempted {
            restore_optional_in(
                root,
                Path::new(super::CONFIG_FILE),
                previous_config.as_deref(),
            )
        } else {
            Ok(())
        };
        if certificate_restore.is_err() || config_restore.is_err() {
            return Err(Error::Config(format!(
                "failed to write config: {err}; certificate restoration: {certificate_restore:?}; configuration restoration: {config_restore:?}"
            )));
        }
        return Err(err);
    }
    Ok(config)
}
