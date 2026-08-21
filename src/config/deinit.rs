//! Safe removal of Noirpass-owned configuration and store files.

use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

use super::format::{config_path, parse_config, validate_recipient_cert_path};
use super::{
    CONFIG_FILE, Config, INDEX_FILE, KEYS_DIR, RECIPIENT_REL, RECOVERY_KINDS, SECRETS_DIR,
};
use crate::error::{Error, Result};
use crate::store::Store;

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
