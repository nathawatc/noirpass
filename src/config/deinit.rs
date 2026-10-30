//! Safe removal of Noirpass-owned configuration and store files.

use std::fs;
use std::io::{self, Read};
use std::ops::Bound;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use super::format::{parse_config, validate_recipient_cert_path};
use super::{CONFIG_FILE, Config, INDEX_FILE, KEYS_DIR, RECIPIENT_REL, SECRETS_DIR};
use crate::error::{Error, Result};
use crate::filesystem::{Directory, validate_no_symlink_components};
use crate::store::{is_lower_hex, is_valid_item_id, parse_recovery_secret_name};
use redb::{StorageBackend, backends::FileBackend};

fn is_canonical_secret_name(name: &str) -> bool {
    name.strip_suffix(".gpg").is_some_and(is_valid_item_id)
}

fn is_recovery_secret_name(name: &str) -> bool {
    parse_recovery_secret_name(name).is_some()
}

fn is_config_temporary_name(name: &str) -> bool {
    name.strip_prefix(".noirpass-tmp-")
        .is_some_and(|token| is_lower_hex(token, 16))
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

// All relative lookups stay beneath the selected root or a pinned child.
fn checked_owned_file(directory: &Directory, relative: &Path, description: &str) -> Result<bool> {
    validate_recipient_cert_path(relative)?;
    match directory.metadata(relative) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(Error::Config(format!(
            "cannot deinitialize {description} at {}; refusing to follow symlink",
            relative.display()
        ))),
        Ok(metadata) if !metadata.is_file() => Err(Error::Config(format!(
            "cannot deinitialize {description} at {}; expected a regular file",
            relative.display()
        ))),
        Ok(_) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err.into()),
    }
}

fn optional_directory(directory: &Directory, relative: &Path) -> Result<Option<Directory>> {
    match directory.metadata(relative) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(Error::Config(format!(
            "cannot deinitialize directory at {}; refusing to follow symlink",
            relative.display()
        ))),
        Ok(metadata) if !metadata.is_dir() => Err(Error::Config(format!(
            "cannot deinitialize directory at {}; expected a directory",
            relative.display()
        ))),
        Ok(_) => Ok(Some(directory.child(relative)?)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err.into()),
    }
}

fn remove_owned_file(directory: &Directory, name: &Path, description: &str) -> Result<()> {
    if checked_owned_file(directory, name, description)? {
        directory.remove(name)?;
        directory.sync_all()?;
    }
    Ok(())
}

pub(super) fn remove_empty_directory(
    root: &Directory,
    directory: &Directory,
    name: &Path,
) -> Result<()> {
    let current = match root.metadata(name) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err.into()),
    };
    let owned = directory.metadata(Path::new("."))?;
    // A renamed child may have been replaced, even with another empty directory.
    // Only the child we inspected and emptied is eligible for removal.
    if (current.dev(), current.ino()) != (owned.dev(), owned.ino()) {
        return Ok(());
    }
    match root.remove_directory(name) {
        Ok(()) => Ok(()),
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::DirectoryNotEmpty
            ) =>
        {
            Ok(())
        }
        Err(err) => Err(err.into()),
    }
}

fn remove_known_secret_files(secrets: &Directory) -> Result<()> {
    for entry in secrets.read_dir()? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if is_canonical_secret_name(&name) || is_recovery_secret_name(&name) {
            remove_owned_file(secrets, Path::new(&name), "a known secret file")?;
        }
    }
    secrets.sync_all()?;
    Ok(())
}

fn remove_config_temporary_files_in(directory: &Directory) -> Result<()> {
    for entry in directory.read_dir()? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if is_config_temporary_name(&name) {
            remove_owned_file(
                directory,
                Path::new(&name),
                "a known configuration temporary file",
            )?;
        }
    }
    Ok(())
}

fn load_deinit_config(root: &Directory) -> Result<Option<Config>> {
    if !checked_owned_file(root, Path::new(CONFIG_FILE), "the configuration")? {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    root.open_regular(Path::new(CONFIG_FILE), libc::O_RDONLY, 0)?
        .read_to_end(&mut bytes)?;
    let text =
        String::from_utf8(bytes).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    Ok(Some(parse_config(&text)?))
}

fn preflight_known_secret_files(secrets: &Directory) -> Result<()> {
    for entry in secrets.read_dir()? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if is_canonical_secret_name(&name) || is_recovery_secret_name(&name) {
            checked_owned_file(secrets, Path::new(&name), "a known secret file")?;
        }
    }
    Ok(())
}

fn preflight_deinit(root: &Directory, recipient_rel: &Path) -> Result<()> {
    checked_owned_file(root, recipient_rel, "the recipient certificate")?;
    checked_owned_file(root, Path::new(INDEX_FILE), "the metadata database")?;
    checked_owned_file(root, Path::new(CONFIG_FILE), "the configuration")?;
    if let Some(secrets) = optional_directory(root, Path::new(SECRETS_DIR))? {
        preflight_known_secret_files(&secrets)?;
    }
    Ok(())
}

fn open_store_guard(data_dir: &Path, root: &Directory) -> Result<Option<FileBackend>> {
    let has_index = checked_owned_file(root, Path::new(INDEX_FILE), "the metadata database")?;
    if !has_index {
        return Ok(None);
    }
    // Claim redb ownership without parsing, initializing, or recovering the index:
    // explicit destructive cleanup must also work for corrupt databases. A daemon
    // may retain a renamed secrets directory, so every existing index needs a lock.
    let file = root.open_regular(Path::new(INDEX_FILE), libc::O_RDWR, 0)?;
    // redb <= 4.2 uses flock; newer redb uses independent OFD range locks.
    // Hold both on this descriptor until destructive cleanup finishes.
    match file.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => {
            return Err(Error::Config(format!(
                "store is in use by another noirpass process: {}; stop the daemon before running maintenance commands",
                data_dir.join(INDEX_FILE).display()
            )));
        }
        Err(std::fs::TryLockError::Error(err)) => {
            return Err(Error::Config(format!(
                "cannot acquire index ownership: {err}"
            )));
        }
    }
    let index = FileBackend::new(file)?;
    if !index
        .try_lock_range(Bound::Unbounded, Bound::Unbounded)
        .map_err(|err| Error::Config(format!("cannot acquire index ownership: {err}")))?
    {
        return Err(Error::Config(format!(
            "store is in use by another noirpass process: {}; stop the daemon before running maintenance commands",
            data_dir.join(INDEX_FILE).display()
        )));
    }
    Ok(Some(index))
}

/// Remove Noirpass-owned state without following symlinks or touching unknown files.
pub fn deinit(data_dir: &Path) -> Result<()> {
    deinit_with_hooks(data_dir, || {}, || {})
}

pub(super) fn deinit_with_hooks(
    data_dir: &Path,
    after_open: impl FnOnce(),
    after_pin: impl FnOnce(),
) -> Result<()> {
    validate_no_symlink_components(data_dir)?;
    if !existing_directory(data_dir, "the selected store")? {
        return Ok(());
    }
    let root = Directory::open(data_dir)?;
    after_open();
    let config = load_deinit_config(&root)?;
    let recipient_rel = config.as_ref().map_or_else(
        || PathBuf::from(RECIPIENT_REL),
        |config| config.recipient_cert.clone(),
    );
    preflight_deinit(&root, &recipient_rel)?;
    let preopened_store = open_store_guard(data_dir, &root)?;
    let _lifecycle_lock = super::LifecycleLock::acquire_in(&root)?;

    let config = load_deinit_config(&root)?;
    let recipient_rel = config.as_ref().map_or_else(
        || PathBuf::from(RECIPIENT_REL),
        |config| config.recipient_cert.clone(),
    );
    preflight_deinit(&root, &recipient_rel)?;
    let _store_guard = match preopened_store {
        Some(store) => Some(store),
        None => open_store_guard(data_dir, &root)?,
    };
    let secrets = optional_directory(&root, Path::new(SECRETS_DIR))?;
    let keys = optional_directory(&root, Path::new(KEYS_DIR))?;
    let recipient_parent_rel = recipient_rel.parent().unwrap_or(Path::new(""));
    let recipient_parent = if recipient_parent_rel == Path::new(KEYS_DIR) {
        keys.as_ref()
            .map(|directory| directory.child(Path::new(".")))
            .transpose()?
    } else {
        optional_directory(
            &root,
            if recipient_parent_rel.as_os_str().is_empty() {
                Path::new(".")
            } else {
                recipient_parent_rel
            },
        )?
    };
    let recipient_name = Path::new(
        recipient_rel
            .file_name()
            .ok_or_else(|| Error::Config("recipient path has no file name".into()))?,
    );
    // Validate exactly the pinned directories that will supply deletion entries.
    if let Some(directory) = &recipient_parent {
        checked_owned_file(directory, recipient_name, "the recipient certificate")?;
    }
    if let Some(directory) = &secrets {
        preflight_known_secret_files(directory)?;
    }
    after_pin();

    if let Some(directory) = &recipient_parent {
        remove_owned_file(directory, recipient_name, "the recipient certificate")?;
    }
    if let Some(directory) = &secrets {
        remove_known_secret_files(directory)?;
        remove_empty_directory(&root, directory, Path::new(SECRETS_DIR))?;
    }
    remove_owned_file(&root, Path::new(INDEX_FILE), "the metadata database")?;
    remove_config_temporary_files_in(&root)?;
    if let Some(directory) = &keys {
        remove_config_temporary_files_in(directory)?;
        remove_empty_directory(&root, directory, Path::new(KEYS_DIR))?;
    }
    remove_owned_file(&root, Path::new(CONFIG_FILE), "the configuration")?;
    root.sync_all()?;
    Ok(())
}
