//! Persisted configuration format and atomic file writes.

use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};

use toml_edit::{DocumentMut, value};

use crate::error::{Error, Result};
use crate::filesystem::{
    Directory, create_directory_all_nofollow, validate_existing_regular_or_absent,
    validate_no_symlink_components,
};
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;

use super::{CONFIG_FILE, Config, DEFAULT_IDLE_EXIT_SECONDS, INIT_HINT, RECIPIENT_REL};

impl Config {
    /// Load `config.toml`.
    pub fn load(data_dir: &Path) -> Result<Self> {
        validate_no_symlink_components(data_dir)?;
        let directory = Directory::open(data_dir).map_err(uninitialized_or_io)?;
        Self::load_in(&directory)
    }

    pub(crate) fn load_in(directory: &Directory) -> Result<Self> {
        let text = directory
            .read_regular(Path::new(CONFIG_FILE))
            .map_err(uninitialized_or_io)
            .and_then(|bytes| {
                String::from_utf8(bytes)
                    .map_err(|e| Error::Io(io::Error::new(io::ErrorKind::InvalidData, e)))
            })?;
        parse_config(&text)
    }

    /// Write `config.toml`.
    pub fn write(&self, data_dir: &Path) -> Result<()> {
        validate_recipient_cert_path(&self.recipient_cert)?;
        validate_idle_exit(self.idle_exit)?;
        let _ = recipient_cert_path_from_config(data_dir, &self.recipient_cert)?;
        let directory = create_directory_all_nofollow(data_dir, 0o700)?;
        directory.set_permissions(Permissions::from_mode(0o700))?;
        self.write_in(&directory)
    }

    pub(super) fn write_in(&self, directory: &Directory) -> Result<()> {
        validate_recipient_cert_path(&self.recipient_cert)?;
        validate_idle_exit(self.idle_exit)?;
        validate_regular_in(directory, &self.recipient_cert)?;
        let mut doc = DocumentMut::new();
        doc["version"] = value(self.version);
        doc["recipient_fingerprint"] = value(self.recipient_fingerprint.as_str());
        doc["recipient_cert"] = value(self.recipient_cert.to_string_lossy().as_ref());
        doc["idle_exit"] = value(self.idle_exit);
        let text = doc.to_string();
        atomic_write_in(directory, Path::new(CONFIG_FILE), text.as_bytes(), 0o600)?;
        Ok(())
    }
}

pub(super) fn uninitialized_or_io(error: io::Error) -> Error {
    if error.kind() == io::ErrorKind::NotFound {
        Error::Config(format!("noirpass is not initialized; {INIT_HINT}"))
    } else {
        Error::Io(error)
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

pub(super) fn validate_recipient_cert_path(path: &Path) -> Result<()> {
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

pub(super) fn recipient_cert_path_from_config(data_dir: &Path, path: &Path) -> Result<PathBuf> {
    validate_recipient_cert_path(path)?;
    let full_path = data_dir.join(path);
    validate_no_symlink_components(&full_path).map_err(|err| {
        Error::Config(format!(
            "configured recipient certificate path is unsafe at {}; refusing to follow symlink: {err}",
            full_path.display()
        ))
    })?;
    validate_existing_regular_or_absent(&full_path).map_err(|err| {
        Error::Config(format!(
            "configured recipient certificate path is not a regular file at {}: {err}",
            full_path.display()
        ))
    })?;
    Ok(full_path)
}

// Keep creation, cleanup, publication, and durability on the same opened directory.
pub(super) fn atomic_write_in(
    directory: &Directory,
    name: &Path,
    bytes: &[u8],
    mode: u32,
) -> Result<()> {
    validate_regular_in(directory, name)?;
    for _ in 0..16 {
        let tmp = PathBuf::from(format!(".noirpass-tmp-{:016x}", rand::random::<u64>()));
        match directory.open_regular(&tmp, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, mode) {
            Ok(mut file) => {
                let write_result = (|| -> io::Result<()> {
                    file.write_all(bytes)?;
                    file.sync_all()?;
                    Ok(())
                })();
                if let Err(err) = write_result {
                    let _ = directory.remove(&tmp);
                    return Err(Error::Io(err));
                }
                if let Err(err) = directory.rename(&tmp, name) {
                    let _ = directory.remove(&tmp);
                    return Err(Error::Io(err));
                }
                directory.sync_all()?;
                return Ok(());
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
            Err(err) => return Err(Error::Io(err)),
        }
    }
    Err(Error::Config(format!(
        "failed to create temporary file for {}",
        name.display()
    )))
}

pub(super) fn validate_regular_in(directory: &Directory, name: &Path) -> io::Result<()> {
    match directory.metadata(name) {
        Ok(metadata) if metadata.is_file() => Ok(()),
        Ok(metadata) if metadata.file_type().is_symlink() => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path contains symlink",
        )),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path is not a regular file",
        )),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

pub(super) fn read_optional_in(directory: &Directory, name: &Path) -> Result<Option<Vec<u8>>> {
    match directory.read_regular(name) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(Error::Io(err)),
    }
}

pub(super) fn restore_optional_in(
    directory: &Directory,
    name: &Path,
    previous: Option<&[u8]>,
) -> Result<()> {
    validate_regular_in(directory, name)?;
    if let Some(bytes) = previous {
        atomic_write_in(directory, name, bytes, 0o600)
    } else {
        match directory.remove(name) {
            Ok(()) => {
                directory.sync_all()?;
                Ok(())
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(Error::Io(err)),
        }
    }
}
fn validate_idle_exit(idle_exit: i64) -> Result<()> {
    if idle_exit < -1 {
        return Err(Error::Config(
            "config.toml `idle_exit` must be -1 or greater".into(),
        ));
    }
    Ok(())
}

pub(super) fn parse_config(text: &str) -> Result<Config> {
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
mod atomic_tests {
    use super::*;
    use std::{fs, os::unix::fs::symlink};

    #[test]
    fn atomic_publication_stays_in_opened_parent_after_path_replacement() {
        let tmp = tempfile::tempdir().unwrap();
        let parent = tmp.path().join("parent");
        let moved = tmp.path().join("moved");
        let outside = tmp.path().join("outside");
        fs::create_dir(&parent).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(parent.join("config.toml"), b"old").unwrap();
        fs::write(outside.join("config.toml"), b"untouched").unwrap();
        let directory = Directory::open(&parent).unwrap();
        fs::rename(&parent, &moved).unwrap();
        symlink(&outside, &parent).unwrap();

        atomic_write_in(&directory, Path::new("config.toml"), b"new", 0o600).unwrap();

        assert_eq!(fs::read(moved.join("config.toml")).unwrap(), b"new");
        assert_eq!(fs::read(outside.join("config.toml")).unwrap(), b"untouched");
        assert_eq!(fs::read_dir(&moved).unwrap().count(), 1);
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 1);
        assert!(Directory::open(&parent).is_err());
    }
}
