//! Persisted configuration format and atomic file writes.

use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};

use toml_edit::{DocumentMut, value};

use crate::error::{Error, Result};
#[cfg(test)]
use crate::filesystem::create_directory_all_nofollow;
use crate::filesystem::{Directory, validate_no_symlink_components};
#[cfg(test)]
use std::fs::Permissions;
#[cfg(test)]
use std::os::unix::fs::PermissionsExt;

#[cfg(test)]
use super::RECIPIENT_REL;
use super::{
    CONFIG_FILE, CONFIG_TMP_PREFIX, Config, DEFAULT_IDLE_EXIT_SECONDS, IDLE_EXIT_KEY, INIT_HINT,
    MIN_IDLE_EXIT_SECONDS, RECIPIENT_CERT_KEY, RECIPIENT_FINGERPRINT_KEY, VERSION_KEY,
};

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
    #[cfg(test)]
    pub(super) fn write(&self, data_dir: &Path) -> Result<()> {
        validate_recipient_cert_path(&self.recipient_cert)?;
        validate_idle_exit(self.idle_exit)?;
        validate_no_symlink_components(data_dir)?;
        let directory = create_directory_all_nofollow(data_dir, 0o700)?;
        directory.set_permissions(Permissions::from_mode(0o700))?;
        self.write_in(&directory)
    }

    pub(super) fn write_in(&self, directory: &Directory) -> Result<()> {
        validate_recipient_cert_path(&self.recipient_cert)?;
        validate_idle_exit(self.idle_exit)?;
        directory.validate_regular_or_absent(&self.recipient_cert)?;
        let mut doc = DocumentMut::new();
        doc[VERSION_KEY] = value(self.version);
        doc[RECIPIENT_FINGERPRINT_KEY] = value(self.recipient_fingerprint.as_str());
        doc[RECIPIENT_CERT_KEY] = value(self.recipient_cert.to_string_lossy().as_ref());
        doc[IDLE_EXIT_KEY] = value(self.idle_exit);
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
#[cfg(test)]
#[must_use]
pub(super) fn config_path(data_dir: &Path) -> PathBuf {
    data_dir.join(CONFIG_FILE)
}

/// Path to stored recipient certificate.
#[cfg(test)]
#[must_use]
pub(super) fn recipient_cert_path(data_dir: &Path) -> PathBuf {
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

// Keep creation, cleanup, publication, and durability on the same opened directory.
pub(super) fn atomic_write_in(
    directory: &Directory,
    name: &Path,
    bytes: &[u8],
    mode: u32,
) -> Result<()> {
    atomic_write_in_with_sync(directory, name, bytes, mode, || directory.sync_all())
}

pub(super) fn atomic_write_in_with_sync(
    directory: &Directory,
    name: &Path,
    bytes: &[u8],
    mode: u32,
    sync_directory: impl FnOnce() -> io::Result<()>,
) -> Result<()> {
    directory.validate_regular_or_absent(name)?;
    for _ in 0..16 {
        let tmp = PathBuf::from(format!("{CONFIG_TMP_PREFIX}{:016x}", rand::random::<u64>()));
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
                sync_directory()?;
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
    directory.validate_regular_or_absent(name)?;
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
    if idle_exit < MIN_IDLE_EXIT_SECONDS {
        return Err(Error::Config(format!(
            "config.toml `idle_exit` must be {MIN_IDLE_EXIT_SECONDS} or greater"
        )));
    }
    Ok(())
}

pub(super) fn parse_config(text: &str) -> Result<Config> {
    let doc = text
        .parse::<DocumentMut>()
        .map_err(|e| Error::Config(format!("invalid config.toml: {e}")))?;
    let version = doc
        .get(VERSION_KEY)
        .and_then(toml_edit::Item::as_integer)
        .ok_or_else(|| Error::Config(format!("config.toml missing integer `{VERSION_KEY}`")))?;
    let recipient_fingerprint = doc
        .get(RECIPIENT_FINGERPRINT_KEY)
        .and_then(toml_edit::Item::as_str)
        .ok_or_else(|| {
            Error::Config(format!(
                "config.toml missing string `{RECIPIENT_FINGERPRINT_KEY}`"
            ))
        })?
        .to_string();
    let recipient_cert = doc
        .get(RECIPIENT_CERT_KEY)
        .and_then(toml_edit::Item::as_str)
        .ok_or_else(|| {
            Error::Config(format!("config.toml missing string `{RECIPIENT_CERT_KEY}`"))
        })?;
    let recipient_cert = PathBuf::from(recipient_cert);
    validate_recipient_cert_path(&recipient_cert)?;
    let idle_exit = doc
        .get(IDLE_EXIT_KEY)
        .map(|item| {
            item.as_integer().ok_or_else(|| {
                Error::Config(format!("config.toml `{IDLE_EXIT_KEY}` must be an integer"))
            })
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
