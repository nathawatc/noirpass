//! Persisted configuration format and atomic file writes.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use toml_edit::{DocumentMut, value};

use crate::error::{Error, Result};

use super::{CONFIG_FILE, Config, DEFAULT_IDLE_EXIT_SECONDS, INIT_HINT, RECIPIENT_REL};

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
    Ok(data_dir.join(path))
}

pub(super) fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
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

pub(super) fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(Error::Io(err)),
    }
}

pub(super) fn restore_recipient_cert(path: &Path, previous: Option<&[u8]>) -> Result<()> {
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
