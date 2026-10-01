//! Persistent noirpass configuration, recipient lifecycle, and deinitialization.

use std::fs::{self, File, Permissions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use sequoia_openpgp::Cert;

use crate::error::{Error, Result};
use crate::filesystem::{Directory, create_directory_all_nofollow, validate_no_symlink_components};

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
const LIFECYCLE_LOCK_FILE: &str = ".noirpass-lifecycle.lock";

fn open_lifecycle_directory(data_dir: &Path) -> Result<Directory> {
    validate_no_symlink_components(data_dir)?;
    match fs::symlink_metadata(data_dir) {
        Ok(_) => Ok(Directory::open(data_dir)?),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            Ok(create_directory_all_nofollow(data_dir, 0o700)?)
        }
        Err(err) => Err(err.into()),
    }
}

/// Kernel-held exclusivity for persistent init/deinit mutations.
///
/// The lock file is persistent and may remain after a process exits. Ownership
/// is held by its open file descriptor, not by file existence; dropping this
/// guard closes the descriptor and releases the kernel lock automatically.
/// This is separate from Secret Service `Item.Locked` and `Collection.Locked`,
/// which remain always false.
#[derive(Debug)]
pub struct LifecycleLock {
    _file: File,
}

impl LifecycleLock {
    /// Open the selected store's lock file without following symlinks and
    /// acquire its exclusive kernel lock, waiting for another lifecycle
    /// process when necessary.
    pub fn acquire(data_dir: &Path) -> Result<Self> {
        let directory = open_lifecycle_directory(data_dir)?;
        Self::acquire_in(&directory)
    }

    pub(crate) fn acquire_in(directory: &Directory) -> Result<Self> {
        let file = directory.open_regular(
            Path::new(LIFECYCLE_LOCK_FILE),
            libc::O_RDWR | libc::O_CREAT,
            0o600,
        )?;

        loop {
            // SAFETY: `file` is an open regular file and its descriptor remains
            // alive for the lifetime of the returned guard.
            let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
            if result == 0 {
                break;
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(Error::Io(error));
        }

        directory.set_permissions(Permissions::from_mode(0o700))?;
        file.set_permissions(Permissions::from_mode(0o600))?;
        Ok(Self { _file: file })
    }
}

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
mod tests;
