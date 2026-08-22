//! Crash-safe ciphertext file operations.

mod artifacts;
mod transactions;

use std::fs;
use std::io;
use std::path::PathBuf;

use crate::error::{Error, Result};
use crate::filesystem::{read_regular_file_nofollow, validate_existing_regular_or_absent};

use super::Store;

impl Store {
    /// Atomically write `ciphertext` to `secrets/<id>.gpg` with `0600`
    /// permissions.
    pub(super) fn write_secret_file(&self, id: &str, ciphertext: &[u8]) -> Result<PathBuf> {
        let path = self.secret_path(id)?;
        validate_existing_regular_or_absent(&path)?;
        let staged = self.stage_secret_file(id, ciphertext, "create")?;
        if let Err(install_err) = fs::hard_link(&staged, &path) {
            return match Self::cleanup_files(&[&staged]) {
                Ok(()) => match self.sync_secrets_dir() {
                    Ok(()) => Err(install_err.into()),
                    Err(sync_err) => self.poison_error(Error::Config(format!(
                        "failed to install ciphertext: {install_err}; staged file was removed, but directory sync failed: {sync_err}"
                    ))),
                },
                Err(cleanup_err) => self.poison_error(Error::Config(format!(
                    "failed to install ciphertext: {install_err}; cleanup {} also failed: {cleanup_err}",
                    staged.display()
                ))),
            };
        }
        self.finish_create_install(
            &path,
            &staged,
            || self.sync_secrets_dir(),
            |candidate| fs::remove_file(candidate),
        )?;
        Ok(staged)
    }

    pub(super) fn read_secret_file_unlocked(&self, id: &str) -> Result<Vec<u8>> {
        self.ensure_not_poisoned()?;
        let path = self.secret_path(id)?;
        match read_regular_file_nofollow(&path) {
            Ok(bytes) => Ok(bytes),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                Err(Error::NotFound(format!("secret file for item {id}")))
            }
            Err(e) => Err(e.into()),
        }
    }
}
