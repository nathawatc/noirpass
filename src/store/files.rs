//! Crash-safe ciphertext file operations.

mod artifacts;
mod transactions;

use std::fs::{File, Metadata};
use std::io;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

use super::Store;

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FileOperation {
    Rename,
    Remove,
    Sync,
}

impl Store {
    /// Fail selected calls on this store only; never affect concurrent fixtures.
    #[cfg(test)]
    fn inject_file_failure(&self, operation: FileOperation) -> io::Result<()> {
        let mut failures = self.file_failures.lock().unwrap();
        if let Some((next, remaining)) = failures.front_mut()
            && *next == operation
        {
            *remaining -= 1;
            if *remaining == 0 {
                failures.pop_front();
                return Err(io::Error::other(format!("injected {operation:?} failure")));
            }
        }
        Ok(())
    }

    pub(super) fn sync_secrets_directory(&self) -> io::Result<()> {
        #[cfg(test)]
        self.inject_file_failure(FileOperation::Sync)?;
        self.secrets_directory.sync_all()
    }

    fn secret_entry<'a>(&self, path: &'a Path) -> io::Result<&'a Path> {
        if path.parent() != Some(self.secrets_dir.as_path()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path is outside secrets directory",
            ));
        }
        path.file_name()
            .map(Path::new)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing secret filename"))
    }

    pub(super) fn secret_metadata(&self, path: &Path) -> io::Result<Metadata> {
        self.secrets_directory.metadata(self.secret_entry(path)?)
    }

    pub(super) fn validate_secret_regular_or_absent(&self, path: &Path) -> io::Result<()> {
        self.secrets_directory
            .validate_regular_or_absent(self.secret_entry(path)?)
    }

    /// Whether item `id` currently has a regular ciphertext file on disk.
    pub fn has_secret_file(&self, id: &str) -> Result<bool> {
        self.ensure_not_poisoned()?;
        let path = self.secret_path(id)?;
        match self.secret_metadata(&path) {
            Ok(metadata) if metadata.is_file() => Ok(true),
            Ok(_) => Err(Error::Config(format!(
                "secret path is not a regular file: {}",
                path.display()
            ))),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(err.into()),
        }
    }

    pub(super) fn create_secret_file(&self, path: &Path) -> io::Result<File> {
        self.secrets_directory.open_file(
            self.secret_entry(path)?,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )
    }

    pub(super) fn read_secret_path(&self, path: &Path) -> io::Result<Vec<u8>> {
        self.secrets_directory
            .read_regular(self.secret_entry(path)?)
    }

    pub(super) fn remove_secret_file(&self, path: &Path) -> io::Result<()> {
        #[cfg(test)]
        self.inject_file_failure(FileOperation::Remove)?;
        self.secrets_directory.remove(self.secret_entry(path)?)
    }

    pub(super) fn rename_secret_file(&self, from: &Path, to: &Path) -> io::Result<()> {
        #[cfg(test)]
        self.inject_file_failure(FileOperation::Rename)?;
        self.secrets_directory
            .rename(self.secret_entry(from)?, self.secret_entry(to)?)
    }

    /// Atomically write `ciphertext` to `secrets/<id>.gpg` with `0600`
    /// permissions.
    pub(super) fn write_secret_file(&self, id: &str, ciphertext: &[u8]) -> Result<PathBuf> {
        let path = self.secret_path(id)?;
        self.validate_secret_regular_or_absent(&path)?;
        let staged = self.stage_secret_file(id, ciphertext, "create")?;
        if let Err(install_err) = self
            .secrets_directory
            .hard_link(self.secret_entry(&staged)?, self.secret_entry(&path)?)
        {
            return match self.cleanup_files(&[&staged]) {
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
            |candidate| self.remove_secret_file(candidate),
        )?;
        Ok(staged)
    }

    pub(super) fn read_secret_file_unlocked(&self, id: &str) -> Result<Vec<u8>> {
        self.ensure_not_poisoned()?;
        let path = self.secret_path(id)?;
        match self.read_secret_path(&path) {
            Ok(bytes) => Ok(bytes),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                Err(Error::NotFound(format!("secret file for item {id}")))
            }
            Err(e) => Err(e.into()),
        }
    }
}
