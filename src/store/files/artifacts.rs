//! Recovery and staging artifact mechanics.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

use super::super::Store;

impl Store {
    pub(in crate::store) fn sync_secrets_dir(&self) -> Result<()> {
        self.sync_secrets_directory()?;
        Ok(())
    }

    pub(in crate::store) fn recovery_path(&self, kind: &str, id: &str) -> PathBuf {
        self.secrets_dir.join(format!(
            ".noirpass-{kind}-{id}-{:016x}.gpg",
            rand::random::<u64>()
        ))
    }

    pub(super) fn reserve_recovery_path(&self, kind: &str, id: &str) -> Result<PathBuf> {
        for _ in 0..16 {
            let path = self.recovery_path(kind, id);
            match self.create_secret_file(&path) {
                Ok(file) => {
                    if let Err(sync_err) = file.sync_all() {
                        return match self.remove_secret_file(&path) {
                            Ok(()) => Err(sync_err.into()),
                            Err(cleanup_err) => self.poison_error(Error::Config(format!(
                                "failed to sync reserved recovery path: {sync_err}; cleanup {} also failed: {cleanup_err}",
                                path.display()
                            ))),
                        };
                    }
                    return Ok(path);
                }
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
                Err(err) => return Err(err.into()),
            }
        }
        Err(Error::Config(format!(
            "failed to reserve recovery path for item {id}"
        )))
    }

    pub(super) fn cleanup_files(&self, paths: &[&Path]) -> io::Result<()> {
        let mut first_error = None;
        for path in paths {
            if let Err(err) = self.remove_secret_file(path)
                && first_error.is_none()
            {
                first_error = Some(err);
            }
        }
        match first_error {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    pub(in crate::store) fn stage_secret_file(
        &self,
        id: &str,
        ciphertext: &[u8],
        kind: &str,
    ) -> Result<PathBuf> {
        for _ in 0..16 {
            let path = self.recovery_path(kind, id);
            match self.create_secret_file(&path) {
                Ok(mut file) => {
                    if let Err(write_err) =
                        file.write_all(ciphertext).and_then(|()| file.sync_all())
                    {
                        return match self.remove_secret_file(&path) {
                            Ok(()) => Err(write_err.into()),
                            Err(cleanup_err) => self.poison_error(Error::Config(format!(
                                "failed to write staged ciphertext: {write_err}; cleanup {} also failed: {cleanup_err}",
                                path.display()
                            ))),
                        };
                    }
                    if let Err(sync_err) = self.sync_secrets_dir() {
                        return match self.remove_secret_file(&path) {
                            Ok(()) => match self.sync_secrets_dir() {
                                Ok(()) => Err(sync_err),
                                Err(cleanup_sync_err) => self.poison_error(Error::Config(format!(
                                    "failed to sync staged ciphertext: {sync_err}; staged file was removed, but directory sync failed: {cleanup_sync_err}"
                                ))),
                            },
                            Err(cleanup_err) => self.poison_error(Error::Config(format!(
                                "failed to sync staged ciphertext: {sync_err}; cleanup {} also failed: {cleanup_err}",
                                path.display()
                            ))),
                        };
                    }
                    return Ok(path);
                }
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
                Err(err) => return Err(err.into()),
            }
        }
        Err(Error::Config(format!(
            "failed to create staged secret file for item {id}"
        )))
    }

    pub(in crate::store) fn remove_recovery_file(
        path: &Path,
        context: &str,
        remove: impl FnOnce(&Path) -> io::Result<()>,
    ) -> Result<()> {
        remove(path).map_err(|err| {
            Error::Config(format!(
                "{context}, but recoverable ciphertext cleanup failed at {}: {err}",
                path.display()
            ))
        })
    }

    pub(super) fn restore_quarantines(&self, moves: &[(PathBuf, PathBuf)]) -> Result<()> {
        let mut first_error = None;
        for (path, quarantine) in moves.iter().rev() {
            if let Err(err) = self.rename_secret_file(quarantine, path)
                && first_error.is_none()
            {
                first_error = Some(format!(
                    "failed to restore {} from {}: {err}",
                    path.display(),
                    quarantine.display()
                ));
            }
        }
        if let Err(err) = self.sync_secrets_dir()
            && first_error.is_none()
        {
            first_error = Some(format!("failed to sync ciphertext restoration: {err}"));
        }
        match first_error {
            Some(error) => Err(Error::Config(error)),
            None => Ok(()),
        }
    }
}
