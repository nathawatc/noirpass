//! Persistence transaction orchestration and state machines.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::filesystem::{open_directory_nofollow, validate_existing_regular_or_absent};

use super::super::{PersistError, Store};

impl Store {
    pub(in crate::store) fn finish_create_install(
        &self,
        path: &Path,
        marker: &Path,
        mut sync: impl FnMut() -> Result<()>,
        mut remove: impl FnMut(&Path) -> io::Result<()>,
    ) -> Result<()> {
        let Err(sync_err) = sync() else {
            return Ok(());
        };
        if let Err(cleanup_err) = remove(path) {
            return self.poison_error(Error::Config(format!(
                "failed to sync installed ciphertext: {sync_err}; cleanup failed at {}: {cleanup_err}",
                path.display()
            )));
        }
        if let Err(cleanup_sync_err) = sync() {
            return self.poison_error(Error::Config(format!(
                "failed to sync installed ciphertext: {sync_err}; ciphertext was removed, but cleanup directory sync failed: {cleanup_sync_err}"
            )));
        }
        if let Err(cleanup_err) = remove(marker) {
            return self.poison_error(Error::Config(format!(
                "failed to sync installed ciphertext: {sync_err}; marker cleanup failed at {}: {cleanup_err}",
                marker.display()
            )));
        }
        match sync() {
            Ok(()) => Err(sync_err),
            Err(marker_sync_err) => self.poison_error(Error::Config(format!(
                "failed to sync installed ciphertext: {sync_err}; marker was removed, but directory sync failed: {marker_sync_err}"
            ))),
        }
    }

    pub(in crate::store) fn replace_then_commit<T>(
        &self,
        path: &Path,
        staged: &Path,
        commit: impl FnOnce() -> std::result::Result<T, PersistError>,
    ) -> Result<T> {
        validate_existing_regular_or_absent(path)?;
        let id = path
            .file_stem()
            .and_then(|name| name.to_str())
            .ok_or_else(|| Error::Config(format!("invalid secret path: {}", path.display())))?;
        let backup = self.reserve_recovery_path("backup", id)?;
        if let Err(backup_err) = fs::rename(path, &backup) {
            return match Self::cleanup_files(&[staged, &backup]) {
                Ok(()) => Err(backup_err.into()),
                Err(cleanup_err) => self.poison_error(Error::Config(format!(
                    "failed to preserve previous ciphertext: {backup_err}; staged/recovery cleanup also failed: {cleanup_err}"
                ))),
            };
        }
        if let Err(install_err) = fs::rename(staged, path) {
            let restore = fs::rename(&backup, path);
            let cleanup = fs::remove_file(staged);
            let sync = self.sync_secrets_dir();
            return match (&restore, &cleanup, &sync) {
                (Ok(()), Ok(()), Ok(())) => Err(install_err.into()),
                _ => self.poison_error(Error::Config(format!(
                    "failed to install new ciphertext: {install_err}; restore: {}; staged cleanup: {}; directory sync: {}; previous ciphertext may remain at {}",
                    restore
                        .err()
                        .map_or_else(|| "ok".to_string(), |error| error.to_string()),
                    cleanup
                        .err()
                        .map_or_else(|| "ok".to_string(), |error| error.to_string()),
                    sync.err()
                        .map_or_else(|| "ok".to_string(), |error| error.to_string()),
                    backup.display()
                ))),
            };
        }
        if let Err(sync_err) = self.sync_secrets_dir() {
            let rollback = fs::rename(&backup, path)
                .and_then(|()| open_directory_nofollow(&self.secrets_dir)?.sync_all());
            return match rollback {
                Ok(()) => Err(sync_err),
                Err(rollback_err) => self.poison_error(Error::Config(format!(
                    "failed to sync installed ciphertext: {sync_err}; rollback failed: {rollback_err}; previous ciphertext may remain at {}",
                    backup.display()
                ))),
            };
        }

        match commit() {
            Ok(value) => {
                self.finish_post_commit_cleanup(Self::remove_recovery_file(
                    &backup,
                    "metadata committed and new ciphertext installed",
                    |path| fs::remove_file(path),
                ))?;
                self.finish_post_commit_cleanup(self.sync_secrets_dir())?;
                Ok(value)
            }
            Err(PersistError::Definite(err)) => {
                let rollback = fs::rename(&backup, path)
                    .and_then(|()| open_directory_nofollow(&self.secrets_dir)?.sync_all());
                match rollback {
                    Ok(()) => Err(err),
                    Err(rollback_err) => self.poison_error(Error::Config(format!(
                        "metadata write failed: {err}; ciphertext rollback failed: {rollback_err}; previous ciphertext may remain at {}",
                        backup.display()
                    ))),
                }
            }
            Err(PersistError::Indeterminate(err)) => {
                self.poison();
                Err(Error::Config(format!(
                    "metadata commit outcome is indeterminate: {err}; backup retained for restart reconciliation"
                )))
            }
        }
    }

    pub(in crate::store) fn quarantine_then_commit<T>(
        &self,
        path: &Path,
        commit: impl FnOnce() -> std::result::Result<T, PersistError>,
    ) -> Result<T> {
        validate_existing_regular_or_absent(path)?;
        let id = path
            .file_stem()
            .and_then(|name| name.to_str())
            .ok_or_else(|| Error::Config(format!("invalid secret path: {}", path.display())))?;
        let quarantine = self.reserve_recovery_path("quarantine", id)?;
        let quarantined = match fs::rename(path, &quarantine) {
            Ok(()) => {
                if let Err(sync_err) = self.sync_secrets_dir() {
                    let restore = fs::rename(&quarantine, path)
                        .and_then(|()| open_directory_nofollow(&self.secrets_dir)?.sync_all());
                    return match restore {
                        Ok(()) => Err(sync_err),
                        Err(restore_err) => self.poison_error(Error::Config(format!(
                            "failed to sync quarantined ciphertext: {sync_err}; restore failed: {restore_err}; recoverable ciphertext remains at {}",
                            quarantine.display()
                        ))),
                    };
                }
                true
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                fs::remove_file(&quarantine)?;
                false
            }
            Err(err) => {
                return match fs::remove_file(&quarantine) {
                    Ok(()) => Err(err.into()),
                    Err(cleanup_err) => self.poison_error(Error::Config(format!(
                        "failed to quarantine ciphertext: {err}; reserved-path cleanup also failed at {}: {cleanup_err}",
                        quarantine.display()
                    ))),
                };
            }
        };

        match commit() {
            Ok(value) if quarantined => {
                self.finish_post_commit_cleanup(Self::remove_recovery_file(
                    &quarantine,
                    "metadata deletion committed",
                    |path| fs::remove_file(path),
                ))?;
                self.finish_post_commit_cleanup(self.sync_secrets_dir())?;
                Ok(value)
            }
            Ok(value) => Ok(value),
            Err(PersistError::Definite(err)) if quarantined => match fs::rename(&quarantine, path)
                .and_then(|()| open_directory_nofollow(&self.secrets_dir)?.sync_all())
            {
                Ok(()) => Err(err),
                Err(restore_err) => self.poison_error(Error::Config(format!(
                    "metadata deletion failed: {err}; ciphertext restore failed: {restore_err}; recoverable ciphertext remains at {}",
                    quarantine.display()
                ))),
            },
            Err(PersistError::Definite(err)) => Err(err),
            Err(PersistError::Indeterminate(err)) => {
                self.poison();
                Err(Error::Config(format!(
                    "metadata deletion commit outcome is indeterminate: {err}; quarantine retained for restart reconciliation"
                )))
            }
        }
    }

    pub(in crate::store) fn quarantine_many_then_commit<T>(
        &self,
        paths: &[PathBuf],
        commit: impl FnOnce() -> std::result::Result<T, PersistError>,
    ) -> Result<T> {
        let validated = paths
            .iter()
            .map(|path| {
                validate_existing_regular_or_absent(path)?;
                let id = path
                    .file_stem()
                    .and_then(|name| name.to_str())
                    .ok_or_else(|| {
                        Error::Config(format!("invalid secret path: {}", path.display()))
                    })?;
                Ok((path.clone(), id.to_string()))
            })
            .collect::<Result<Vec<_>>>()?;
        let mut planned = Vec::new();
        for (path, id) in validated {
            match self.reserve_recovery_path("quarantine", &id) {
                Ok(quarantine) => planned.push((path, quarantine)),
                Err(reserve_err) => {
                    let reserved = planned
                        .iter()
                        .map(|(_, quarantine): &(PathBuf, PathBuf)| quarantine.as_path())
                        .collect::<Vec<_>>();
                    return match Self::cleanup_files(&reserved) {
                        Ok(()) => Err(reserve_err),
                        Err(cleanup_err) => self.poison_error(Error::Config(format!(
                            "failed to reserve quarantine path: {reserve_err}; reserved-path cleanup also failed: {cleanup_err}"
                        ))),
                    };
                }
            }
        }
        let mut moves = Vec::new();
        for (index, (path, quarantine)) in planned.iter().enumerate() {
            match fs::rename(path, quarantine) {
                Ok(()) => moves.push((path.clone(), quarantine.clone())),
                Err(err) => {
                    let reserved = planned[index..]
                        .iter()
                        .map(|(_, reserved)| reserved.as_path())
                        .collect::<Vec<_>>();
                    let cleanup = Self::cleanup_files(&reserved);
                    let restore = self.restore_quarantines(&moves);
                    return match (cleanup, restore) {
                        (Ok(()), Ok(())) => Err(err.into()),
                        (cleanup, restore) => self.poison_error(Error::Config(format!(
                            "failed to quarantine {}: {err}; reserved cleanup: {}; rollback: {}",
                            path.display(),
                            cleanup
                                .err()
                                .map_or_else(|| "ok".to_string(), |error| error.to_string()),
                            restore
                                .err()
                                .map_or_else(|| "ok".to_string(), |error| error.to_string())
                        ))),
                    };
                }
            }
        }
        if let Err(sync_err) = self.sync_secrets_dir() {
            return match self.restore_quarantines(&moves) {
                Ok(()) => Err(sync_err),
                Err(restore_err) => self.poison_error(Error::Config(format!(
                    "failed to sync quarantined ciphertext: {sync_err}; rollback also failed: {restore_err}"
                ))),
            };
        }

        match commit() {
            Ok(value) => {
                for (_, quarantine) in &moves {
                    self.finish_post_commit_cleanup(Self::remove_recovery_file(
                        quarantine,
                        "metadata deletion committed",
                        |path| fs::remove_file(path),
                    ))?;
                }
                self.finish_post_commit_cleanup(self.sync_secrets_dir())?;
                Ok(value)
            }
            Err(PersistError::Definite(err)) => match self.restore_quarantines(&moves) {
                Ok(()) => Err(err),
                Err(restore_err) => self.poison_error(Error::Config(format!(
                    "metadata deletion failed: {err}; ciphertext rollback also failed: {restore_err}"
                ))),
            },
            Err(PersistError::Indeterminate(err)) => {
                self.poison();
                Err(Error::Config(format!(
                    "collection deletion commit outcome is indeterminate: {err}; quarantines retained for restart reconciliation"
                )))
            }
        }
    }
}
