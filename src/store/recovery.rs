//! Interrupted-operation recovery.

use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use redb::{ReadableDatabase, ReadableTable};

use crate::error::{Error, Result};

use super::{ITEMS, RecoveryKind, Store, parse_recovery_secret_name};

impl Store {
    /// Reconcile interrupted update/delete filesystem transactions at startup.
    pub fn recover_interrupted_operations(&self) -> Result<()> {
        let mut recovery_guard = self.write_guard_checked()?;
        let mut recovery_files = self
            .secrets_directory
            .read_dir()?
            .map(|entry| entry.map(|entry| self.secrets_dir.join(entry.file_name())))
            .collect::<io::Result<Vec<_>>>()?;
        recovery_files.sort_by_key(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .and_then(RecoveryKind::from_file_name)
                .map_or(u8::MAX, RecoveryKind::priority)
        });

        let mut changed = false;
        for recovery in recovery_files {
            if self.recover_entry(&recovery)? {
                changed = true;
            }
        }
        if changed {
            self.sync_secrets_dir()?;
        }
        // Recovery changes only ciphertext files; validated metadata and its
        // derived lookup index still describe the same committed transaction.
        recovery_guard.preserve_index();
        Ok(())
    }

    fn recover_entry(&self, recovery: &Path) -> Result<bool> {
        let Some(file_name) = recovery.file_name().and_then(|name| name.to_str()) else {
            return Ok(false);
        };
        if RecoveryKind::from_file_name(file_name).is_none() {
            return Ok(false);
        }
        let file_metadata = self.secret_metadata(recovery)?;
        let Some((kind, id)) = parse_recovery_secret_name(file_name) else {
            return Err(Error::Config(format!(
                "invalid recovery file: {}",
                recovery.display()
            )));
        };
        if !file_metadata.file_type().is_file() {
            return Err(Error::Config(format!(
                "invalid recovery file: {}",
                recovery.display()
            )));
        }
        if file_metadata.len() == 0 {
            self.remove_secret_file(recovery)?;
            return Ok(true);
        }

        let canonical = self.secret_path(id)?;
        self.validate_secret_regular_or_absent(&canonical)?;
        match kind {
            RecoveryKind::Create => self.recover_create(recovery, &file_metadata, id, &canonical),
            RecoveryKind::Update => {
                self.remove_secret_file(recovery)?;
                Ok(true)
            }
            RecoveryKind::Quarantine => {
                let txn = self.db.begin_read()?;
                let items = txn.open_table(ITEMS)?;
                if items.get(id)?.is_some() {
                    self.rename_secret_file(recovery, &canonical)?;
                } else {
                    self.remove_secret_file(recovery)?;
                }
                Ok(true)
            }
            RecoveryKind::Backup => self.recover_backup(recovery, id, &canonical),
        }
    }

    fn recover_create(
        &self,
        recovery: &Path,
        file_metadata: &std::fs::Metadata,
        id: &str,
        canonical: &Path,
    ) -> Result<bool> {
        match self.get_item(id) {
            Ok(metadata) => {
                let expected_hash = metadata.ciphertext_sha256.ok_or_else(|| {
                    Error::Config(format!(
                        "create recovery file has metadata without ciphertext digest: {}",
                        recovery.display()
                    ))
                })?;
                if self.secret_file_sha256(canonical)? != expected_hash {
                    return Err(Error::Config(format!(
                        "create recovery file does not match committed ciphertext: {}",
                        recovery.display()
                    )));
                }
                self.remove_secret_file(recovery)?;
                Ok(true)
            }
            Err(Error::NotFound(_)) => match self.secret_metadata(canonical) {
                Ok(canonical_metadata)
                    if canonical_metadata.file_type().is_file()
                        && canonical_metadata.dev() == file_metadata.dev()
                        && canonical_metadata.ino() == file_metadata.ino() =>
                {
                    self.remove_secret_file(canonical)?;
                    self.sync_secrets_dir()?;
                    self.remove_secret_file(recovery)?;
                    Ok(true)
                }
                Ok(_) => Err(Error::Config(format!(
                    "create recovery file does not match unindexed ciphertext: {}",
                    recovery.display()
                ))),
                Err(err) if err.kind() == io::ErrorKind::NotFound => {
                    self.remove_secret_file(recovery)?;
                    Ok(true)
                }
                Err(err) => Err(err.into()),
            },
            Err(err) => Err(err),
        }
    }

    fn recover_backup(&self, recovery: &Path, id: &str, canonical: &Path) -> Result<bool> {
        let metadata = match self.get_item(id) {
            Ok(metadata) => metadata,
            Err(Error::NotFound(_)) => {
                return Err(Error::Config(format!(
                    "backup has no matching item metadata and was preserved for manual recovery: {}",
                    recovery.display()
                )));
            }
            Err(err) => return Err(err),
        };
        let Some(expected_hash) = metadata.ciphertext_sha256 else {
            self.rename_secret_file(recovery, canonical)?;
            return Ok(true);
        };
        match self.secret_file_sha256(canonical) {
            Ok(digest) if digest == expected_hash => self.remove_secret_file(recovery)?,
            Ok(_) => self.rename_secret_file(recovery, canonical)?,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                self.rename_secret_file(recovery, canonical)?;
            }
            Err(err) => return Err(err.into()),
        }
        Ok(true)
    }
}
