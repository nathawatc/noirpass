//! Interrupted-operation recovery.

use std::io;
use std::os::unix::fs::MetadataExt;

use redb::{ReadableDatabase, ReadableTable};

use crate::error::{Error, Result};

use super::{ITEMS, Store, ciphertext_sha256, parse_recovery_secret_name, recovery_kind};

impl Store {
    /// Reconcile interrupted update/delete filesystem transactions at startup.
    #[allow(
        clippy::too_many_lines,
        reason = "linear recovery branches preserve durable create/update/quarantine/backup ordering"
    )]
    pub fn recover_interrupted_operations(&self) -> Result<()> {
        let mut recovery_guard = self.write_guard_checked()?;
        let mut recovery_files = self
            .secrets_directory
            .read_dir()?
            .map(|entry| entry.map(|entry| self.secrets_dir.join(entry.file_name())))
            .collect::<io::Result<Vec<_>>>()?;
        recovery_files.sort_by_key(|path| {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            match recovery_kind(name) {
                Some("create" | "update") => 0,
                Some("quarantine") => 1,
                _ => 2,
            }
        });

        for recovery in recovery_files {
            let Some(file_name) = recovery.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if recovery_kind(file_name).is_none() {
                continue;
            }
            let file_metadata = self.secret_metadata(&recovery)?;
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
                self.remove_secret_file(&recovery)?;
                continue;
            }

            let canonical = self.secret_path(id)?;
            self.validate_secret_regular_or_absent(&canonical)?;
            if kind == "create" {
                match self.get_item(id) {
                    Ok(metadata) => {
                        let expected_hash = metadata.ciphertext_sha256.ok_or_else(|| {
                            Error::Config(format!(
                                "create recovery file has metadata without ciphertext digest: {}",
                                recovery.display()
                            ))
                        })?;
                        let ciphertext = self.read_secret_path(&canonical)?;
                        if ciphertext_sha256(&ciphertext) != expected_hash {
                            return Err(Error::Config(format!(
                                "create recovery file does not match committed ciphertext: {}",
                                recovery.display()
                            )));
                        }
                        self.remove_secret_file(&recovery)?;
                    }
                    Err(Error::NotFound(_)) => match self.secret_metadata(&canonical) {
                        Ok(canonical_metadata)
                            if canonical_metadata.file_type().is_file()
                                && canonical_metadata.dev() == file_metadata.dev()
                                && canonical_metadata.ino() == file_metadata.ino() =>
                        {
                            self.remove_secret_file(&canonical)?;
                            self.sync_secrets_dir()?;
                            self.remove_secret_file(&recovery)?;
                        }
                        Ok(_) => {
                            return Err(Error::Config(format!(
                                "create recovery file does not match unindexed ciphertext: {}",
                                recovery.display()
                            )));
                        }
                        Err(err) if err.kind() == io::ErrorKind::NotFound => {
                            self.remove_secret_file(&recovery)?;
                        }
                        Err(err) => return Err(err.into()),
                    },
                    Err(err) => return Err(err),
                }
                continue;
            }
            if kind == "update" {
                self.remove_secret_file(&recovery)?;
                continue;
            }

            if kind == "quarantine" {
                let txn = self.db.begin_read()?;
                let items = txn.open_table(ITEMS)?;
                if items.get(id)?.is_some() {
                    self.rename_secret_file(&recovery, &canonical)?;
                } else {
                    self.remove_secret_file(&recovery)?;
                }
                continue;
            }

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
                self.rename_secret_file(&recovery, &canonical)?;
                continue;
            };
            match self.read_secret_path(&canonical) {
                Ok(ciphertext) if ciphertext_sha256(&ciphertext) == expected_hash => {
                    self.remove_secret_file(&recovery)?;
                }
                Ok(_) => self.rename_secret_file(&recovery, &canonical)?,
                Err(err) if err.kind() == io::ErrorKind::NotFound => {
                    self.rename_secret_file(&recovery, &canonical)?;
                }
                Err(err) => return Err(err.into()),
            }
        }
        self.sync_secrets_dir()?;
        // Recovery changes only ciphertext files; validated metadata and its
        // derived lookup index still describe the same committed transaction.
        recovery_guard.preserve_index();
        Ok(())
    }
}
