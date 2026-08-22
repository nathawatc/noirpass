//! Interrupted-operation recovery.

use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;

use redb::ReadableDatabase;

use crate::error::{Error, Result};
use crate::filesystem::{
    read_regular_file_nofollow, validate_existing_regular_or_absent, validate_no_symlink_components,
};

use super::{ITEMS, Store, ciphertext_sha256, is_valid_item_id};

impl Store {
    /// Reconcile interrupted update/delete filesystem transactions at startup.
    #[allow(
        clippy::too_many_lines,
        reason = "linear recovery branches preserve durable create/update/quarantine/backup ordering"
    )]
    pub fn recover_interrupted_operations(&self) -> Result<()> {
        let _recovery_guard = self.write_guard_checked()?;
        validate_no_symlink_components(&self.secrets_dir)?;
        let mut recovery_files = fs::read_dir(&self.secrets_dir)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<io::Result<Vec<_>>>()?;
        recovery_files.sort_by_key(|path| {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            if name.starts_with(".noirpass-create-") || name.starts_with(".noirpass-update-") {
                0
            } else if name.starts_with(".noirpass-quarantine-") {
                1
            } else {
                2
            }
        });

        for recovery in recovery_files {
            let Some(file_name) = recovery.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let kind = if file_name.starts_with(".noirpass-create-") {
                "create"
            } else if file_name.starts_with(".noirpass-update-") {
                "update"
            } else if file_name.starts_with(".noirpass-quarantine-") {
                "quarantine"
            } else if file_name.starts_with(".noirpass-backup-") {
                "backup"
            } else {
                continue;
            };
            let prefix = format!(".noirpass-{kind}-");
            let rest = file_name
                .strip_prefix(&prefix)
                .ok_or_else(|| Error::Config(format!("invalid recovery filename: {file_name}")))?;
            let Some((id, suffix)) = rest.split_once('-') else {
                return Err(Error::Config(format!(
                    "invalid recovery filename: {file_name}"
                )));
            };
            let file_metadata = fs::symlink_metadata(&recovery)?;
            let valid_suffix = suffix.strip_suffix(".gpg").is_some_and(|token| {
                token.len() == 16 && token.bytes().all(|byte| byte.is_ascii_hexdigit())
            });
            if !is_valid_item_id(id) || !valid_suffix || !file_metadata.file_type().is_file() {
                return Err(Error::Config(format!(
                    "invalid recovery file: {}",
                    recovery.display()
                )));
            }
            if file_metadata.len() == 0 {
                fs::remove_file(&recovery)?;
                continue;
            }

            let canonical = self.secret_path(id)?;
            validate_existing_regular_or_absent(&canonical)?;
            if kind == "create" {
                match self.get_item(id) {
                    Ok(metadata) => {
                        let expected_hash = metadata.ciphertext_sha256.ok_or_else(|| {
                            Error::Config(format!(
                                "create recovery file has metadata without ciphertext digest: {}",
                                recovery.display()
                            ))
                        })?;
                        let ciphertext = read_regular_file_nofollow(&canonical)?;
                        if ciphertext_sha256(&ciphertext) != expected_hash {
                            return Err(Error::Config(format!(
                                "create recovery file does not match committed ciphertext: {}",
                                recovery.display()
                            )));
                        }
                        fs::remove_file(&recovery)?;
                    }
                    Err(Error::NotFound(_)) => match fs::symlink_metadata(&canonical) {
                        Ok(canonical_metadata)
                            if canonical_metadata.file_type().is_file()
                                && canonical_metadata.dev() == file_metadata.dev()
                                && canonical_metadata.ino() == file_metadata.ino() =>
                        {
                            fs::remove_file(&canonical)?;
                            self.sync_secrets_dir()?;
                            fs::remove_file(&recovery)?;
                        }
                        Ok(_) => {
                            return Err(Error::Config(format!(
                                "create recovery file does not match unindexed ciphertext: {}",
                                recovery.display()
                            )));
                        }
                        Err(err) if err.kind() == io::ErrorKind::NotFound => {
                            fs::remove_file(&recovery)?;
                        }
                        Err(err) => return Err(err.into()),
                    },
                    Err(err) => return Err(err),
                }
                continue;
            }
            if kind == "update" {
                fs::remove_file(&recovery)?;
                continue;
            }

            if kind == "quarantine" {
                let txn = self.db.begin_read()?;
                let items = txn.open_table(ITEMS)?;
                if items.get(id)?.is_some() {
                    fs::rename(&recovery, &canonical)?;
                } else {
                    fs::remove_file(&recovery)?;
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
                fs::rename(&recovery, &canonical)?;
                continue;
            };
            match read_regular_file_nofollow(&canonical) {
                Ok(ciphertext) if ciphertext_sha256(&ciphertext) == expected_hash => {
                    fs::remove_file(&recovery)?;
                }
                Ok(_) => fs::rename(&recovery, &canonical)?,
                Err(err) if err.kind() == io::ErrorKind::NotFound => {
                    fs::rename(&recovery, &canonical)?;
                }
                Err(err) => return Err(err.into()),
            }
        }
        self.sync_secrets_dir()
    }
}
