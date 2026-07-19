//! Ciphertext persistence, recovery, and integrity checks.

use std::collections::HashSet;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use redb::{ReadableDatabase, ReadableTable};

use super::{
    ALIASES, COLLECTIONS, CollectionMeta, CorruptCollection, CorruptItem, Error, ITEMS,
    IndexedItem, IntegrityReport, ItemMeta, PersistError, Result, Store, ciphertext_sha256,
    is_valid_collection_id, is_valid_item_id,
};

impl Store {
    /// Reconcile interrupted update/delete filesystem transactions at startup.
    #[allow(
        clippy::too_many_lines,
        reason = "linear recovery branches preserve durable create/update/quarantine/backup ordering"
    )]
    pub fn recover_interrupted_operations(&self) -> Result<()> {
        let _recovery_guard = self.write_guard_checked()?;
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
            if kind == "create" {
                match self.get_item(id) {
                    Ok(metadata) => {
                        let expected_hash = metadata.ciphertext_sha256.ok_or_else(|| {
                            Error::Config(format!(
                                "create recovery file has metadata without ciphertext digest: {}",
                                recovery.display()
                            ))
                        })?;
                        let ciphertext = fs::read(&canonical)?;
                        if ciphertext_sha256(&ciphertext) != expected_hash {
                            return Err(Error::Config(format!(
                                "create recovery file does not match committed ciphertext: {}",
                                recovery.display()
                            )));
                        }
                        fs::remove_file(&recovery)?;
                    }
                    Err(Error::NotFound(_)) => match fs::metadata(&canonical) {
                        Ok(canonical_metadata)
                            if canonical_metadata.dev() == file_metadata.dev()
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
            match fs::read(&canonical) {
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

    /// Refuse daemon startup while unresolved integrity problems exist.
    pub fn ensure_safe_to_serve(&self) -> Result<()> {
        let report = self.check_integrity()?;
        if report.is_healthy() {
            return Ok(());
        }
        Err(Error::Config(
            "store integrity check failed; run `noirpass check` before starting daemon".into(),
        ))
    }

    /// Cross-check every redb item against ciphertext files on disk.
    #[allow(
        clippy::too_many_lines,
        reason = "single read transaction validates related collection, item, and alias tables"
    )]
    pub fn check_integrity(&self) -> Result<IntegrityReport> {
        let txn = self.db.begin_read()?;
        let mut collection_ids = HashSet::new();
        let mut present_collection_ids = HashSet::new();
        let mut corrupt_collections = Vec::new();
        {
            let collections = txn.open_table(COLLECTIONS)?;
            for entry in collections.iter()? {
                let (key, value) = entry?;
                let table_key = key.value().to_string();
                present_collection_ids.insert(table_key.clone());
                let metadata = serde_json::from_slice::<CollectionMeta>(value.value());
                let error = if is_valid_collection_id(&table_key) {
                    match metadata {
                        Ok(metadata) if metadata.id == table_key => {
                            collection_ids.insert(table_key.clone());
                            None
                        }
                        Ok(metadata) => Some(format!(
                            "metadata id {} does not match table key {table_key}",
                            metadata.id
                        )),
                        Err(err) => Some(format!("metadata cannot be decoded: {err}")),
                    }
                } else {
                    Some(format!(
                        "table key {table_key} is not a canonical collection id"
                    ))
                };
                if let Some(error) = error {
                    corrupt_collections.push(CorruptCollection { table_key, error });
                }
            }
        }

        let items = txn.open_table(ITEMS)?;
        let mut indexed = HashSet::new();
        let mut missing_secret_items = Vec::new();
        let mut corrupt_items = Vec::new();
        let mut ciphertext_mismatches = Vec::new();
        let mut items_with_invalid_collection = Vec::new();
        for entry in items.iter()? {
            let (key, value) = entry?;
            let table_key = key.value().to_string();
            indexed.insert(table_key.clone());
            if !is_valid_item_id(&table_key) {
                corrupt_items.push(CorruptItem {
                    table_key: table_key.clone(),
                    metadata: serde_json::from_slice(value.value()).ok(),
                    error: format!("table key {table_key} is not a canonical item id"),
                });
                continue;
            }
            let metadata = match serde_json::from_slice::<ItemMeta>(value.value()) {
                Ok(metadata)
                    if metadata.id == table_key
                        && collection_ids.contains(&metadata.collection) =>
                {
                    metadata
                }
                Ok(metadata) if metadata.id == table_key => {
                    let owner_state = if present_collection_ids.contains(&metadata.collection) {
                        "corrupt"
                    } else {
                        "missing"
                    };
                    items_with_invalid_collection.push(CorruptItem {
                        table_key: table_key.clone(),
                        error: format!(
                            "item references {owner_state} collection {}",
                            metadata.collection
                        ),
                        metadata: Some(metadata),
                    });
                    continue;
                }
                Ok(metadata) => {
                    corrupt_items.push(CorruptItem {
                        table_key: table_key.clone(),
                        error: format!(
                            "metadata id {} does not match table key {table_key}",
                            metadata.id
                        ),
                        metadata: Some(metadata),
                    });
                    continue;
                }
                Err(err) => {
                    corrupt_items.push(CorruptItem {
                        table_key: table_key.clone(),
                        metadata: None,
                        error: format!("metadata cannot be decoded: {err}"),
                    });
                    continue;
                }
            };
            let path = self.secret_path(&table_key)?;
            match fs::symlink_metadata(&path) {
                Ok(file_metadata) if file_metadata.file_type().is_file() => {
                    if let Some(expected_hash) = &metadata.ciphertext_sha256 {
                        let ciphertext = fs::read(&path)?;
                        if ciphertext_sha256(&ciphertext) != *expected_hash {
                            ciphertext_mismatches.push(IndexedItem {
                                table_key,
                                metadata,
                            });
                        }
                    }
                }
                Ok(_) => {
                    return Err(Error::Config(format!(
                        "secret path is not a regular file: {}",
                        path.display()
                    )));
                }
                Err(err) if err.kind() == io::ErrorKind::NotFound => {
                    missing_secret_items.push(IndexedItem {
                        table_key,
                        metadata,
                    });
                }
                Err(err) => return Err(err.into()),
            }
        }
        drop(items);

        let mut corrupt_aliases = Vec::new();
        let mut aliases_with_corrupt_collection = Vec::new();
        {
            let aliases = txn.open_table(ALIASES)?;
            for entry in aliases.iter()? {
                let (name, collection_id) = entry?;
                if !collection_ids.contains(collection_id.value()) {
                    let alias = (name.value().to_string(), collection_id.value().to_string());
                    if present_collection_ids.contains(collection_id.value()) {
                        aliases_with_corrupt_collection.push(alias);
                    } else {
                        corrupt_aliases.push(alias);
                    }
                }
            }
        }
        drop(txn);

        let mut orphan_secret_files = Vec::new();
        let mut recovery_secret_files = Vec::new();
        for entry in fs::read_dir(&self.secrets_dir)? {
            let entry = entry?;
            let path = entry.path();
            let file_name = entry.file_name().to_string_lossy().into_owned();
            if file_name.starts_with(".noirpass-backup-")
                || file_name.starts_with(".noirpass-quarantine-")
                || file_name.starts_with(".noirpass-create-")
                || file_name.starts_with(".noirpass-update-")
            {
                if !entry.file_type()?.is_file() {
                    return Err(Error::Config(format!(
                        "recovery path is not a regular file: {}",
                        path.display()
                    )));
                }
                recovery_secret_files.push(file_name);
                continue;
            }
            if path.extension().is_none_or(|extension| extension != "gpg") {
                continue;
            }
            if !entry.file_type()?.is_file() {
                return Err(Error::Config(format!(
                    "secret path is not a regular file: {}",
                    path.display()
                )));
            }
            let Some(id) = path.file_stem().and_then(|name| name.to_str()) else {
                orphan_secret_files.push(file_name);
                continue;
            };
            if !indexed.contains(id) {
                orphan_secret_files.push(file_name);
            }
        }
        orphan_secret_files.sort();
        recovery_secret_files.sort();

        Ok(IntegrityReport {
            corrupt_collections,
            missing_secret_items,
            corrupt_items,
            ciphertext_mismatches,
            items_with_invalid_collection,
            corrupt_aliases,
            aliases_with_corrupt_collection,
            orphan_secret_files,
            recovery_secret_files,
        })
    }

    // --- secret files ----------------------------------------------------

    pub(super) fn sync_secrets_dir(&self) -> Result<()> {
        fs::File::open(&self.secrets_dir)?.sync_all()?;
        Ok(())
    }

    pub(super) fn recovery_path(&self, kind: &str, id: &str) -> PathBuf {
        self.secrets_dir.join(format!(
            ".noirpass-{kind}-{id}-{:016x}.gpg",
            rand::random::<u64>()
        ))
    }

    pub(super) fn reserve_recovery_path(&self, kind: &str, id: &str) -> Result<PathBuf> {
        for _ in 0..16 {
            let path = self.recovery_path(kind, id);
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(file) => {
                    if let Err(sync_err) = file.sync_all() {
                        return match fs::remove_file(&path) {
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

    pub(super) fn finish_create_install(
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

    pub(super) fn cleanup_files(paths: &[&Path]) -> io::Result<()> {
        let mut first_error = None;
        for path in paths {
            if let Err(err) = fs::remove_file(path)
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

    pub(super) fn stage_secret_file(
        &self,
        id: &str,
        ciphertext: &[u8],
        kind: &str,
    ) -> Result<PathBuf> {
        for _ in 0..16 {
            let path = self.recovery_path(kind, id);
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(mut file) => {
                    if let Err(write_err) =
                        file.write_all(ciphertext).and_then(|()| file.sync_all())
                    {
                        return match fs::remove_file(&path) {
                            Ok(()) => Err(write_err.into()),
                            Err(cleanup_err) => self.poison_error(Error::Config(format!(
                                "failed to write staged ciphertext: {write_err}; cleanup {} also failed: {cleanup_err}",
                                path.display()
                            ))),
                        };
                    }
                    if let Err(sync_err) = self.sync_secrets_dir() {
                        return match fs::remove_file(&path) {
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

    pub(super) fn remove_recovery_file(
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
            if let Err(err) = fs::rename(quarantine, path)
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

    pub(super) fn replace_then_commit<T>(
        &self,
        path: &Path,
        staged: &Path,
        commit: impl FnOnce() -> std::result::Result<T, PersistError>,
    ) -> Result<T> {
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
                .and_then(|()| fs::File::open(&self.secrets_dir)?.sync_all());
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
                    .and_then(|()| fs::File::open(&self.secrets_dir)?.sync_all());
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

    pub(super) fn quarantine_then_commit<T>(
        &self,
        path: &Path,
        commit: impl FnOnce() -> std::result::Result<T, PersistError>,
    ) -> Result<T> {
        let id = path
            .file_stem()
            .and_then(|name| name.to_str())
            .ok_or_else(|| Error::Config(format!("invalid secret path: {}", path.display())))?;
        let quarantine = self.reserve_recovery_path("quarantine", id)?;
        let quarantined = match fs::rename(path, &quarantine) {
            Ok(()) => {
                if let Err(sync_err) = self.sync_secrets_dir() {
                    let restore = fs::rename(&quarantine, path)
                        .and_then(|()| fs::File::open(&self.secrets_dir)?.sync_all());
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
                .and_then(|()| fs::File::open(&self.secrets_dir)?.sync_all())
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

    pub(super) fn quarantine_many_then_commit<T>(
        &self,
        paths: &[PathBuf],
        commit: impl FnOnce() -> std::result::Result<T, PersistError>,
    ) -> Result<T> {
        let validated = paths
            .iter()
            .map(|path| {
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

    /// Atomically write `ciphertext` to `secrets/<id>.gpg` with `0600`
    /// permissions.
    pub(super) fn write_secret_file(&self, id: &str, ciphertext: &[u8]) -> Result<PathBuf> {
        let path = self.secret_path(id)?;
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

    /// Read item metadata and ciphertext under one shared transaction guard.
    pub fn read_item_secret(&self, id: &str) -> Result<(ItemMeta, Vec<u8>)> {
        self.read_item_secret_after_initial_check(id, || {})
    }

    pub(super) fn read_item_secret_after_initial_check(
        &self,
        id: &str,
        after_initial_check: impl FnOnce(),
    ) -> Result<(ItemMeta, Vec<u8>)> {
        let _read_guard = self.read_guard_checked_after_initial_check(after_initial_check)?;
        let metadata = self.get_item(id)?;
        let ciphertext = self.read_secret_file_unlocked(id)?;
        if let Some(expected_hash) = &metadata.ciphertext_sha256
            && ciphertext_sha256(&ciphertext) != *expected_hash
        {
            return Err(Error::Config(format!(
                "ciphertext digest does not match metadata for item {id}"
            )));
        }
        Ok((metadata, ciphertext))
    }

    /// Read the raw ciphertext of item `id`'s secret file.
    pub fn read_secret_file(&self, id: &str) -> Result<Vec<u8>> {
        self.read_secret_file_after_initial_check(id, || {})
    }

    pub(super) fn read_secret_file_after_initial_check(
        &self,
        id: &str,
        after_initial_check: impl FnOnce(),
    ) -> Result<Vec<u8>> {
        let _read_guard = self.read_guard_checked_after_initial_check(after_initial_check)?;
        self.read_secret_file_unlocked(id)
    }

    pub(super) fn read_secret_file_unlocked(&self, id: &str) -> Result<Vec<u8>> {
        self.ensure_not_poisoned()?;
        let path = self.secret_path(id)?;
        match fs::read(&path) {
            Ok(bytes) => Ok(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(Error::NotFound(format!("secret file for item {id}")))
            }
            Err(e) => Err(e.into()),
        }
    }
}
