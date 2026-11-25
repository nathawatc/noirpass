//! Store integrity scanning and startup safety policy.

use std::collections::HashSet;
use std::io;
use std::path::Path;

use redb::{DatabaseError, ReadableDatabase, ReadableTable};

use crate::error::{Error, Result};
use crate::filesystem::Directory;

use super::{
    ALIASES, COLLECTIONS, CollectionMeta, CorruptCollection, CorruptItem, ITEMS, IndexedItem,
    IntegrityReport, ItemMeta, Store, ciphertext_file_sha256, is_valid_collection_id,
    is_valid_item_id, parse_recovery_secret_name, recovery_kind,
};

impl Store {
    /// Refuse daemon startup while unresolved integrity problems exist.
    pub fn ensure_safe_to_serve(&self) -> Result<()> {
        let _read_guard = self.read_guard_checked_after_initial_check(|| {})?;
        let mut index = self
            .item_index
            .read()
            .map_err(|_| Error::Config("item lookup index is poisoned".into()))?
            .is_none()
            .then(super::items::ItemIndex::default);
        // Reuse mandatory startup validation instead of decoding every item
        // again when the first lookup arrives. The shared gate pins this snapshot.
        let report = scan_integrity(
            &self.db,
            &self.secrets_dir,
            &self.secrets_directory,
            index.as_mut(),
        )?;
        if report.is_healthy() {
            if let Some(index) = index {
                *self
                    .item_index
                    .write()
                    .map_err(|_| Error::Config("item lookup index is poisoned".into()))? =
                    Some(index);
            }
            return Ok(());
        }
        *self
            .item_index
            .write()
            .map_err(|_| Error::Config("item lookup index is poisoned".into()))? = None;
        Err(Error::Config(
            "store integrity check failed; run `noirpass check` before starting daemon".into(),
        ))
    }

    /// Cross-check every redb item against ciphertext files on disk.
    pub fn check_integrity(&self) -> Result<IntegrityReport> {
        scan_integrity(&self.db, &self.secrets_dir, &self.secrets_directory, None)
    }

    /// Cross-check an existing store without acquiring its writer lock.
    pub(crate) fn probe_integrity_in(dir: &Path, root: &Directory) -> Result<IntegrityReport> {
        let (secrets_dir, secrets_directory) = super::open_existing_secrets(dir, root)?;
        let index = root
            .open_regular(Path::new("index.redb"), libc::O_RDONLY, 0)
            .map_err(DatabaseError::from)?;
        let db = match super::open_readonly_database_file(&index) {
            Ok(db) => db,
            Err(DatabaseError::DatabaseAlreadyOpen) => {
                // The running daemon already passed startup integrity admission. Preserve the
                // non-mutating busy-store status behavior instead of racing its live database.
                return Ok(IntegrityReport::default());
            }
            Err(err) => return Err(err.into()),
        };
        scan_integrity(&db, &secrets_dir, &secrets_directory, None)
    }

    #[cfg(test)]
    pub(crate) fn probe_integrity(dir: &Path) -> Result<IntegrityReport> {
        let root = super::open_existing_root(dir)?;
        Self::probe_integrity_in(dir, &root)
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "single read transaction validates related collection, item, and alias tables"
)]
fn scan_integrity<D: ReadableDatabase>(
    db: &D,
    secrets_dir: &Path,
    directory: &Directory,
    mut index: Option<&mut super::items::ItemIndex>,
) -> Result<IntegrityReport> {
    let txn = db.begin_read()?;
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
                if metadata.id == table_key && collection_ids.contains(&metadata.collection) =>
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
        if let Some(index) = index.as_mut() {
            index.insert(&metadata);
        }
        let path = super::secret_path(secrets_dir, &table_key)?;
        match directory.metadata(Path::new(path.file_name().expect("canonical filename"))) {
            Ok(file_metadata) if file_metadata.file_type().is_file() => {
                if let Some(expected_hash) = &metadata.ciphertext_sha256 {
                    let mut file = directory.open_regular(
                        Path::new(path.file_name().expect("canonical filename")),
                        libc::O_RDONLY,
                        0,
                    )?;
                    if ciphertext_file_sha256(&mut file)? != *expected_hash {
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
    for entry in directory.read_dir()? {
        let entry = entry?;
        let path = secrets_dir.join(entry.file_name());
        let file_name = entry.file_name().to_string_lossy().into_owned();
        if parse_recovery_secret_name(&file_name).is_some() {
            if !directory.metadata(Path::new(&entry.file_name()))?.is_file() {
                return Err(Error::Config(format!(
                    "recovery path is not a regular file: {}",
                    path.display()
                )));
            }
            recovery_secret_files.push(file_name);
            continue;
        }
        if recovery_kind(&file_name).is_some() {
            return Err(Error::Config(format!(
                "invalid recovery file: {}",
                path.display()
            )));
        }
        if path.extension().is_none_or(|extension| extension != "gpg") {
            continue;
        }
        if !directory.metadata(Path::new(&entry.file_name()))?.is_file() {
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
