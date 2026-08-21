//! On-disk storage: a redb metadata index plus one `.gpg` file per secret.
//!
//! The store keeps all searchable metadata (labels, attributes, timestamps,
//! collection membership, aliases) in a single `index.redb` database, and
//! writes each secret's ciphertext to `secrets/<item_id>.gpg`. The ciphertext
//! is produced by the caller (the `GnuPG` layer); the store never sees plaintext.
//!
//! All directories are created `0700` and all secret files `0600`. The redb
//! [`Database`] is `Send + Sync`, so every method takes `&self` and performs
//! its own short-lived transaction.

use std::collections::HashMap;
use std::fs;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use redb::{
    Database, DatabaseError, ReadOnlyDatabase, ReadableDatabase, ReadableTable, TableDefinition,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

mod files;
mod integrity;
mod persistence;
mod recovery;

/// id → `serde_json(CollectionMeta)`
const COLLECTIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("collections");
/// id → `serde_json(ItemMeta)`
const ITEMS: TableDefinition<&str, &[u8]> = TableDefinition::new("items");
/// alias name → collection id
const ALIASES: TableDefinition<&str, &str> = TableDefinition::new("aliases");

/// The well-known id, label and alias of the default collection.
pub const DEFAULT_COLLECTION_ID: &str = "default";

/// Metadata describing a collection (a named group of items).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionMeta {
    /// Stable identifier (either `"default"` or 16 random bytes as hex).
    pub id: String,
    /// Human-readable label.
    pub label: String,
    /// Creation time, seconds since the Unix epoch.
    pub created: u64,
    /// Last modification time, seconds since the Unix epoch.
    pub modified: u64,
}

/// Metadata describing a single stored secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemMeta {
    /// Stable identifier (16 random bytes as hex).
    pub id: String,
    /// Id of the owning collection.
    pub collection: String,
    /// Human-readable label.
    pub label: String,
    /// Lookup attributes; the Secret Service search key/value pairs.
    pub attributes: HashMap<String, String>,
    /// MIME-ish content type of the stored secret.
    pub content_type: String,
    /// SHA-256 of ciphertext used to resolve interrupted atomic updates.
    #[serde(default)]
    pub ciphertext_sha256: Option<String>,
    /// Creation time, seconds since the Unix epoch.
    pub created: u64,
    /// Last modification time, seconds since the Unix epoch.
    pub modified: u64,
}

/// A handle to the persistent metadata index and secret files.
#[derive(Debug)]
pub struct Store {
    db: Database,
    secrets_dir: PathBuf,
    poisoned: AtomicBool,
    transaction_gate: RwLock<()>,
}

/// Parsed item metadata paired with its authoritative redb table key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedItem {
    /// Authoritative item identity from the redb table key.
    pub table_key: String,
    /// Parsed metadata stored under `table_key`.
    pub metadata: ItemMeta,
}

/// Object identities removed by one collection deletion transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletedCollection {
    /// Item table keys removed with the collection.
    pub item_ids: Vec<String>,
    /// Alias names removed because they targeted the collection.
    pub aliases: Vec<String>,
}

/// Corrupt collection record that cannot safely be served over D-Bus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorruptCollection {
    /// Authoritative collection identity from the redb table key.
    pub table_key: String,
    /// Human-readable corruption detail.
    pub error: String,
}

/// Corrupt item record that cannot safely be treated as normal metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorruptItem {
    /// Authoritative item identity from the redb table key.
    pub table_key: String,
    /// Parsed metadata when JSON was valid but its embedded id mismatched.
    pub metadata: Option<ItemMeta>,
    /// Human-readable corruption detail.
    pub error: String,
}

/// Cross-check result for redb item metadata and `.gpg` files.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct IntegrityReport {
    /// Collection records with malformed, mismatched, or path-unsafe ids.
    pub corrupt_collections: Vec<CorruptCollection>,
    /// Items retained in redb whose ciphertext file is absent.
    pub missing_secret_items: Vec<IndexedItem>,
    /// Item records with malformed metadata or mismatched ids.
    pub corrupt_items: Vec<CorruptItem>,
    /// Valid item records whose ciphertext digest does not match metadata.
    pub ciphertext_mismatches: Vec<IndexedItem>,
    /// Valid item records whose collection owner is missing or corrupt.
    pub items_with_invalid_collection: Vec<CorruptItem>,
    /// Aliases that target a missing collection.
    pub corrupt_aliases: Vec<(String, String)>,
    /// Aliases retained because their target collection record is corrupt.
    pub aliases_with_corrupt_collection: Vec<(String, String)>,
    /// Ciphertext files that have no matching item table key.
    pub orphan_secret_files: Vec<String>,
    /// Recoverable backup/quarantine files left by interrupted maintenance.
    pub recovery_secret_files: Vec<String>,
}

impl IntegrityReport {
    /// True when every indexed item has one ciphertext file and no orphan exists.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.corrupt_collections.is_empty()
            && self.missing_secret_items.is_empty()
            && self.corrupt_items.is_empty()
            && self.ciphertext_mismatches.is_empty()
            && self.items_with_invalid_collection.is_empty()
            && self.corrupt_aliases.is_empty()
            && self.aliases_with_corrupt_collection.is_empty()
            && self.orphan_secret_files.is_empty()
            && self.recovery_secret_files.is_empty()
    }
}

enum PersistError {
    Definite(Error),
    Indeterminate(Error),
}

fn definite<E: Into<Error>>(error: E) -> PersistError {
    PersistError::Definite(error.into())
}

/// Seconds since the Unix epoch (saturating at 0 for pre-epoch clocks).
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Lowercase hex encoding of a byte slice.
fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// A fresh random 128-bit identifier rendered as 32 hex characters.
fn ciphertext_sha256(ciphertext: &[u8]) -> String {
    to_hex(&Sha256::digest(ciphertext))
}

fn random_id() -> String {
    let bytes: [u8; 16] = rand::random();
    to_hex(&bytes)
}

/// Whether `id` is a canonical item identifier safe for use as a filename.
fn is_valid_collection_id(id: &str) -> bool {
    id == DEFAULT_COLLECTION_ID || is_valid_item_id(id)
}

fn is_valid_item_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn decode_item(table_key: &str, value: &[u8]) -> Result<ItemMeta> {
    if !is_valid_item_id(table_key) {
        return Err(Error::Config(format!(
            "item table key is not canonical: {table_key}"
        )));
    }
    let metadata: ItemMeta = serde_json::from_slice(value)?;
    if metadata.id != table_key {
        return Err(Error::Config(format!(
            "item metadata id {} does not match table key {table_key}",
            metadata.id
        )));
    }
    Ok(metadata)
}

/// Create `dir` (if absent) and force its permissions to `0700`.
fn ensure_dir_0700(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// Validate store paths without opening redb.
fn existing_store_paths(dir: &Path) -> Result<(PathBuf, PathBuf)> {
    let secrets_dir = dir.join("secrets");
    let secrets_meta = fs::symlink_metadata(&secrets_dir)?;
    if !secrets_meta.is_dir() {
        return Err(Error::Config(format!(
            "store secrets path is not a directory: {}",
            secrets_dir.display()
        )));
    }
    let _ = fs::read_dir(&secrets_dir)?;

    let index_path = dir.join("index.redb");
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&index_path)?;

    Ok((secrets_dir, index_path))
}

impl Store {
    fn poison(&self) {
        self.poisoned.store(true, Ordering::Release);
    }

    fn ensure_not_poisoned(&self) -> Result<()> {
        if self.is_poisoned() {
            return Err(Error::Config(
                "store is unavailable after an indeterminate database commit".into(),
            ));
        }
        Ok(())
    }

    fn begin_write_checked(&self) -> Result<(RwLockWriteGuard<'_, ()>, redb::WriteTransaction)> {
        self.begin_write_checked_after_initial_check(|| {})
    }

    fn begin_write_checked_after_initial_check(
        &self,
        after_initial_check: impl FnOnce(),
    ) -> Result<(RwLockWriteGuard<'_, ()>, redb::WriteTransaction)> {
        let guard = self.write_guard_checked_after_initial_check(after_initial_check)?;
        let txn = self.db.begin_write()?;
        self.ensure_not_poisoned()?;
        Ok((guard, txn))
    }

    fn write_guard_checked(&self) -> Result<RwLockWriteGuard<'_, ()>> {
        self.write_guard_checked_after_initial_check(|| {})
    }

    fn write_guard_checked_after_initial_check(
        &self,
        after_initial_check: impl FnOnce(),
    ) -> Result<RwLockWriteGuard<'_, ()>> {
        self.ensure_not_poisoned()?;
        after_initial_check();
        let guard = self
            .transaction_gate
            .write()
            .map_err(|_| Error::Config("store transaction gate is poisoned".into()))?;
        self.ensure_not_poisoned()?;
        Ok(guard)
    }

    fn read_guard_checked_after_initial_check(
        &self,
        after_initial_check: impl FnOnce(),
    ) -> Result<RwLockReadGuard<'_, ()>> {
        self.ensure_not_poisoned()?;
        after_initial_check();
        let guard = self
            .transaction_gate
            .read()
            .map_err(|_| Error::Config("store transaction gate is poisoned".into()))?;
        self.ensure_not_poisoned()?;
        Ok(guard)
    }

    fn poison_error<T>(&self, error: Error) -> Result<T> {
        self.poison();
        Err(error)
    }

    fn finish_post_commit_cleanup(&self, result: Result<()>) -> Result<()> {
        if result.is_err() {
            self.poison();
        }
        result
    }

    fn finish_metadata_commit(
        &self,
        result: std::result::Result<(), redb::CommitError>,
    ) -> Result<()> {
        match result {
            Ok(()) => Ok(()),
            Err(err) => {
                self.poison();
                Err(Error::Config(format!(
                    "database commit outcome is indeterminate: {err}"
                )))
            }
        }
    }

    /// Whether an indeterminate database commit requires daemon shutdown.
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.poisoned.load(Ordering::Acquire)
    }

    /// Open (creating if necessary) a store rooted at `dir`.
    ///
    /// Creates `dir` and `dir/secrets/` as `0700` directories and opens (or
    /// creates) `dir/index.redb`.
    pub fn open(dir: &Path) -> Result<Self> {
        ensure_dir_0700(dir)?;
        let secrets_dir = dir.join("secrets");
        ensure_dir_0700(&secrets_dir)?;

        let db = Database::create(dir.join("index.redb"))?;
        // Ensure all tables exist so read-only transactions never fail on a
        // brand-new database.
        {
            let txn = db.begin_write()?;
            txn.open_table(COLLECTIONS)?;
            txn.open_table(ITEMS)?;
            txn.open_table(ALIASES)?;
            txn.commit()?;
        }

        Ok(Self {
            db,
            secrets_dir,
            poisoned: AtomicBool::new(false),
            transaction_gate: RwLock::new(()),
        })
    }

    /// Open an already initialized store without creating files or directories.
    ///
    /// Maintenance commands use this so a typo in `--store-dir` cannot create a
    /// second empty store. The redb writer lock also prevents offline mutation
    /// while the daemon is using the same index.
    pub fn open_existing(dir: &Path) -> Result<Self> {
        let (secrets_dir, index_path) = existing_store_paths(dir)?;
        let db = match Database::open(&index_path) {
            Ok(db) => db,
            Err(DatabaseError::DatabaseAlreadyOpen) => {
                return Err(Error::Config(format!(
                    "store is in use by another noirpass process: {}; stop the daemon before running maintenance commands",
                    index_path.display()
                )));
            }
            Err(err) => return Err(err.into()),
        };
        {
            let txn = db.begin_read()?;
            txn.open_table(COLLECTIONS)?;
            txn.open_table(ITEMS)?;
            txn.open_table(ALIASES)?;
        }
        Ok(Self {
            db,
            secrets_dir,
            poisoned: AtomicBool::new(false),
            transaction_gate: RwLock::new(()),
        })
    }

    /// Check whether an existing store is usable without mutating it.
    pub fn probe_health(dir: &Path) -> Result<()> {
        let (_, index_path) = existing_store_paths(dir)?;
        let db = match ReadOnlyDatabase::open(index_path) {
            Ok(db) => db,
            Err(DatabaseError::DatabaseAlreadyOpen) => return Ok(()),
            Err(err) => return Err(err.into()),
        };
        let txn = db.begin_read()?;
        txn.open_table(COLLECTIONS)?;
        txn.open_table(ITEMS)?;
        txn.open_table(ALIASES)?;
        Ok(())
    }

    /// Path of the `.gpg` secret file backing item `id`.
    fn secret_path(&self, id: &str) -> Result<PathBuf> {
        if !is_valid_item_id(id) {
            return Err(Error::Config(format!("invalid item id in store: {id}")));
        }
        Ok(self.secrets_dir.join(format!("{id}.gpg")))
    }

    // --- collections -----------------------------------------------------

    /// Create a new collection with the given label, optionally registering an
    /// alias that points at it.
    pub fn create_collection(&self, label: &str, alias: Option<&str>) -> Result<CollectionMeta> {
        let now = now_secs();
        let meta = CollectionMeta {
            id: random_id(),
            label: label.to_string(),
            created: now,
            modified: now,
        };

        let (_mutation_guard, txn) = self.begin_write_checked()?;
        {
            let mut table = txn.open_table(COLLECTIONS)?;
            let bytes = serde_json::to_vec(&meta)?;
            table.insert(meta.id.as_str(), bytes.as_slice())?;
        }
        if let Some(alias) = alias {
            let mut aliases = txn.open_table(ALIASES)?;
            aliases.insert(alias, meta.id.as_str())?;
        }
        self.finish_metadata_commit(txn.commit())?;
        Ok(meta)
    }

    /// Fetch a single collection by id.
    pub fn get_collection(&self, id: &str) -> Result<CollectionMeta> {
        self.ensure_not_poisoned()?;
        if !is_valid_collection_id(id) {
            return Err(Error::NotFound(format!("collection {id}")));
        }
        let txn = self.db.begin_read()?;
        let table = txn.open_table(COLLECTIONS)?;
        let metadata: CollectionMeta = match table.get(id)? {
            Some(value) => serde_json::from_slice(value.value())?,
            None => return Err(Error::NotFound(format!("collection {id}"))),
        };
        if metadata.id != id {
            return Err(Error::Config(format!(
                "collection metadata id {} does not match table key {id}",
                metadata.id
            )));
        }
        Ok(metadata)
    }

    /// List every collection, in id order.
    pub fn list_collections(&self) -> Result<Vec<CollectionMeta>> {
        self.ensure_not_poisoned()?;
        let txn = self.db.begin_read()?;
        let table = txn.open_table(COLLECTIONS)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            let table_key = key.value();
            if !is_valid_collection_id(table_key) {
                return Err(Error::Config(format!(
                    "invalid collection id in store: {table_key}"
                )));
            }
            let metadata: CollectionMeta = serde_json::from_slice(value.value())?;
            if metadata.id != table_key {
                return Err(Error::Config(format!(
                    "collection metadata id {} does not match table key {table_key}",
                    metadata.id
                )));
            }
            out.push(metadata);
        }
        Ok(out)
    }

    /// Delete a collection together with all its items, their `.gpg` files and
    /// any aliases pointing at it. Returns [`Error::NotFound`] if the
    /// collection does not exist.
    pub fn delete_collection(&self, id: &str) -> Result<DeletedCollection> {
        if !is_valid_collection_id(id) {
            return Err(Error::NotFound(format!("collection {id}")));
        }
        let (_mutation_guard, txn) = self.begin_write_checked()?;
        {
            let collections = txn.open_table(COLLECTIONS)?;
            let metadata: CollectionMeta = collections
                .get(id)?
                .map(|value| serde_json::from_slice(value.value()))
                .transpose()?
                .ok_or_else(|| Error::NotFound(format!("collection {id}")))?;
            if metadata.id != id {
                return Err(Error::Config(format!(
                    "collection metadata id {} does not match table key {id}",
                    metadata.id
                )));
            }
        }

        let mut item_ids = Vec::new();
        {
            let items = txn.open_table(ITEMS)?;
            for entry in items.iter()? {
                let (key, value) = entry?;
                let metadata: ItemMeta = serde_json::from_slice(value.value())?;
                if metadata.collection == id {
                    let item_id = key.value().to_string();
                    self.secret_path(&item_id)?;
                    if metadata.id != item_id {
                        return Err(Error::Config(format!(
                            "item metadata id {} does not match table key {item_id}",
                            metadata.id
                        )));
                    }
                    item_ids.push(item_id);
                }
            }
        }
        let paths = item_ids
            .iter()
            .map(|item_id| self.secret_path(item_id))
            .collect::<Result<Vec<_>>>()?;
        let aliases = {
            let aliases_table = txn.open_table(ALIASES)?;
            let mut aliases = Vec::new();
            for entry in aliases_table.iter()? {
                let (key, value) = entry?;
                if value.value() == id {
                    aliases.push(key.value().to_string());
                }
            }
            aliases
        };

        let commit = || -> std::result::Result<(), PersistError> {
            {
                let mut collections = txn.open_table(COLLECTIONS).map_err(definite)?;
                collections.remove(id).map_err(definite)?;
            }
            {
                let mut items = txn.open_table(ITEMS).map_err(definite)?;
                for item_id in &item_ids {
                    items.remove(item_id.as_str()).map_err(definite)?;
                }
            }
            {
                let mut aliases_table = txn.open_table(ALIASES).map_err(definite)?;
                for alias in &aliases {
                    aliases_table.remove(alias.as_str()).map_err(definite)?;
                }
            }
            txn.commit()
                .map_err(|err| PersistError::Indeterminate(err.into()))
        };
        self.quarantine_many_then_commit(&paths, commit)?;
        Ok(DeletedCollection { item_ids, aliases })
    }

    /// Ensure the well-known `default` collection (and its `default` alias)
    /// exist, creating them if missing. Returns the collection metadata.
    pub fn ensure_default(&self) -> Result<CollectionMeta> {
        let (_mutation_guard, txn) = self.begin_write_checked()?;
        let meta = {
            let mut collections = txn.open_table(COLLECTIONS)?;
            let existing = collections
                .get(DEFAULT_COLLECTION_ID)?
                .map(|value| value.value().to_vec());
            let meta = if let Some(bytes) = existing {
                let metadata: CollectionMeta = serde_json::from_slice(&bytes)?;
                if metadata.id != DEFAULT_COLLECTION_ID {
                    return Err(Error::Config(format!(
                        "collection metadata id {} does not match table key {DEFAULT_COLLECTION_ID}",
                        metadata.id
                    )));
                }
                metadata
            } else {
                let now = now_secs();
                let meta = CollectionMeta {
                    id: DEFAULT_COLLECTION_ID.to_string(),
                    label: "Default".to_string(),
                    created: now,
                    modified: now,
                };
                let bytes = serde_json::to_vec(&meta)?;
                collections.insert(DEFAULT_COLLECTION_ID, bytes.as_slice())?;
                meta
            };
            let mut aliases = txn.open_table(ALIASES)?;
            aliases.insert("default", DEFAULT_COLLECTION_ID)?;
            meta
        };
        self.finish_metadata_commit(txn.commit())?;
        Ok(meta)
    }

    /// Change a collection's label and bump its modified timestamp.
    pub fn set_collection_label(&self, id: &str, label: &str) -> Result<CollectionMeta> {
        if !is_valid_collection_id(id) {
            return Err(Error::NotFound(format!("collection {id}")));
        }
        let (_mutation_guard, txn) = self.begin_write_checked()?;
        let meta = {
            let mut collections = txn.open_table(COLLECTIONS)?;
            let bytes = collections
                .get(id)?
                .map(|value| value.value().to_vec())
                .ok_or_else(|| Error::NotFound(format!("collection {id}")))?;
            let mut meta: CollectionMeta = serde_json::from_slice(&bytes)?;
            if meta.id != id {
                return Err(Error::Config(format!(
                    "collection metadata id {} does not match table key {id}",
                    meta.id
                )));
            }
            meta.label = label.to_string();
            meta.modified = now_secs();
            let bytes = serde_json::to_vec(&meta)?;
            collections.insert(id, bytes.as_slice())?;
            meta
        };
        self.finish_metadata_commit(txn.commit())?;
        Ok(meta)
    }

    // --- aliases ---------------------------------------------------------

    /// Set (`Some`) or remove (`None`) the alias `name`.
    pub fn set_alias(&self, name: &str, collection_id: Option<&str>) -> Result<()> {
        let (_mutation_guard, txn) = self.begin_write_checked()?;
        if let Some(id) = collection_id {
            if !is_valid_collection_id(id) {
                return Err(Error::NotFound(format!("collection {id}")));
            }
            let collections = txn.open_table(COLLECTIONS)?;
            let metadata: CollectionMeta = collections
                .get(id)?
                .map(|value| serde_json::from_slice(value.value()))
                .transpose()?
                .ok_or_else(|| Error::NotFound(format!("collection {id}")))?;
            if metadata.id != id {
                return Err(Error::Config(format!(
                    "collection metadata id {} does not match table key {id}",
                    metadata.id
                )));
            }
        }
        {
            let mut aliases = txn.open_table(ALIASES)?;
            match collection_id {
                Some(id) => {
                    aliases.insert(name, id)?;
                }
                None => {
                    aliases.remove(name)?;
                }
            }
        }
        self.finish_metadata_commit(txn.commit())?;
        Ok(())
    }

    /// Resolve alias `name` to a collection id, or `None` if unset.
    pub fn read_alias(&self, name: &str) -> Result<Option<String>> {
        self.ensure_not_poisoned()?;
        let txn = self.db.begin_read()?;
        let aliases = txn.open_table(ALIASES)?;
        Ok(aliases.get(name)?.map(|v| v.value().to_string()))
    }

    /// List every alias as `(name, collection_id)` pairs.
    pub fn list_aliases(&self) -> Result<Vec<(String, String)>> {
        self.ensure_not_poisoned()?;
        let txn = self.db.begin_read()?;
        let aliases = txn.open_table(ALIASES)?;
        let mut out = Vec::new();
        for entry in aliases.iter()? {
            let (k, v) = entry?;
            out.push((k.value().to_string(), v.value().to_string()));
        }
        Ok(out)
    }

    // --- items -----------------------------------------------------------

    /// Create an item in `collection`, writing its ciphertext to a fresh
    /// `0600` secret file. The collection must already exist.
    pub fn create_item(
        &self,
        collection: &str,
        label: &str,
        attributes: HashMap<String, String>,
        content_type: &str,
        secret_ciphertext: &[u8],
    ) -> Result<ItemMeta> {
        if !is_valid_collection_id(collection) {
            return Err(Error::NotFound(format!("collection {collection}")));
        }
        let (_mutation_guard, txn) = self.begin_write_checked()?;
        Self::validate_item_collection(&txn, collection)?;
        self.create_item_locked(
            txn,
            collection,
            label,
            attributes,
            content_type,
            secret_ciphertext,
        )
    }

    /// Create an item or atomically replace an exact attribute match.
    pub fn create_or_replace_item(
        &self,
        collection: &str,
        label: &str,
        attributes: HashMap<String, String>,
        content_type: &str,
        secret_ciphertext: &[u8],
        replace: bool,
    ) -> Result<(ItemMeta, bool)> {
        self.create_or_replace_item_after_initial_check(
            collection,
            label,
            attributes,
            content_type,
            secret_ciphertext,
            replace,
            || {},
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "test hook preserves production replace inputs while controlling gate contention"
    )]
    fn create_or_replace_item_after_initial_check(
        &self,
        collection: &str,
        label: &str,
        attributes: HashMap<String, String>,
        content_type: &str,
        secret_ciphertext: &[u8],
        replace: bool,
        after_initial_check: impl FnOnce(),
    ) -> Result<(ItemMeta, bool)> {
        if !is_valid_collection_id(collection) {
            return Err(Error::NotFound(format!("collection {collection}")));
        }
        let (_mutation_guard, txn) =
            self.begin_write_checked_after_initial_check(after_initial_check)?;
        Self::validate_item_collection(&txn, collection)?;
        let existing = if replace {
            Self::find_item_by_attrs_exact_locked(&txn, collection, &attributes)?
        } else {
            None
        };
        match existing {
            Some(metadata) => self
                .update_item_locked(
                    txn,
                    &metadata.id,
                    Some(label),
                    None,
                    Some(content_type),
                    Some(secret_ciphertext),
                )
                .map(|metadata| (metadata, true)),
            None => self
                .create_item_locked(
                    txn,
                    collection,
                    label,
                    attributes,
                    content_type,
                    secret_ciphertext,
                )
                .map(|metadata| (metadata, false)),
        }
    }

    fn validate_item_collection(txn: &redb::WriteTransaction, collection: &str) -> Result<()> {
        let collections = txn.open_table(COLLECTIONS)?;
        let metadata: CollectionMeta = collections
            .get(collection)?
            .map(|value| serde_json::from_slice(value.value()))
            .transpose()?
            .ok_or_else(|| Error::NotFound(format!("collection {collection}")))?;
        if metadata.id != collection {
            return Err(Error::Config(format!(
                "collection metadata id {} does not match table key {collection}",
                metadata.id
            )));
        }
        Ok(())
    }

    fn find_item_by_attrs_exact_locked(
        txn: &redb::WriteTransaction,
        collection: &str,
        attrs: &HashMap<String, String>,
    ) -> Result<Option<ItemMeta>> {
        let items = txn.open_table(ITEMS)?;
        for entry in items.iter()? {
            let (key, value) = entry?;
            let metadata = decode_item(key.value(), value.value())?;
            if metadata.collection == collection && &metadata.attributes == attrs {
                return Ok(Some(metadata));
            }
        }
        Ok(None)
    }

    fn create_item_locked(
        &self,
        txn: redb::WriteTransaction,
        collection: &str,
        label: &str,
        attributes: HashMap<String, String>,
        content_type: &str,
        secret_ciphertext: &[u8],
    ) -> Result<ItemMeta> {
        let now = now_secs();
        let meta = ItemMeta {
            id: random_id(),
            collection: collection.to_string(),
            label: label.to_string(),
            attributes,
            content_type: content_type.to_string(),
            ciphertext_sha256: Some(ciphertext_sha256(secret_ciphertext)),
            created: now,
            modified: now,
        };
        let create_marker = self.write_secret_file(&meta.id, secret_ciphertext)?;
        let persist_result = (|| -> std::result::Result<(), PersistError> {
            {
                let mut items = txn.open_table(ITEMS).map_err(definite)?;
                let bytes = serde_json::to_vec(&meta).map_err(definite)?;
                items
                    .insert(meta.id.as_str(), bytes.as_slice())
                    .map_err(definite)?;
            }
            txn.commit()
                .map_err(|err| PersistError::Indeterminate(err.into()))
        })();
        self.finish_create_persist(&meta.id, &create_marker, persist_result)?;
        Ok(meta)
    }

    fn finish_create_persist(
        &self,
        id: &str,
        create_marker: &Path,
        persist_result: std::result::Result<(), PersistError>,
    ) -> Result<()> {
        match persist_result {
            Ok(()) => {
                self.finish_post_commit_cleanup(Self::remove_recovery_file(
                    create_marker,
                    "item metadata committed",
                    |path| fs::remove_file(path),
                ))?;
                self.finish_post_commit_cleanup(self.sync_secrets_dir())
            }
            Err(PersistError::Definite(err)) => {
                let path = self.secret_path(id)?;
                if let Err(cleanup_err) = fs::remove_file(&path) {
                    return self.poison_error(Error::Config(format!(
                        "item metadata write failed: {err}; unindexed ciphertext cleanup failed at {}: {cleanup_err}",
                        path.display()
                    )));
                }
                if let Err(sync_err) = self.sync_secrets_dir() {
                    return self.poison_error(Error::Config(format!(
                        "item metadata write failed: {err}; unindexed ciphertext was removed, but directory sync failed: {sync_err}"
                    )));
                }
                if let Err(cleanup_err) = fs::remove_file(create_marker) {
                    return self.poison_error(Error::Config(format!(
                        "item metadata write failed: {err}; create marker cleanup failed at {}: {cleanup_err}",
                        create_marker.display()
                    )));
                }
                match self.sync_secrets_dir() {
                    Ok(()) => Err(err),
                    Err(sync_err) => self.poison_error(Error::Config(format!(
                        "item metadata write failed: {err}; create marker was removed, but directory sync failed: {sync_err}"
                    ))),
                }
            }
            Err(PersistError::Indeterminate(err)) => {
                self.poison();
                Err(Error::Config(format!(
                    "item metadata commit outcome is indeterminate: {err}; ciphertext retained for restart reconciliation"
                )))
            }
        }
    }

    /// Fetch a single item by id.
    pub fn get_item(&self, id: &str) -> Result<ItemMeta> {
        self.ensure_not_poisoned()?;
        self.secret_path(id)?;
        let txn = self.db.begin_read()?;
        let items = txn.open_table(ITEMS)?;
        let metadata: ItemMeta = match items.get(id)? {
            Some(value) => serde_json::from_slice(value.value())?,
            None => return Err(Error::NotFound(format!("item {id}"))),
        };
        if metadata.id != id {
            return Err(Error::Config(format!(
                "item metadata id {} does not match table key {id}",
                metadata.id
            )));
        }
        Ok(metadata)
    }

    /// List every item in `collection`, in id order.
    pub fn list_items(&self, collection: &str) -> Result<Vec<ItemMeta>> {
        self.ensure_not_poisoned()?;
        let txn = self.db.begin_read()?;
        let items = txn.open_table(ITEMS)?;
        let mut out = Vec::new();
        for entry in items.iter()? {
            let (key, value) = entry?;
            let metadata = decode_item(key.value(), value.value())?;
            if metadata.collection == collection {
                out.push(metadata);
            }
        }
        Ok(out)
    }

    /// Find an item in `collection` whose attribute set is *exactly* `attrs`.
    pub fn find_item_by_attrs_exact(
        &self,
        collection: &str,
        attrs: &HashMap<String, String>,
    ) -> Result<Option<ItemMeta>> {
        self.ensure_not_poisoned()?;
        let txn = self.db.begin_read()?;
        let items = txn.open_table(ITEMS)?;
        for entry in items.iter()? {
            let (key, value) = entry?;
            let metadata = decode_item(key.value(), value.value())?;
            if metadata.collection == collection && &metadata.attributes == attrs {
                return Ok(Some(metadata));
            }
        }
        Ok(None)
    }

    /// Search all items for those whose attributes are a superset of `attrs`.
    ///
    /// An item matches when every `(k, v)` in `attrs` is present with the same
    /// value; an empty query therefore matches every item. This is a full
    /// table scan, which is acceptable for the expected data sizes.
    pub fn search_items(&self, attrs: &HashMap<String, String>) -> Result<Vec<ItemMeta>> {
        self.ensure_not_poisoned()?;
        let txn = self.db.begin_read()?;
        let items = txn.open_table(ITEMS)?;
        let mut out = Vec::new();
        for entry in items.iter()? {
            let (key, value) = entry?;
            let metadata = decode_item(key.value(), value.value())?;
            let matches = attrs.iter().all(|(name, expected)| {
                metadata
                    .attributes
                    .get(name)
                    .is_some_and(|actual| actual == expected)
            });
            if matches {
                out.push(metadata);
            }
        }
        Ok(out)
    }

    /// Update an item's label, attributes, content type and/or secret and bump
    /// its modified timestamp. `None` fields are left unchanged; a `Some`
    /// secret rewrites the `.gpg` file.
    pub fn update_item(
        &self,
        id: &str,
        label: Option<&str>,
        attributes: Option<HashMap<String, String>>,
        content_type: Option<&str>,
        secret_ciphertext: Option<&[u8]>,
    ) -> Result<ItemMeta> {
        self.secret_path(id)?;
        let (_mutation_guard, txn) = self.begin_write_checked()?;
        self.update_item_locked(txn, id, label, attributes, content_type, secret_ciphertext)
    }

    fn update_item_locked(
        &self,
        txn: redb::WriteTransaction,
        id: &str,
        label: Option<&str>,
        attributes: Option<HashMap<String, String>>,
        content_type: Option<&str>,
        secret_ciphertext: Option<&[u8]>,
    ) -> Result<ItemMeta> {
        let mut meta = {
            let items = txn.open_table(ITEMS)?;
            let bytes = items
                .get(id)?
                .map(|value| value.value().to_vec())
                .ok_or_else(|| Error::NotFound(format!("item {id}")))?;
            decode_item(id, &bytes)?
        };
        if let Some(label) = label {
            meta.label = label.to_string();
        }
        if let Some(attrs) = attributes {
            meta.attributes = attrs;
        }
        if let Some(content_type) = content_type {
            meta.content_type = content_type.to_string();
        }
        if let Some(secret) = secret_ciphertext {
            meta.ciphertext_sha256 = Some(ciphertext_sha256(secret));
        }
        meta.modified = now_secs();

        let bytes = serde_json::to_vec(&meta)?;
        let commit = || -> std::result::Result<(), PersistError> {
            {
                let mut items = txn.open_table(ITEMS).map_err(definite)?;
                items.insert(id, bytes.as_slice()).map_err(definite)?;
            }
            txn.commit()
                .map_err(|err| PersistError::Indeterminate(err.into()))
        };
        if let Some(secret) = secret_ciphertext {
            let path = self.secret_path(id)?;
            let staged = self.stage_secret_file(id, secret, "update")?;
            self.replace_then_commit(&path, &staged, commit)?;
        } else {
            match commit() {
                Ok(()) => {}
                Err(PersistError::Definite(err)) => return Err(err),
                Err(PersistError::Indeterminate(err)) => {
                    self.poison();
                    return Err(Error::Config(format!(
                        "item metadata commit outcome is indeterminate: {err}"
                    )));
                }
            }
        }
        Ok(meta)
    }

    /// Delete an item and its secret file. Returns [`Error::NotFound`] if the
    /// item does not exist.
    pub fn delete_item(&self, id: &str) -> Result<()> {
        let path = self.secret_path(id)?;
        let (_mutation_guard, txn) = self.begin_write_checked()?;
        {
            let items = txn.open_table(ITEMS)?;
            if items.get(id)?.is_none() {
                return Err(Error::NotFound(format!("item {id}")));
            }
        }
        let commit = || -> std::result::Result<(), PersistError> {
            {
                let mut items = txn
                    .open_table(ITEMS)
                    .map_err(|err| PersistError::Definite(err.into()))?;
                items
                    .remove(id)
                    .map_err(|err| PersistError::Definite(err.into()))?;
            }
            txn.commit()
                .map_err(|err| PersistError::Indeterminate(err.into()))
        };
        self.quarantine_then_commit(&path, commit)
    }

    /// Delete only an item metadata record using its authoritative redb key.
    ///
    /// Used by integrity repair for noncanonical keys that must never become
    /// filesystem paths.
    pub fn delete_item_metadata(&self, table_key: &str) -> Result<()> {
        let (_mutation_guard, txn) = self.begin_write_checked()?;
        {
            let mut items = txn.open_table(ITEMS)?;
            if items.remove(table_key)?.is_none() {
                return Err(Error::NotFound(format!("item {table_key}")));
            }
        }
        self.finish_metadata_commit(txn.commit())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
