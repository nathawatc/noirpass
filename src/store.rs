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

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
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
    let secrets_meta = fs::metadata(&secrets_dir)?;
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

    fn sync_secrets_dir(&self) -> Result<()> {
        fs::File::open(&self.secrets_dir)?.sync_all()?;
        Ok(())
    }

    fn recovery_path(&self, kind: &str, id: &str) -> PathBuf {
        self.secrets_dir.join(format!(
            ".noirpass-{kind}-{id}-{:016x}.gpg",
            rand::random::<u64>()
        ))
    }

    fn reserve_recovery_path(&self, kind: &str, id: &str) -> Result<PathBuf> {
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

    fn finish_create_install(
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

    fn cleanup_files(paths: &[&Path]) -> io::Result<()> {
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

    fn stage_secret_file(&self, id: &str, ciphertext: &[u8], kind: &str) -> Result<PathBuf> {
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

    fn remove_recovery_file(
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

    fn restore_quarantines(&self, moves: &[(PathBuf, PathBuf)]) -> Result<()> {
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

    fn replace_then_commit<T>(
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

    fn quarantine_then_commit<T>(
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

    fn quarantine_many_then_commit<T>(
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
    fn write_secret_file(&self, id: &str, ciphertext: &[u8]) -> Result<PathBuf> {
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

    fn read_item_secret_after_initial_check(
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

    fn read_secret_file_after_initial_check(
        &self,
        id: &str,
        after_initial_check: impl FnOnce(),
    ) -> Result<Vec<u8>> {
        let _read_guard = self.read_guard_checked_after_initial_check(after_initial_check)?;
        self.read_secret_file_unlocked(id)
    }

    fn read_secret_file_unlocked(&self, id: &str) -> Result<Vec<u8>> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn attrs(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn open_creates_dirs_with_0700() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("store");
        let store = Store::open(&root).unwrap();
        assert_eq!(mode(&root), 0o700);
        assert_eq!(mode(&store.secrets_dir), 0o700);
    }

    #[test]
    fn collection_crud() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();

        let c = store
            .create_collection("Personal", Some("personal"))
            .unwrap();
        assert_eq!(c.label, "Personal");
        assert_eq!(store.get_collection(&c.id).unwrap(), c);
        assert_eq!(store.read_alias("personal").unwrap(), Some(c.id.clone()));

        let all = store.list_collections().unwrap();
        assert_eq!(all.len(), 1);

        let relabelled = store.set_collection_label(&c.id, "Work").unwrap();
        assert_eq!(relabelled.label, "Work");
        assert!(relabelled.modified >= c.modified);
        assert_eq!(store.get_collection(&c.id).unwrap().label, "Work");

        store.delete_collection(&c.id).unwrap();
        assert!(matches!(
            store.get_collection(&c.id),
            Err(Error::NotFound(_))
        ));
        assert!(matches!(
            store.delete_collection(&c.id),
            Err(Error::NotFound(_))
        ));
    }

    #[test]
    fn ensure_default_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let a = store.ensure_default().unwrap();
        let b = store.ensure_default().unwrap();
        assert_eq!(a, b);
        assert_eq!(a.id, DEFAULT_COLLECTION_ID);
        assert_eq!(
            store.read_alias("default").unwrap().as_deref(),
            Some(DEFAULT_COLLECTION_ID)
        );
        assert_eq!(store.list_collections().unwrap().len(), 1);
    }

    #[test]
    fn alias_set_read_remove() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        assert_eq!(store.read_alias("missing").unwrap(), None);

        let collection = store.create_collection("c", None).unwrap();
        store.set_alias("session", Some(&collection.id)).unwrap();
        assert_eq!(
            store.read_alias("session").unwrap().as_deref(),
            Some(collection.id.as_str())
        );
        assert_eq!(
            store.list_aliases().unwrap(),
            vec![("session".to_string(), collection.id)]
        );

        store.set_alias("session", None).unwrap();
        assert_eq!(store.read_alias("session").unwrap(), None);
        assert!(store.list_aliases().unwrap().is_empty());
    }

    #[test]
    fn item_crud_and_secret_perms() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let c = store.create_collection("c", None).unwrap();

        let item = store
            .create_item(
                &c.id,
                "wifi",
                attrs(&[("service", "wifi"), ("user", "me")]),
                "text/plain",
                b"CIPHERTEXT-1",
            )
            .unwrap();

        assert_eq!(store.get_item(&item.id).unwrap(), item);
        assert_eq!(store.read_secret_file(&item.id).unwrap(), b"CIPHERTEXT-1");
        assert_eq!(mode(&store.secret_path(&item.id).unwrap()), 0o600);
        assert_eq!(store.list_items(&c.id).unwrap().len(), 1);

        let updated = store
            .update_item(
                &item.id,
                Some("wifi-home"),
                None,
                None,
                Some(b"CIPHERTEXT-2"),
            )
            .unwrap();
        assert_eq!(updated.label, "wifi-home");
        assert!(updated.modified >= item.modified);
        assert_eq!(store.read_secret_file(&item.id).unwrap(), b"CIPHERTEXT-2");

        store.delete_item(&item.id).unwrap();
        assert!(matches!(store.get_item(&item.id), Err(Error::NotFound(_))));
        assert!(matches!(
            store.read_secret_file(&item.id),
            Err(Error::NotFound(_))
        ));
    }

    #[test]
    fn create_item_in_missing_collection_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        assert!(matches!(
            store.create_item("nope", "x", HashMap::new(), "text/plain", b"c"),
            Err(Error::NotFound(_))
        ));
    }

    #[test]
    fn find_item_by_attrs_exact_matches_full_set_only() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let c = store.create_collection("c", None).unwrap();
        let a = attrs(&[("service", "mail"), ("user", "a")]);
        let item = store
            .create_item(&c.id, "mail", a.clone(), "text/plain", b"c")
            .unwrap();

        assert_eq!(
            store
                .find_item_by_attrs_exact(&c.id, &a)
                .unwrap()
                .unwrap()
                .id,
            item.id
        );
        // A strict subset is not an exact match.
        let subset = attrs(&[("service", "mail")]);
        assert!(
            store
                .find_item_by_attrs_exact(&c.id, &subset)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn concurrent_exact_replacements_create_one_item() {
        let tmp = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(Store::open(tmp.path()).unwrap());
        let collection = store.create_collection("c", None).unwrap();
        let attributes = attrs(&[("service", "mail"), ("user", "me")]);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let mut workers = Vec::new();
        for ciphertext in [b"first".as_slice(), b"second".as_slice()] {
            let worker_store = std::sync::Arc::clone(&store);
            let worker_collection = collection.id.clone();
            let worker_attributes = attributes.clone();
            let worker_barrier = std::sync::Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                worker_store
                    .create_or_replace_item_after_initial_check(
                        &worker_collection,
                        "mail",
                        worker_attributes,
                        "text/plain",
                        ciphertext,
                        true,
                        || {
                            worker_barrier.wait();
                        },
                    )
                    .unwrap()
            }));
        }

        let first = workers.remove(0).join().unwrap();
        let second = workers.remove(0).join().unwrap();
        assert_eq!(first.0.id, second.0.id);
        assert_ne!(first.1, second.1);
        let items = store.list_items(&collection.id).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].attributes, attributes);
        let (metadata, ciphertext) = store.read_item_secret(&items[0].id).unwrap();
        assert_eq!(metadata, items[0]);
        assert!(ciphertext == b"first" || ciphertext == b"second");
    }

    #[test]
    fn search_subset_semantics() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let c = store.create_collection("c", None).unwrap();

        store
            .create_item(
                &c.id,
                "one",
                attrs(&[("service", "mail"), ("user", "a")]),
                "text/plain",
                b"1",
            )
            .unwrap();
        store
            .create_item(
                &c.id,
                "two",
                attrs(&[("service", "mail"), ("user", "b")]),
                "text/plain",
                b"2",
            )
            .unwrap();
        store
            .create_item(
                &c.id,
                "three",
                attrs(&[("service", "chat"), ("user", "a")]),
                "text/plain",
                b"3",
            )
            .unwrap();

        // Empty query matches everything.
        assert_eq!(store.search_items(&HashMap::new()).unwrap().len(), 3);
        // Single attribute subset.
        assert_eq!(
            store
                .search_items(&attrs(&[("service", "mail")]))
                .unwrap()
                .len(),
            2
        );
        // Multiple attributes must all match.
        assert_eq!(
            store
                .search_items(&attrs(&[("service", "mail"), ("user", "a")]))
                .unwrap()
                .len(),
            1
        );
        // No match.
        assert_eq!(
            store
                .search_items(&attrs(&[("service", "vpn")]))
                .unwrap()
                .len(),
            0
        );
    }

    #[test]
    fn delete_collection_cascades() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let c = store.create_collection("c", Some("c-alias")).unwrap();
        let other = store.create_collection("other", None).unwrap();

        let i1 = store
            .create_item(&c.id, "a", attrs(&[("k", "v")]), "text/plain", b"1")
            .unwrap();
        let i2 = store
            .create_item(&c.id, "b", attrs(&[("k", "w")]), "text/plain", b"2")
            .unwrap();
        let survivor = store
            .create_item(&other.id, "s", attrs(&[("k", "x")]), "text/plain", b"3")
            .unwrap();

        let p1 = store.secret_path(&i1.id).unwrap();
        let p2 = store.secret_path(&i2.id).unwrap();
        assert!(p1.exists() && p2.exists());

        let deleted = store.delete_collection(&c.id).unwrap();
        assert_eq!(
            deleted.item_ids.into_iter().collect::<HashSet<_>>(),
            HashSet::from([i1.id.clone(), i2.id.clone()])
        );
        assert_eq!(deleted.aliases, vec!["c-alias".to_string()]);

        // Items and secret files gone, alias gone.
        assert!(matches!(store.get_item(&i1.id), Err(Error::NotFound(_))));
        assert!(matches!(store.get_item(&i2.id), Err(Error::NotFound(_))));
        assert!(!p1.exists() && !p2.exists());
        assert_eq!(store.read_alias("c-alias").unwrap(), None);

        // The other collection and its item survive.
        assert!(store.get_collection(&other.id).is_ok());
        assert!(store.get_item(&survivor.id).is_ok());
    }

    #[test]
    fn ensure_default_repairs_missing_alias() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let original = store.ensure_default().unwrap();
        store.set_alias("default", None).unwrap();

        let repaired = store.ensure_default().unwrap();

        assert_eq!(repaired, original);
        assert_eq!(
            store.read_alias("default").unwrap().as_deref(),
            Some(DEFAULT_COLLECTION_ID)
        );
    }

    #[test]
    fn open_existing_refuses_missing_or_locked_store() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("missing");
        assert!(Store::open_existing(&missing).is_err());
        assert!(!missing.exists());

        let store = Store::open(tmp.path()).unwrap();
        let err = Store::open_existing(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("store is in use"));
        drop(store);
        assert!(Store::open_existing(tmp.path()).is_ok());
    }

    #[test]
    fn collection_reads_and_updates_reject_embedded_id_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let valid_b = store.create_collection("valid-b", None).unwrap();
        let key_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let corrupt = CollectionMeta {
            label: "corrupt-a".to_string(),
            ..valid_b.clone()
        };
        let txn = store.db.begin_write().unwrap();
        {
            let mut collections = txn.open_table(COLLECTIONS).unwrap();
            let bytes = serde_json::to_vec(&corrupt).unwrap();
            collections.insert(key_a, bytes.as_slice()).unwrap();
        }
        txn.commit().unwrap();

        assert!(store.get_collection(key_a).is_err());
        assert!(store.set_collection_label(key_a, "changed").is_err());
        assert_eq!(store.get_collection(&valid_b.id).unwrap(), valid_b);
        let report = store.check_integrity().unwrap();
        assert_eq!(report.corrupt_collections.len(), 1);
        assert_eq!(report.corrupt_collections[0].table_key, key_a);
    }

    #[test]
    fn integrity_reports_missing_item_owner_and_dangling_alias() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let collection = store.create_collection("owner", None).unwrap();
        let item = store
            .create_item(
                &collection.id,
                "item",
                HashMap::new(),
                "text/plain",
                b"ciphertext",
            )
            .unwrap();
        let txn = store.db.begin_write().unwrap();
        {
            let mut items = txn.open_table(ITEMS).unwrap();
            let mut metadata = item.clone();
            metadata.collection = "cccccccccccccccccccccccccccccccc".to_string();
            let bytes = serde_json::to_vec(&metadata).unwrap();
            items.insert(item.id.as_str(), bytes.as_slice()).unwrap();
            let mut aliases = txn.open_table(ALIASES).unwrap();
            aliases
                .insert("dangling", metadata.collection.as_str())
                .unwrap();
        }
        txn.commit().unwrap();

        let report = store.check_integrity().unwrap();
        assert!(report.corrupt_items.is_empty());
        assert_eq!(report.items_with_invalid_collection.len(), 1);
        assert!(
            report.items_with_invalid_collection[0]
                .error
                .contains("missing collection")
        );
        assert_eq!(
            report.corrupt_aliases,
            vec![(
                "dangling".to_string(),
                "cccccccccccccccccccccccccccccccc".to_string()
            )]
        );
    }

    #[test]
    fn integrity_reports_missing_and_orphan_ciphertext() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let collection = store.create_collection("c", None).unwrap();
        let missing = store
            .create_item(
                &collection.id,
                "missing",
                attrs(&[("k", "v")]),
                "text/plain",
                b"ciphertext",
            )
            .unwrap();
        let present = store
            .create_item(
                &collection.id,
                "present",
                attrs(&[("k", "w")]),
                "text/plain",
                b"ciphertext",
            )
            .unwrap();
        fs::remove_file(store.secret_path(&missing.id).unwrap()).unwrap();
        fs::write(store.secrets_dir.join("orphan.gpg"), b"ciphertext").unwrap();

        let report = store.check_integrity().unwrap();

        assert_eq!(
            report.missing_secret_items,
            vec![IndexedItem {
                table_key: missing.id.clone(),
                metadata: missing.clone(),
            }]
        );
        assert_eq!(report.orphan_secret_files, vec!["orphan.gpg".to_string()]);
        assert!(!report.is_healthy());
        assert!(store.read_secret_file(&present.id).is_ok());

        store.delete_item(&missing.id).unwrap();
        fs::remove_file(store.secrets_dir.join("orphan.gpg")).unwrap();
        assert!(store.check_integrity().unwrap().is_healthy());
    }

    #[test]
    fn integrity_uses_table_keys_and_isolates_corrupt_records() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let collection = store.create_collection("c", None).unwrap();
        let valid_b = store
            .create_item(
                &collection.id,
                "valid-b",
                attrs(&[("k", "b")]),
                "text/plain",
                b"b",
            )
            .unwrap();
        let key_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut mismatched = valid_b.clone();
        mismatched.label = "corrupt-a".to_string();
        let txn = store.db.begin_write().unwrap();
        {
            let mut items = txn.open_table(ITEMS).unwrap();
            let bytes = serde_json::to_vec(&mismatched).unwrap();
            items.insert(key_a, bytes.as_slice()).unwrap();
        }
        txn.commit().unwrap();

        let report = store.check_integrity().unwrap();
        assert_eq!(report.corrupt_items.len(), 1);
        assert_eq!(report.corrupt_items[0].table_key, key_a);
        assert_eq!(
            report.corrupt_items[0].metadata.as_ref().unwrap().id,
            valid_b.id
        );

        store.delete_item(key_a).unwrap();
        assert_eq!(store.get_item(&valid_b.id).unwrap(), valid_b);
        assert_eq!(store.read_secret_file(&valid_b.id).unwrap(), b"b");
        assert!(store.check_integrity().unwrap().is_healthy());
    }

    #[test]
    fn integrity_reports_malformed_metadata_by_table_key() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let txn = store.db.begin_write().unwrap();
        {
            let mut items = txn.open_table(ITEMS).unwrap();
            items.insert(key, b"not-json".as_slice()).unwrap();
        }
        txn.commit().unwrap();

        let report = store.check_integrity().unwrap();
        assert_eq!(report.corrupt_items.len(), 1);
        assert_eq!(report.corrupt_items[0].table_key, key);
        assert!(report.corrupt_items[0].metadata.is_none());
        store.delete_item(key).unwrap();
        assert!(store.check_integrity().unwrap().is_healthy());
    }

    #[test]
    fn replacement_restores_previous_ciphertext_when_commit_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let path = store.secret_path(id).unwrap();
        fs::write(&path, b"old").unwrap();
        let staged = store.stage_secret_file(id, b"new", "test").unwrap();

        let err = store
            .replace_then_commit(
                &path,
                &staged,
                || -> std::result::Result<(), PersistError> {
                    Err(PersistError::Definite(Error::Config(
                        "injected commit failure".into(),
                    )))
                },
            )
            .unwrap_err();

        assert!(err.to_string().contains("injected commit failure"));
        assert_eq!(fs::read(path).unwrap(), b"old");
        assert_eq!(
            store.check_integrity().unwrap().orphan_secret_files.len(),
            1
        );
    }

    #[test]
    fn deletion_restores_ciphertext_when_commit_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let path = store.secret_path(id).unwrap();
        fs::write(&path, b"ciphertext").unwrap();

        let err = store
            .quarantine_then_commit(&path, || -> std::result::Result<(), PersistError> {
                Err(PersistError::Definite(Error::Config(
                    "injected commit failure".into(),
                )))
            })
            .unwrap_err();

        assert!(err.to_string().contains("injected commit failure"));
        assert_eq!(fs::read(path).unwrap(), b"ciphertext");
        assert!(
            store
                .check_integrity()
                .unwrap()
                .recovery_secret_files
                .is_empty()
        );
    }

    #[test]
    fn collection_ciphertexts_restore_when_commit_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let first = store
            .secret_path("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .unwrap();
        let second = store
            .secret_path("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
            .unwrap();
        fs::write(&first, b"first").unwrap();
        fs::write(&second, b"second").unwrap();

        let err = store
            .quarantine_many_then_commit(
                &[first.clone(), second.clone()],
                || -> std::result::Result<(), PersistError> {
                    Err(PersistError::Definite(Error::Config(
                        "injected collection commit failure".into(),
                    )))
                },
            )
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("injected collection commit failure")
        );
        assert_eq!(fs::read(first).unwrap(), b"first");
        assert_eq!(fs::read(second).unwrap(), b"second");
        assert!(
            store
                .check_integrity()
                .unwrap()
                .recovery_secret_files
                .is_empty()
        );
    }

    #[test]
    fn indeterminate_create_commit_keeps_ciphertext_and_poisons_store() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let collection = store.create_collection("c", None).unwrap();
        let item = store
            .create_item(
                &collection.id,
                "item",
                HashMap::new(),
                "text/plain",
                b"ciphertext",
            )
            .unwrap();

        let path = store.secret_path(&item.id).unwrap();
        let create_marker = store.recovery_path("create", &item.id);
        fs::hard_link(&path, &create_marker).unwrap();
        let err = store
            .finish_create_persist(
                &item.id,
                &create_marker,
                Err(PersistError::Indeterminate(Error::Config(
                    "injected post-commit error".into(),
                ))),
            )
            .unwrap_err();

        assert!(err.to_string().contains("indeterminate"));
        assert!(store.is_poisoned());
        assert_eq!(fs::read(&path).unwrap(), b"ciphertext");
        assert!(create_marker.exists());
        assert!(store.get_item(&item.id).is_err());
        drop(store);
        let reopened = Store::open(tmp.path()).unwrap();
        reopened.recover_interrupted_operations().unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"ciphertext");
        assert!(!create_marker.exists());
        assert!(reopened.check_integrity().unwrap().is_healthy());
    }

    #[test]
    fn indeterminate_create_without_metadata_is_removed_after_reopen() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let path = store.secret_path(id).unwrap();
        let create_marker = store.write_secret_file(id, b"ciphertext").unwrap();

        let err = store
            .finish_create_persist(
                id,
                &create_marker,
                Err(PersistError::Indeterminate(Error::Config(
                    "injected pre-commit outcome".into(),
                ))),
            )
            .unwrap_err();

        assert!(err.to_string().contains("indeterminate"));
        assert!(store.is_poisoned());
        assert!(path.exists());
        assert!(create_marker.exists());
        drop(store);

        let reopened = Store::open(tmp.path()).unwrap();
        reopened.recover_interrupted_operations().unwrap();
        assert!(!path.exists());
        assert!(!create_marker.exists());
        assert!(reopened.check_integrity().unwrap().is_healthy());
    }

    #[test]
    fn queued_writer_stops_after_store_is_poisoned() {
        let tmp = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(Store::open(tmp.path()).unwrap());
        let active_guard = store.transaction_gate.write().unwrap();
        let active_txn = store.db.begin_write().unwrap();
        let passed_initial_check = std::sync::Arc::new(std::sync::Barrier::new(2));
        let queued_store = std::sync::Arc::clone(&store);
        let queued_barrier = std::sync::Arc::clone(&passed_initial_check);
        let queued_file = store.secrets_dir.join("queued.gpg");
        let queued_file_for_thread = queued_file.clone();

        let queued = std::thread::spawn(move || {
            let txn = queued_store.begin_write_checked_after_initial_check(|| {
                queued_barrier.wait();
            });
            let Ok((_mutation_guard, txn)) = txn else {
                return false;
            };
            fs::write(&queued_file_for_thread, b"mutated").unwrap();
            {
                let mut collections = txn.open_table(COLLECTIONS).unwrap();
                collections.insert("queued", b"mutated".as_slice()).unwrap();
            }
            txn.commit().unwrap();
            true
        });

        passed_initial_check.wait();
        store.poison();
        drop(active_txn);
        drop(active_guard);

        assert!(!queued.join().unwrap());
        let txn = store.db.begin_read().unwrap();
        let collections = txn.open_table(COLLECTIONS).unwrap();
        assert!(collections.get("queued").unwrap().is_none());
        assert!(!queued_file.exists());
    }

    #[test]
    fn item_secret_reader_waits_for_update_rollback() {
        let tmp = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(Store::open(tmp.path()).unwrap());
        let collection = store.create_collection("c", None).unwrap();
        let item = store
            .create_item(&collection.id, "item", HashMap::new(), "text/plain", b"old")
            .unwrap();
        let path = store.secret_path(&item.id).unwrap();
        let staged = store.stage_secret_file(&item.id, b"new", "update").unwrap();
        let write_guard = store.write_guard_checked().unwrap();
        let reader_store = std::sync::Arc::clone(&store);
        let reader_id = item.id.clone();
        let passed_initial_check = std::sync::Arc::new(std::sync::Barrier::new(2));
        let reader_barrier = std::sync::Arc::clone(&passed_initial_check);
        let (sender, receiver) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let result = reader_store.read_item_secret_after_initial_check(&reader_id, || {
                reader_barrier.wait();
            });
            sender.send(result).unwrap();
        });

        passed_initial_check.wait();
        let err = store
            .replace_then_commit(&path, &staged, || {
                assert!(matches!(
                    receiver.try_recv(),
                    Err(std::sync::mpsc::TryRecvError::Empty)
                ));
                Err::<(), _>(PersistError::Definite(Error::Config(
                    "injected metadata failure".into(),
                )))
            })
            .unwrap_err();

        assert!(err.to_string().contains("injected metadata failure"));
        assert_eq!(fs::read(&path).unwrap(), b"old");
        assert!(matches!(
            receiver.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        drop(write_guard);

        let (metadata, ciphertext) = receiver
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap()
            .unwrap();
        reader.join().unwrap();
        assert_eq!(metadata, item);
        assert_eq!(ciphertext, b"old");
    }

    #[test]
    fn raw_ciphertext_reader_waits_for_rollback() {
        let tmp = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(Store::open(tmp.path()).unwrap());
        let collection = store.create_collection("c", None).unwrap();
        let item = store
            .create_item(&collection.id, "item", HashMap::new(), "text/plain", b"old")
            .unwrap();
        let path = store.secret_path(&item.id).unwrap();
        let write_guard = store.write_guard_checked().unwrap();
        let reader_store = std::sync::Arc::clone(&store);
        let reader_id = item.id.clone();
        let passed_initial_check = std::sync::Arc::new(std::sync::Barrier::new(2));
        let reader_barrier = std::sync::Arc::clone(&passed_initial_check);
        let (sender, receiver) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let result = reader_store.read_secret_file_after_initial_check(&reader_id, || {
                reader_barrier.wait();
            });
            sender.send(result).unwrap();
        });

        passed_initial_check.wait();
        fs::write(&path, b"uncommitted").unwrap();
        assert!(matches!(
            receiver.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        fs::write(&path, b"old").unwrap();
        drop(write_guard);

        assert_eq!(
            receiver
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap()
                .unwrap(),
            b"old"
        );
        reader.join().unwrap();
    }

    #[test]
    fn create_install_sync_failure_removes_unindexed_ciphertext() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let path = store.secrets_dir.join("unindexed.gpg");
        let marker = store.secrets_dir.join("create-marker.gpg");
        fs::write(&path, b"ciphertext").unwrap();
        fs::write(&marker, b"ciphertext").unwrap();
        let sync_calls = std::cell::Cell::new(0);

        let err = store
            .finish_create_install(
                &path,
                &marker,
                || {
                    sync_calls.set(sync_calls.get() + 1);
                    if sync_calls.get() == 1 {
                        Err(Error::Io(io::Error::other("injected install sync failure")))
                    } else {
                        Ok(())
                    }
                },
                |candidate| fs::remove_file(candidate),
            )
            .unwrap_err();

        assert!(err.to_string().contains("injected install sync failure"));
        assert_eq!(sync_calls.get(), 3);
        assert!(!path.exists());
        assert!(!marker.exists());
        assert!(!store.is_poisoned());
    }

    #[test]
    fn create_install_cleanup_failure_poisons_store() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let path = store.secrets_dir.join("unindexed.gpg");
        let marker = store.secrets_dir.join("create-marker.gpg");
        fs::write(&path, b"ciphertext").unwrap();
        fs::write(&marker, b"ciphertext").unwrap();

        let err = store
            .finish_create_install(
                &path,
                &marker,
                || Err(Error::Io(io::Error::other("injected install sync failure"))),
                |_| Err(io::Error::other("injected cleanup failure")),
            )
            .unwrap_err();

        assert!(err.to_string().contains("injected cleanup failure"));
        assert!(path.exists());
        assert!(marker.exists());
        assert!(store.is_poisoned());
        assert!(store.create_collection("blocked", None).is_err());
    }

    #[test]
    fn create_install_cleanup_sync_failure_poisons_store() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let path = store.secrets_dir.join("unindexed.gpg");
        let marker = store.secrets_dir.join("create-marker.gpg");
        fs::write(&path, b"ciphertext").unwrap();
        fs::write(&marker, b"ciphertext").unwrap();

        let err = store
            .finish_create_install(
                &path,
                &marker,
                || {
                    Err(Error::Io(io::Error::other(
                        "injected directory sync failure",
                    )))
                },
                |candidate| fs::remove_file(candidate),
            )
            .unwrap_err();

        assert!(err.to_string().contains("cleanup directory sync failed"));
        assert!(!path.exists());
        assert!(marker.exists());
        assert!(store.is_poisoned());
        assert!(store.create_collection("blocked", None).is_err());
    }

    #[test]
    fn indeterminate_update_commit_keeps_artifacts_for_persisted_outcome() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let collection = store.create_collection("c", None).unwrap();
        let item = store
            .create_item(&collection.id, "item", HashMap::new(), "text/plain", b"old")
            .unwrap();
        let path = store.secret_path(&item.id).unwrap();
        let staged = store.stage_secret_file(&item.id, b"new", "update").unwrap();
        let mut updated = item.clone();
        updated.ciphertext_sha256 = Some(ciphertext_sha256(b"new"));
        let bytes = serde_json::to_vec(&updated).unwrap();
        let txn = store.db.begin_write().unwrap();

        let err = store
            .replace_then_commit(
                &path,
                &staged,
                || -> std::result::Result<(), PersistError> {
                    {
                        let mut items = txn.open_table(ITEMS).unwrap();
                        items.insert(item.id.as_str(), bytes.as_slice()).unwrap();
                    }
                    txn.commit().unwrap();
                    Err(PersistError::Indeterminate(Error::Config(
                        "injected post-commit error".into(),
                    )))
                },
            )
            .unwrap_err();

        assert!(err.to_string().contains("indeterminate"));
        assert!(store.is_poisoned());
        assert_eq!(fs::read(&path).unwrap(), b"new");
        assert_eq!(
            store.check_integrity().unwrap().recovery_secret_files.len(),
            1
        );
        drop(store);
        let reopened = Store::open(tmp.path()).unwrap();
        reopened.recover_interrupted_operations().unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new");
        assert!(reopened.check_integrity().unwrap().is_healthy());
    }

    #[test]
    fn indeterminate_update_without_metadata_commit_restores_old_ciphertext() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let collection = store.create_collection("c", None).unwrap();
        let item = store
            .create_item(&collection.id, "item", HashMap::new(), "text/plain", b"old")
            .unwrap();
        let path = store.secret_path(&item.id).unwrap();
        let staged = store.stage_secret_file(&item.id, b"new", "update").unwrap();
        let txn = store.db.begin_write().unwrap();

        let err = store
            .replace_then_commit(&path, &staged, || {
                drop(txn);
                Err::<(), _>(PersistError::Indeterminate(Error::Config(
                    "injected pre-commit outcome".into(),
                )))
            })
            .unwrap_err();

        assert!(err.to_string().contains("indeterminate"));
        assert!(store.is_poisoned());
        assert_eq!(fs::read(&path).unwrap(), b"new");
        drop(store);

        let reopened = Store::open(tmp.path()).unwrap();
        reopened.recover_interrupted_operations().unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"old");
        assert!(reopened.check_integrity().unwrap().is_healthy());
    }

    #[test]
    fn indeterminate_delete_commit_keeps_quarantine_for_persisted_outcome() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let collection = store.create_collection("c", None).unwrap();
        let item = store
            .create_item(
                &collection.id,
                "item",
                HashMap::new(),
                "text/plain",
                b"ciphertext",
            )
            .unwrap();
        let path = store.secret_path(&item.id).unwrap();
        let txn = store.db.begin_write().unwrap();

        let err = store
            .quarantine_then_commit(&path, || -> std::result::Result<(), PersistError> {
                {
                    let mut items = txn.open_table(ITEMS).unwrap();
                    items.remove(item.id.as_str()).unwrap();
                }
                txn.commit().unwrap();
                Err(PersistError::Indeterminate(Error::Config(
                    "injected post-commit error".into(),
                )))
            })
            .unwrap_err();

        assert!(err.to_string().contains("indeterminate"));
        assert!(store.is_poisoned());
        assert!(!path.exists());
        assert_eq!(
            store.check_integrity().unwrap().recovery_secret_files.len(),
            1
        );
        drop(store);
        let reopened = Store::open(tmp.path()).unwrap();
        reopened.recover_interrupted_operations().unwrap();
        assert!(!path.exists());
        assert!(reopened.check_integrity().unwrap().is_healthy());
    }

    #[test]
    fn indeterminate_delete_without_metadata_commit_restores_ciphertext() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let collection = store.create_collection("c", None).unwrap();
        let item = store
            .create_item(
                &collection.id,
                "item",
                HashMap::new(),
                "text/plain",
                b"ciphertext",
            )
            .unwrap();
        let path = store.secret_path(&item.id).unwrap();
        let txn = store.db.begin_write().unwrap();

        let err = store
            .quarantine_then_commit(&path, || {
                drop(txn);
                Err::<(), _>(PersistError::Indeterminate(Error::Config(
                    "injected pre-commit outcome".into(),
                )))
            })
            .unwrap_err();

        assert!(err.to_string().contains("indeterminate"));
        assert!(store.is_poisoned());
        assert!(!path.exists());
        drop(store);

        let reopened = Store::open(tmp.path()).unwrap();
        reopened.recover_interrupted_operations().unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"ciphertext");
        assert!(reopened.check_integrity().unwrap().is_healthy());
    }

    #[test]
    fn indeterminate_collection_delete_without_commit_restores_all_ciphertexts() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let collection = store.create_collection("c", None).unwrap();
        let first = store
            .create_item(
                &collection.id,
                "first",
                HashMap::new(),
                "text/plain",
                b"first ciphertext",
            )
            .unwrap();
        let second = store
            .create_item(
                &collection.id,
                "second",
                HashMap::new(),
                "text/plain",
                b"second ciphertext",
            )
            .unwrap();
        let paths = [
            store.secret_path(&first.id).unwrap(),
            store.secret_path(&second.id).unwrap(),
        ];
        let txn = store.db.begin_write().unwrap();

        let err = store
            .quarantine_many_then_commit(&paths, || {
                drop(txn);
                Err::<(), _>(PersistError::Indeterminate(Error::Config(
                    "injected pre-commit outcome".into(),
                )))
            })
            .unwrap_err();

        assert!(err.to_string().contains("indeterminate"));
        assert!(store.is_poisoned());
        assert!(paths.iter().all(|path| !path.exists()));
        drop(store);

        let reopened = Store::open(tmp.path()).unwrap();
        reopened.recover_interrupted_operations().unwrap();
        assert_eq!(fs::read(&paths[0]).unwrap(), b"first ciphertext");
        assert_eq!(fs::read(&paths[1]).unwrap(), b"second ciphertext");
        assert_eq!(reopened.get_collection(&collection.id).unwrap(), collection);
        assert_eq!(reopened.list_items(&collection.id).unwrap().len(), 2);
        assert!(reopened.check_integrity().unwrap().is_healthy());
    }

    #[test]
    fn indeterminate_collection_commit_keeps_quarantines_for_persisted_outcome() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let collection = store.create_collection("c", None).unwrap();
        let item = store
            .create_item(
                &collection.id,
                "item",
                HashMap::new(),
                "text/plain",
                b"ciphertext",
            )
            .unwrap();
        let path = store.secret_path(&item.id).unwrap();
        let txn = store.db.begin_write().unwrap();

        let err = store
            .quarantine_many_then_commit(
                std::slice::from_ref(&path),
                || -> std::result::Result<(), PersistError> {
                    {
                        let mut items = txn.open_table(ITEMS).unwrap();
                        items.remove(item.id.as_str()).unwrap();
                        let mut collections = txn.open_table(COLLECTIONS).unwrap();
                        collections.remove(collection.id.as_str()).unwrap();
                    }
                    txn.commit().unwrap();
                    Err(PersistError::Indeterminate(Error::Config(
                        "injected post-commit error".into(),
                    )))
                },
            )
            .unwrap_err();

        assert!(err.to_string().contains("indeterminate"));
        assert!(store.is_poisoned());
        assert!(!path.exists());
        assert_eq!(
            store.check_integrity().unwrap().recovery_secret_files.len(),
            1
        );
        drop(store);
        let reopened = Store::open(tmp.path()).unwrap();
        reopened.recover_interrupted_operations().unwrap();
        assert!(!path.exists());
        assert!(reopened.check_integrity().unwrap().is_healthy());
    }

    #[test]
    fn cleanup_failure_keeps_recoverable_file_and_reports_path() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let file = ".noirpass-quarantine-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-1.gpg";
        let path = store.secrets_dir.join(file);
        fs::write(&path, b"ciphertext").unwrap();

        let err = Store::remove_recovery_file(&path, "metadata deletion committed", |_| {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "injected cleanup failure",
            ))
        })
        .unwrap_err();

        assert!(err.to_string().contains("metadata deletion committed"));
        assert!(err.to_string().contains(path.to_string_lossy().as_ref()));
        assert!(path.exists());
        assert_eq!(
            store.check_integrity().unwrap().recovery_secret_files,
            vec![file.to_string()]
        );
    }

    #[test]
    fn integrity_blocks_ciphertext_digest_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let collection = store.create_collection("c", None).unwrap();
        let item = store
            .create_item(
                &collection.id,
                "item",
                HashMap::new(),
                "text/plain",
                b"expected",
            )
            .unwrap();
        fs::write(store.secret_path(&item.id).unwrap(), b"wrong").unwrap();

        let report = store.check_integrity().unwrap();
        assert_eq!(report.ciphertext_mismatches.len(), 1);
        assert_eq!(report.ciphertext_mismatches[0].table_key, item.id);
        assert!(!report.is_healthy());
        assert!(store.ensure_safe_to_serve().is_err());
    }

    #[test]
    fn startup_recovery_removes_valid_staged_files() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let create = store.stage_secret_file(id, b"create", "create").unwrap();
        let update = store.stage_secret_file(id, b"update", "update").unwrap();

        let report = store.check_integrity().unwrap();
        assert_eq!(report.recovery_secret_files.len(), 2);
        assert!(!report.is_healthy());
        store.recover_interrupted_operations().unwrap();
        assert!(!create.exists());
        assert!(!update.exists());
        assert!(store.check_integrity().unwrap().is_healthy());
    }

    #[test]
    fn startup_recovery_preserves_backup_without_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let backup = store
            .secrets_dir
            .join(".noirpass-backup-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-0000000000000001.gpg");
        fs::write(&backup, b"only-copy").unwrap();

        let err = store.recover_interrupted_operations().unwrap_err();

        assert!(err.to_string().contains("preserved for manual recovery"));
        assert_eq!(fs::read(backup).unwrap(), b"only-copy");
    }

    #[test]
    fn startup_recovery_keeps_committed_update_and_finishes_committed_delete() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let collection = store.create_collection("c", None).unwrap();
        let updated = store
            .create_item(
                &collection.id,
                "updated",
                HashMap::new(),
                "text/plain",
                b"old",
            )
            .unwrap();
        store
            .update_item(&updated.id, None, None, None, Some(b"new"))
            .unwrap();
        let backup = store.secrets_dir.join(format!(
            ".noirpass-backup-{}-0000000000000001.gpg",
            updated.id
        ));
        fs::write(&backup, b"old").unwrap();

        let deleted = store
            .create_item(
                &collection.id,
                "deleted",
                HashMap::new(),
                "text/plain",
                b"deleted",
            )
            .unwrap();
        let deleted_path = store.secret_path(&deleted.id).unwrap();
        let quarantine = store.secrets_dir.join(format!(
            ".noirpass-quarantine-{}-0000000000000001.gpg",
            deleted.id
        ));
        fs::rename(&deleted_path, &quarantine).unwrap();
        store.delete_item_metadata(&deleted.id).unwrap();

        store.recover_interrupted_operations().unwrap();

        assert_eq!(store.read_secret_file(&updated.id).unwrap(), b"new");
        assert!(!backup.exists());
        assert!(!quarantine.exists());
        assert!(!deleted_path.exists());
    }

    #[test]
    fn integrity_reports_recoverable_quarantine_files() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let file = ".noirpass-quarantine-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-1.gpg";
        fs::write(store.secrets_dir.join(file), b"ciphertext").unwrap();

        let report = store.check_integrity().unwrap();
        assert_eq!(report.recovery_secret_files, vec![file.to_string()]);
        assert!(!report.is_healthy());
    }

    #[test]
    fn integrity_rejects_non_regular_ciphertext_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let collection = store.create_collection("c", None).unwrap();
        let item = store
            .create_item(
                &collection.id,
                "item",
                attrs(&[("k", "v")]),
                "text/plain",
                b"ciphertext",
            )
            .unwrap();
        let path = store.secret_path(&item.id).unwrap();
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();

        let err = store.check_integrity().unwrap_err();

        assert!(err.to_string().contains("not a regular file"));
    }

    #[test]
    fn invalid_item_ids_never_form_filesystem_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let outside = tmp.path().join("outside.gpg");
        fs::write(&outside, b"keep").unwrap();

        assert!(store.read_secret_file("../outside").is_err());
        assert!(store.delete_item("../outside").is_err());
        assert_eq!(fs::read(outside).unwrap(), b"keep");
    }
}
