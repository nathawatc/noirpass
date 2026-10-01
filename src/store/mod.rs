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
use std::os::fd::AsRawFd;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use redb::{Database, DatabaseError, ReadOnlyDatabase, ReadableDatabase, TableDefinition};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::filesystem::{
    Directory, ensure_dir_0700, open_regular_read_nofollow, open_regular_rw_nofollow,
    validate_no_symlink_components,
};

mod collections;
mod files;
mod integrity;
mod items;
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
    secrets_directory: Directory,
    poisoned: AtomicBool,
    poison_changed: tokio::sync::Notify,
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

fn secret_path(secrets_dir: &Path, id: &str) -> Result<PathBuf> {
    if !is_valid_item_id(id) {
        return Err(Error::Config(format!("invalid item id in store: {id}")));
    }
    Ok(secrets_dir.join(format!("{id}.gpg")))
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

/// Open redb through a verified no-follow descriptor.
fn open_readonly_database_nofollow(
    path: &Path,
) -> std::result::Result<ReadOnlyDatabase, DatabaseError> {
    // redb 4.1 accepts only a path for read-only opens. Keep the no-follow
    // descriptor alive while redb opens its procfs alias, which remains pinned
    // to the verified file even if the original path is replaced meanwhile.
    let file = open_regular_read_nofollow(path).map_err(DatabaseError::from)?;
    let proc_path = PathBuf::from("/proc/self/fd").join(file.as_raw_fd().to_string());
    ReadOnlyDatabase::open(proc_path)
}

/// Validate store paths without opening redb.
fn existing_store_paths(dir: &Path) -> Result<(PathBuf, PathBuf)> {
    validate_no_symlink_components(dir)?;
    let store_metadata = fs::symlink_metadata(dir)?;
    if !store_metadata.is_dir() {
        return Err(Error::Config(format!(
            "store path is not a directory: {}",
            dir.display()
        )));
    }

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
    let _ = open_regular_rw_nofollow(&index_path)?;

    Ok((secrets_dir, index_path))
}

impl Store {
    fn poison(&self) {
        self.poisoned.store(true, Ordering::Release);
        self.poison_changed.notify_waiters();
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

    /// Wait for a poisoned store without polling or losing a concurrent notification.
    pub async fn wait_until_poisoned(&self) {
        let notified = self.poison_changed.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if !self.is_poisoned() {
            notified.await;
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

        let root = Directory::open(dir)?;
        let secrets_directory = root.child(Path::new("secrets"))?;
        let index =
            root.open_regular(Path::new("index.redb"), libc::O_RDWR | libc::O_CREAT, 0o600)?;
        let db = Database::builder().create_file(index)?;
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
            secrets_directory,
            secrets_dir,
            poisoned: AtomicBool::new(false),
            poison_changed: tokio::sync::Notify::new(),
            transaction_gate: RwLock::new(()),
        })
    }

    /// Open an already initialized store without creating files or directories.
    ///
    /// Maintenance commands use this so a typo in `--store-dir` cannot create a
    /// second empty store. The redb writer lock also prevents offline mutation
    /// while the daemon is using the same index.
    pub fn open_existing(dir: &Path) -> Result<Self> {
        existing_store_paths(dir)?;
        let root = Directory::open(dir)?;
        Self::open_existing_in(dir, &root)
    }

    /// Share a pinned root with configuration lifecycle operations.
    pub(crate) fn open_existing_in(dir: &Path, root: &Directory) -> Result<Self> {
        let secrets_dir = dir.join("secrets");
        let index_path = dir.join("index.redb");
        let secrets_directory = root.child(Path::new("secrets"))?;
        let index = root.open_regular(Path::new("index.redb"), libc::O_RDWR, 0)?;
        if index.metadata()?.len() == 0 {
            return Err(Error::Config(format!(
                "metadata database is empty: {}",
                index_path.display()
            )));
        }
        let db = match Database::builder().create_file(index) {
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
            secrets_directory,
            secrets_dir,
            poisoned: AtomicBool::new(false),
            poison_changed: tokio::sync::Notify::new(),
            transaction_gate: RwLock::new(()),
        })
    }

    /// Check whether an existing store is usable without mutating it.
    pub fn probe_health(dir: &Path) -> Result<()> {
        let (_, index_path) = existing_store_paths(dir)?;
        let db = match open_readonly_database_nofollow(&index_path) {
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
        secret_path(&self.secrets_dir, id)
    }
}

#[cfg(test)]
mod tests;
