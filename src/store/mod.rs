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

use std::fs;
use std::os::fd::AsRawFd;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use redb::{Database, DatabaseError, ReadOnlyDatabase, ReadableDatabase, TableDefinition};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::filesystem::{Directory, create_directory_all_nofollow, validate_no_symlink_components};
use crate::now_secs;

mod collections;
mod files;
mod integrity;
mod items;
mod persistence;
mod records;
mod recovery;

pub use records::{
    CollectionMeta, CorruptCollection, CorruptItem, DeletedCollection, IndexedItem,
    IntegrityReport, ItemMeta,
};

/// id → `serde_json(CollectionMeta)`
const COLLECTIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("collections");
/// id → `serde_json(ItemMeta)`
const ITEMS: TableDefinition<&str, &[u8]> = TableDefinition::new("items");
/// alias name → collection id
const ALIASES: TableDefinition<&str, &str> = TableDefinition::new("aliases");

/// The well-known id, label and alias of the default collection.
pub const DEFAULT_COLLECTION_ID: &str = "default";

/// A handle to the persistent metadata index and secret files.
#[derive(Debug)]
pub struct Store {
    db: Database,
    secrets_dir: PathBuf,
    secrets_directory: Directory,
    poisoned: AtomicBool,
    write_aborted: AtomicBool,
    poison_changed: tokio::sync::Notify,
    transaction_gate: RwLock<()>,
    item_index: RwLock<Option<items::ItemIndex>>,
    #[cfg(test)]
    file_failures: std::sync::Mutex<std::collections::VecDeque<(files::FileOperation, usize)>>,
}

/// Keep derived lookup state only when the caller has accounted for a successful
/// mutation or the transaction has explicitly aborted. Uncertain outcomes,
/// repair, recovery and raw committed writes discard it.
struct StoreWriteGuard<'a> {
    index: RwLockWriteGuard<'a, Option<items::ItemIndex>>,
    _gate: RwLockWriteGuard<'a, ()>,
    keep_index: bool,
    store: &'a Store,
}

impl StoreWriteGuard<'_> {
    fn preserve_index(&mut self) {
        self.keep_index = true;
    }
}

impl Drop for StoreWriteGuard<'_> {
    fn drop(&mut self) {
        if self.store.is_poisoned()
            || (!self.keep_index && !self.store.write_aborted.load(Ordering::Relaxed))
        {
            *self.index = None;
        }
    }
}

/// Explicitly verify rollback before the write guard retains a validated index.
/// A failed abort poisons the Store; no reader may use uncertain metadata.
struct StoreTransaction<'a> {
    transaction: Option<redb::WriteTransaction>,
    store: &'a Store,
}

impl StoreTransaction<'_> {
    fn commit(mut self) -> std::result::Result<(), redb::CommitError> {
        let result = self
            .transaction
            .take()
            .expect("transaction is open")
            .commit();
        if result.is_err() {
            self.store.poison();
        }
        result
    }
}

impl std::ops::Deref for StoreTransaction<'_> {
    type Target = redb::WriteTransaction;

    fn deref(&self) -> &Self::Target {
        self.transaction.as_ref().expect("transaction is open")
    }
}

impl Drop for StoreTransaction<'_> {
    fn drop(&mut self) {
        if let Some(transaction) = self.transaction.take() {
            if std::thread::panicking() {
                self.store.poison();
                return;
            }
            match transaction.abort() {
                Ok(()) => self.store.write_aborted.store(true, Ordering::Relaxed),
                Err(_) => self.store.poison(),
            }
        }
    }
}

enum PersistError {
    Definite(Error),
    Indeterminate(Error),
}

fn definite<E: Into<Error>>(error: E) -> PersistError {
    PersistError::Definite(error.into())
}

/// Lowercase hex SHA-256 digest of `ciphertext`.
fn ciphertext_sha256(ciphertext: &[u8]) -> String {
    use std::fmt::Write as _;
    Sha256::digest(ciphertext)
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// A fresh random 128-bit identifier rendered as 32 hex characters.
fn random_id() -> String {
    format!("{:032x}", rand::random::<u128>())
}

/// Whether `id` is a canonical item identifier safe for use as a filename.
fn is_valid_collection_id(id: &str) -> bool {
    id == DEFAULT_COLLECTION_ID || is_valid_item_id(id)
}

const RECOVERY_KINDS: [&str; 4] = ["create", "update", "quarantine", "backup"];

/// Whether `id` is a canonical 32-character lowercase hexadecimal item id.
#[must_use]
pub fn is_valid_item_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn recovery_kind(file_name: &str) -> Option<&'static str> {
    RECOVERY_KINDS.into_iter().find(|kind| {
        file_name
            .strip_prefix(".noirpass-")
            .and_then(|rest| rest.strip_prefix(kind))
            .is_some_and(|rest| rest.starts_with('-'))
    })
}

pub(crate) fn parse_recovery_secret_name(file_name: &str) -> Option<(&'static str, &str)> {
    let kind = recovery_kind(file_name)?;
    let rest = &file_name[".noirpass-".len() + kind.len() + 1..];
    let (id, suffix) = rest.split_once('-')?;
    let valid_token = suffix.strip_suffix(".gpg").is_some_and(|token| {
        token.len() == 16 && token.bytes().all(|byte| byte.is_ascii_hexdigit())
    });
    (is_valid_item_id(id) && valid_token).then_some((kind, id))
}

fn secret_path(secrets_dir: &Path, id: &str) -> Result<PathBuf> {
    if !is_valid_item_id(id) {
        return Err(Error::Config(format!("invalid item id in store: {id}")));
    }
    Ok(secrets_dir.join(format!("{id}.gpg")))
}

fn decode_collection(table_key: &str, value: &[u8]) -> Result<CollectionMeta> {
    if !is_valid_collection_id(table_key) {
        return Err(Error::Config(format!(
            "invalid collection id in store: {table_key}"
        )));
    }
    let metadata: CollectionMeta = serde_json::from_slice(value)?;
    if metadata.id != table_key {
        return Err(Error::Config(format!(
            "collection metadata id {} does not match table key {table_key}",
            metadata.id
        )));
    }
    Ok(metadata)
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

fn open_readonly_database_file(
    file: &fs::File,
) -> std::result::Result<ReadOnlyDatabase, DatabaseError> {
    // Pin the verified file while redb opens its procfs alias.
    let proc_path = PathBuf::from("/proc/self/fd").join(file.as_raw_fd().to_string());
    ReadOnlyDatabase::open(proc_path)
}

fn open_existing_root(dir: &Path) -> Result<Directory> {
    validate_no_symlink_components(dir)?;
    if !fs::symlink_metadata(dir)?.is_dir() {
        return Err(Error::Config(format!(
            "store path is not a directory: {}",
            dir.display()
        )));
    }
    Ok(Directory::open(dir)?)
}

fn open_existing_secrets(dir: &Path, root: &Directory) -> Result<(PathBuf, Directory)> {
    let secrets_dir = dir.join("secrets");
    if !root.metadata(Path::new("secrets"))?.is_dir() {
        return Err(Error::Config(format!(
            "store secrets path is not a directory: {}",
            secrets_dir.display()
        )));
    }
    let secrets_directory = root.child(Path::new("secrets"))?;
    let _ = secrets_directory.read_dir()?;
    let _ = root.open_regular(Path::new("index.redb"), libc::O_RDWR, 0)?;
    Ok((secrets_dir, secrets_directory))
}

impl Store {
    fn from_parts(db: Database, secrets_dir: PathBuf, secrets_directory: Directory) -> Self {
        Self {
            db,
            secrets_dir,
            secrets_directory,
            poisoned: AtomicBool::new(false),
            write_aborted: AtomicBool::new(false),
            poison_changed: tokio::sync::Notify::new(),
            transaction_gate: RwLock::new(()),
            item_index: RwLock::new(None),
            #[cfg(test)]
            file_failures: std::sync::Mutex::default(),
        }
    }

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

    fn begin_write_checked(&self) -> Result<(StoreWriteGuard<'_>, StoreTransaction<'_>)> {
        self.begin_write_checked_after_initial_check(|| {})
    }

    fn begin_write_checked_after_initial_check(
        &self,
        after_initial_check: impl FnOnce(),
    ) -> Result<(StoreWriteGuard<'_>, StoreTransaction<'_>)> {
        let guard = self.write_guard_checked_after_initial_check(after_initial_check)?;
        let txn = self.db.begin_write()?;
        self.ensure_not_poisoned()?;
        Ok((
            guard,
            StoreTransaction {
                transaction: Some(txn),
                store: self,
            },
        ))
    }

    fn write_guard_checked(&self) -> Result<StoreWriteGuard<'_>> {
        self.write_guard_checked_after_initial_check(|| {})
    }

    fn write_guard_checked_after_initial_check(
        &self,
        after_initial_check: impl FnOnce(),
    ) -> Result<StoreWriteGuard<'_>> {
        self.ensure_not_poisoned()?;
        after_initial_check();
        let guard = self
            .transaction_gate
            .write()
            .map_err(|_| Error::Config("store transaction gate is poisoned".into()))?;
        self.ensure_not_poisoned()?;
        let index = self
            .item_index
            .write()
            .map_err(|_| Error::Config("item lookup index is poisoned".into()))?;
        self.write_aborted.store(false, Ordering::Relaxed);
        Ok(StoreWriteGuard {
            store: self,
            index,
            _gate: guard,
            keep_index: false,
        })
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
        let root = create_directory_all_nofollow(dir, 0o700)?;
        Self::open_in(dir, &root)
    }

    pub(crate) fn open_in(dir: &Path, root: &Directory) -> Result<Self> {
        Self::open_in_with_sync(dir, root, |_| root.sync_all())
    }

    fn open_in_with_sync(
        dir: &Path,
        root: &Directory,
        sync_root: impl FnOnce(&Database) -> std::io::Result<()>,
    ) -> Result<Self> {
        use std::os::unix::fs::PermissionsExt;
        root.set_permissions(fs::Permissions::from_mode(0o700))?;
        let secrets_dir = dir.join("secrets");
        let secrets_directory = root.create_child(Path::new("secrets"), 0o700)?;
        secrets_directory.set_permissions(fs::Permissions::from_mode(0o700))?;
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
        // redb syncs index contents; persist the index and secrets directory entries too.
        sync_root(&db)?;

        Ok(Self::from_parts(db, secrets_dir, secrets_directory))
    }

    /// Open an already initialized store without creating files or directories.
    ///
    /// Maintenance commands use this so a typo in `--store-dir` cannot create a
    /// second empty store. The redb writer lock also prevents offline mutation
    /// while the daemon is using the same index.
    pub fn open_existing(dir: &Path) -> Result<Self> {
        let root = open_existing_root(dir)?;
        let _ = open_existing_secrets(dir, &root)?;
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
        Ok(Self::from_parts(db, secrets_dir, secrets_directory))
    }

    /// Check whether an existing store is usable without mutating it.
    #[cfg(test)]
    pub(super) fn probe_health(dir: &Path) -> Result<()> {
        let root = open_existing_root(dir)?;
        let _ = open_existing_secrets(dir, &root)?;
        Self::probe_health_in(&root)
    }

    pub(crate) fn probe_health_in(root: &Directory) -> Result<()> {
        root.child(Path::new("secrets"))?;
        let index = root.open_regular(Path::new("index.redb"), libc::O_RDONLY, 0)?;
        let db = match open_readonly_database_file(&index) {
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
