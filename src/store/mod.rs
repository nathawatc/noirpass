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

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use redb::{Database, TableDefinition};

use crate::error::{Error, Result};
use crate::filesystem::Directory;
use crate::now_secs;

mod collections;
mod files;
mod format;
mod integrity;
mod items;
mod open;
mod records;
mod recovery;

pub use format::is_valid_item_id;
pub(crate) use format::{RecoveryKind, is_lower_hex, parse_recovery_secret_name};
use format::{
    ciphertext_file_sha256, ciphertext_sha256, decode_collection, decode_item,
    is_valid_collection_id, secret_path,
};
pub(crate) use integrity::INTEGRITY_CHECK_FAILED_ERROR;
#[cfg(test)]
use open::open_existing_root;
use open::{open_existing_secrets, open_readonly_database_file};
pub(crate) use records::DeletedCollection;
pub use records::{
    CollectionMeta, CorruptCollection, CorruptItem, IndexedItem, IntegrityReport, ItemMeta,
};

pub(crate) fn store_in_use_error(index_path: &Path) -> Error {
    Error::Config(format!(
        "store is in use by another noirpass process: {}; stop the daemon before running maintenance commands",
        index_path.display()
    ))
}

/// id → `serde_json(CollectionMeta)`
const COLLECTIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("collections");
/// id → `serde_json(ItemMeta)`
const ITEMS: TableDefinition<&str, &[u8]> = TableDefinition::new("items");
/// alias name → collection id
const ALIASES: TableDefinition<&str, &str> = TableDefinition::new("aliases");

/// The well-known id, label and alias of the default collection.
pub const DEFAULT_COLLECTION_ID: &str = "default";
pub(crate) const INDEX_FILE: &str = "index.redb";
pub(crate) const SECRETS_DIR: &str = "secrets";

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
    fn is_poisoned(&self) -> bool {
        self.poisoned.load(Ordering::Acquire)
    }

    /// Path of the `.gpg` secret file backing item `id`.
    fn secret_path(&self, id: &str) -> Result<PathBuf> {
        secret_path(&self.secrets_dir, id)
    }
}

#[cfg(test)]
mod tests;
