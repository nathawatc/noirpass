//! Store creation, existing-store opening, and read-only health probing.

use std::fs;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use redb::{Database, DatabaseError, ReadOnlyDatabase, ReadableDatabase, backends::FileBackend};

use crate::error::{Error, Result};
use crate::filesystem::{Directory, create_directory_all_nofollow, validate_no_symlink_components};

use super::{ALIASES, COLLECTIONS, INDEX_FILE, ITEMS, SECRETS_DIR, Store, store_in_use_error};

pub(super) fn open_readonly_database_file(
    file: &fs::File,
) -> std::result::Result<ReadOnlyDatabase, DatabaseError> {
    // Pin the verified file while redb opens its procfs alias.
    let proc_path = PathBuf::from("/proc/self/fd").join(file.as_raw_fd().to_string());
    ReadOnlyDatabase::open(proc_path)
}

pub(super) fn open_existing_root(dir: &Path) -> Result<Directory> {
    validate_no_symlink_components(dir)?;
    if !fs::symlink_metadata(dir)?.is_dir() {
        return Err(Error::Config(format!(
            "store path is not a directory: {}",
            dir.display()
        )));
    }
    Ok(Directory::open(dir)?)
}

pub(super) fn open_existing_secrets(dir: &Path, root: &Directory) -> Result<(PathBuf, Directory)> {
    let secrets_dir = dir.join(SECRETS_DIR);
    if !root.metadata(Path::new(SECRETS_DIR))?.is_dir() {
        return Err(Error::Config(format!(
            "store secrets path is not a directory: {}",
            secrets_dir.display()
        )));
    }
    let secrets_directory = root.child(Path::new(SECRETS_DIR))?;
    let _ = secrets_directory.read_dir()?;
    Ok((secrets_dir, secrets_directory))
}

impl Store {
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

    pub(super) fn open_in_with_sync(
        dir: &Path,
        root: &Directory,
        sync_root: impl FnOnce(&Database) -> std::io::Result<()>,
    ) -> Result<Self> {
        use std::os::unix::fs::PermissionsExt;
        root.set_permissions(fs::Permissions::from_mode(0o700))?;
        let secrets_dir = dir.join(SECRETS_DIR);
        let secrets_directory = root.create_child(Path::new(SECRETS_DIR), 0o700)?;
        secrets_directory.set_permissions(fs::Permissions::from_mode(0o700))?;
        let index =
            root.open_regular(Path::new(INDEX_FILE), libc::O_RDWR | libc::O_CREAT, 0o600)?;
        let db = Database::builder().create_with_backend(FileBackend::new(index))?;
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
        Self::open_existing_in(dir, &root)
    }

    /// Share a pinned root with configuration lifecycle operations.
    pub(crate) fn open_existing_in(dir: &Path, root: &Directory) -> Result<Self> {
        let (secrets_dir, secrets_directory) = open_existing_secrets(dir, root)?;
        let index_path = dir.join(INDEX_FILE);
        let index = root.open_regular(Path::new(INDEX_FILE), libc::O_RDWR, 0)?;
        if index.metadata()?.len() == 0 {
            return Err(Error::Config(format!(
                "metadata database is empty: {}",
                index_path.display()
            )));
        }
        let db = match Database::builder().create_with_backend(FileBackend::new(index)) {
            Ok(db) => db,
            Err(DatabaseError::DatabaseAlreadyOpen) => {
                return Err(store_in_use_error(&index_path));
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
        root.child(Path::new(SECRETS_DIR))?;
        let index = root.open_regular(Path::new(INDEX_FILE), libc::O_RDONLY, 0)?;
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
}
