//! Crate-wide error type.
//!
//! [`Error`] unifies the failure modes of the storage, crypto and `GnuPG`
//! layers behind a single `thiserror`-derived enum. Sequoia's public API
//! returns `anyhow::Error` values; rather than take a direct dependency on
//! `anyhow`, those are flattened into [`Error::OpenPgp`] via their `Display`
//! representation at the call site (see `src/gpg/`).

use thiserror::Error;

/// The unified error type for noirpass core modules.
#[derive(Debug, Error)]
pub enum Error {
    /// A filesystem or other I/O operation failed.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// The redb database could not be opened or created.
    #[error("database open error: {0}")]
    RedbDatabase(#[from] redb::DatabaseError),

    /// A redb transaction could not be started.
    #[error("database transaction error: {0}")]
    RedbTransaction(#[from] redb::TransactionError),

    /// A redb table could not be opened.
    #[error("database table error: {0}")]
    RedbTable(#[from] redb::TableError),

    /// A redb read/write on storage failed.
    #[error("database storage error: {0}")]
    RedbStorage(#[from] redb::StorageError),

    /// A redb transaction failed to commit.
    #[error("database commit error: {0}")]
    RedbCommit(#[from] redb::CommitError),

    /// A (de)serialization of stored metadata failed.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// An `OpenPGP` / `GnuPG` operation failed (Sequoia error text, flattened).
    #[error("openpgp error: {0}")]
    OpenPgp(String),

    /// A requested object (collection, item, alias, secret file) does not exist.
    #[error("not found: {0}")]
    NotFound(String),

    /// A session-crypto operation failed (bad key, bad padding, tampering, ...).
    #[error("crypto error: {0}")]
    Crypto(String),

    /// The noirpass store/config is missing or inconsistent.
    #[error("config error: {0}")]
    Config(String),
}

/// A convenience alias for results in this crate.
pub type Result<T> = std::result::Result<T, Error>;

impl From<Error> for zbus::fdo::Error {
    /// Map a core error onto the closest D-Bus `org.freedesktop.DBus.Error.*`.
    ///
    /// [`Error::NotFound`] maps to `UnknownObject`, which is the nearest
    /// standard analogue to the Secret Service `NoSuchObject` error. The
    /// dedicated `org.freedesktop.Secret.Error.NoSuchObject` code is a custom
    /// error name that is handled at the D-Bus interface layer (added later);
    /// this conversion intentionally stays on the standard error set so it is
    /// always usable. Everything else becomes `Failed`, carrying the original
    /// message for debugging.
    fn from(err: Error) -> Self {
        match err {
            Error::NotFound(msg) => zbus::fdo::Error::UnknownObject(msg),
            other => zbus::fdo::Error::Failed(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_found_maps_to_unknown_object() {
        let err = Error::NotFound("collection x".into());
        match zbus::fdo::Error::from(err) {
            zbus::fdo::Error::UnknownObject(msg) => assert_eq!(msg, "collection x"),
            other => panic!("expected UnknownObject, got {other:?}"),
        }
    }

    #[test]
    fn other_errors_map_to_failed_with_message() {
        let err = Error::Crypto("bad padding".into());
        match zbus::fdo::Error::from(err) {
            zbus::fdo::Error::Failed(msg) => assert!(msg.contains("bad padding")),
            other => panic!("expected Failed, got {other:?}"),
        }
    }
}
