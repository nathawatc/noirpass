//! Validate existing startup state, then reload configuration under store ownership.

use std::path::Path;

use noirpass::config::{Config, Recipient, load_recipient};
use noirpass::store::Store;

pub(super) fn open_store(
    directory: &Path,
    idle_override: Option<i64>,
) -> noirpass::Result<(Store, Recipient, i64)> {
    open_store_after_preflight(directory, idle_override, || {})
}

fn open_store_after_preflight(
    directory: &Path,
    idle_override: Option<i64>,
    before_open: impl FnOnce(),
) -> noirpass::Result<(Store, Recipient, i64)> {
    // Preserve pure preflight for invalid configuration or database state.
    Config::load(directory)?;
    load_recipient(directory)?;
    Store::probe_health(directory)?;
    before_open();
    // Never recreate an index removed by concurrent deinitialization. Once redb
    // ownership is held, init/deinit cannot refresh or remove configuration.
    let store = Store::open_existing(directory)?;
    let config = Config::load(directory)?;
    let recipient = load_recipient(directory)?;
    Ok((store, recipient, idle_override.unwrap_or(config.idle_exit)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use noirpass::config::{init_from_bytes, recipient_cert_path};
    use sequoia_openpgp::cert::CertBuilder;
    use sequoia_openpgp::serialize::Serialize;

    #[test]
    fn startup_revalidates_after_preflight_without_recreating_missing_index() {
        let directory = tempfile::tempdir().unwrap();
        let (cert, _) = CertBuilder::new()
            .add_storage_encryption_subkey()
            .generate()
            .unwrap();
        let mut bytes = Vec::new();
        cert.serialize(&mut bytes).unwrap();
        init_from_bytes(directory.path(), &bytes).unwrap();
        drop(Store::open(directory.path()).unwrap());

        let (store, _, idle_exit) = open_store_after_preflight(directory.path(), None, || {
            let mut config = Config::load(directory.path()).unwrap();
            config.idle_exit = 123;
            config.write(directory.path()).unwrap();
        })
        .unwrap();
        assert_eq!(idle_exit, 123);
        drop(store);

        let err = open_store_after_preflight(directory.path(), None, || {
            std::fs::write(
                recipient_cert_path(directory.path()),
                b"invalid certificate",
            )
            .unwrap();
        })
        .unwrap_err();
        assert!(matches!(err, noirpass::Error::OpenPgp(_)));
        std::fs::write(recipient_cert_path(directory.path()), &bytes).unwrap();

        assert!(
            open_store_after_preflight(directory.path(), None, || {
                std::fs::remove_file(directory.path().join("index.redb")).unwrap();
            })
            .is_err()
        );
        assert!(!directory.path().join("index.redb").exists());
    }
}
