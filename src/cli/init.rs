use std::fs;
use std::io;
use std::path::Path;

use noirpass::config::{LifecycleLock, init_from_path};
use noirpass::store::Store;

pub(super) fn run(store_dir: &Path, recipient: &str) -> noirpass::Result<()> {
    let preopened_store = match fs::symlink_metadata(store_dir.join("index.redb")) {
        Ok(_) => Some(Store::open_existing(store_dir)?),
        Err(err) if err.kind() == io::ErrorKind::NotFound => None,
        Err(err) => return Err(err.into()),
    };
    let had_existing_store = preopened_store.is_some();
    let _lifecycle_lock = LifecycleLock::acquire(store_dir)?;
    let existing_store = match fs::symlink_metadata(store_dir.join("index.redb")) {
        Ok(_) => match preopened_store {
            Some(store) => Some(store),
            None => Some(Store::open_existing(store_dir)?),
        },
        Err(err) if err.kind() == io::ErrorKind::NotFound && !had_existing_store => None,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Err(noirpass::Error::Config(
                "store disappeared while acquiring lifecycle lock".into(),
            ));
        }
        Err(err) => return Err(err.into()),
    };
    let config = init_from_path(store_dir, recipient)?;
    let store = match existing_store {
        Some(store) => store,
        None => Store::open(store_dir)?,
    };
    store.ensure_default()?;
    println!("initialized: yes");
    println!("data directory: {}", store_dir.display());
    println!("recipient fingerprint: {}", config.recipient_fingerprint);
    Ok(())
}
