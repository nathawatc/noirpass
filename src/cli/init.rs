use std::fs;
use std::io;
use std::path::Path;

use noirpass::config::init_from_path;
use noirpass::store::Store;

pub(super) fn run(store_dir: &Path, recipient: &str) -> noirpass::Result<()> {
    let existing_store = match fs::symlink_metadata(store_dir.join("index.redb")) {
        Ok(_) => Some(Store::open_existing(store_dir)?),
        Err(err) if err.kind() == io::ErrorKind::NotFound => None,
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
