use std::path::Path;

use noirpass::config::init_from_path;
use noirpass::store::Store;

pub(super) fn run(store_dir: &Path, recipient: &str) -> noirpass::Result<()> {
    if store_dir.join("index.redb").exists() {
        Store::probe_health(store_dir)?;
    }
    let config = init_from_path(store_dir, recipient)?;
    let store = Store::open(store_dir)?;
    store.ensure_default()?;
    println!("initialized: yes");
    println!("data directory: {}", store_dir.display());
    println!("recipient fingerprint: {}", config.recipient_fingerprint);
    Ok(())
}
