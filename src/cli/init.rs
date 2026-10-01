use std::path::Path;

use noirpass::config::init_store_from_path;

pub(super) fn run(store_dir: &Path, recipient: &str) -> noirpass::Result<()> {
    let config = init_store_from_path(store_dir, recipient)?;
    println!("initialized: yes");
    println!("data directory: {}", store_dir.display());
    println!("recipient fingerprint: {}", config.recipient_fingerprint);
    Ok(())
}
