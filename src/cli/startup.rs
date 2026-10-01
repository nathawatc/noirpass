//! Select startup configuration and persistence from the same pinned root.

use std::path::Path;

use noirpass::config::{Recipient, open_startup_store};
use noirpass::store::Store;

pub(super) fn open_store(
    directory: &Path,
    idle_override: Option<i64>,
) -> noirpass::Result<(Store, Recipient, i64)> {
    let (store, recipient, config) = open_startup_store(directory)?;
    Ok((store, recipient, idle_override.unwrap_or(config.idle_exit)))
}
