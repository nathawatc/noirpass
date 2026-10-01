//! Validate startup state and claim persistence under one pinned root.

use std::path::Path;

use crate::error::Result;
use crate::filesystem::{Directory, validate_no_symlink_components};
use crate::store::Store;

use super::status::load_recipient_in;
use super::{Config, Recipient};

/// Load configuration and recipient while claiming the same store's writer ownership.
pub fn open_startup_store(directory: &Path) -> Result<(Store, Recipient, Config)> {
    open_startup_after_preflight(directory, || {})
}

pub(super) fn open_startup_after_preflight(
    directory: &Path,
    before_open: impl FnOnce(),
) -> Result<(Store, Recipient, Config)> {
    validate_no_symlink_components(directory)?;
    let root = Directory::open(directory).map_err(super::format::uninitialized_or_io)?;
    load_recipient_in(directory, &root)?;
    Store::probe_health_in(&root)?;
    before_open();
    // Never recreate an index removed by concurrent deinitialization. Reload
    // recipient/config after ownership, without re-resolving the selected root.
    let store = Store::open_existing_in(directory, &root)?;
    let (config, recipient) = load_recipient_in(directory, &root)?;
    Ok((store, recipient, config))
}
