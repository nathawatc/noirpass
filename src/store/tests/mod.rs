//! Store unit tests.

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use redb::ReadableDatabase;

use super::*;

mod atomicity;
mod collections;
mod filesystem_failures;
mod index;
mod integrity;
mod items;
mod recovery;
mod scan_benchmark;

fn attrs(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}
