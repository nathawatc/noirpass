//! noirpass — a minimal, on-demand GPG-backed freedesktop Secret Service.
//!
//! Internal library crate shared by the `noirpass` binary and repository tests.
//! Rust module paths and APIs are implementation details; supported external
//! interfaces are the Noirpass CLI and Secret Service D-Bus API.

pub mod config;
pub mod crypto;
pub mod error;
mod filesystem;
pub mod gpg;
pub mod service;
pub mod store;

pub use error::{Error, Result};

/// Seconds since the Unix epoch (saturating at 0 for pre-epoch clocks).
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
