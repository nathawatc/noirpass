//! noirpass — a minimal, on-demand GPG-backed freedesktop Secret Service.
//!
//! Internal library crate shared by the `noirpass` binary and repository tests.
//! Rust module paths and APIs are implementation details; supported external
//! interfaces are the Noirpass CLI and Secret Service D-Bus API.

pub mod config;
pub mod crypto;
pub mod error;
pub mod gpg;
pub mod service;
pub mod store;

pub use error::{Error, Result};
