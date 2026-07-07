//! noirpass — a minimal, on-demand GPG-backed freedesktop Secret Service.
//!
//! This crate library exposes the storage and cryptographic building blocks
//! used by both the `noirpass` binary and the integration tests. The D-Bus
//! interface layer is built on top of these modules.

pub mod crypto;
pub mod error;
pub mod gpg;
pub mod store;

pub use error::{Error, Result};
