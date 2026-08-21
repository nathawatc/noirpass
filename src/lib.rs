//! noirpass — a minimal, on-demand GPG-backed freedesktop Secret Service.
//!
//! This crate library exposes the storage and cryptographic building blocks
//! plus the D-Bus interface objects used by the `noirpass` binary and the
//! integration tests.

pub mod config;
pub mod crypto;
pub mod error;
pub mod gpg;
pub mod service;
pub mod store;

// Preserve the original public module paths while service objects live under
// their owning subsystem.
pub use service::{collection, item, session};

pub use error::{Error, Result};
