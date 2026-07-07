//! noirpass — a minimal, on-demand GPG-backed freedesktop Secret Service.
//!
//! This crate library exposes the storage and cryptographic building blocks
//! plus the D-Bus interface objects used by the `noirpass` binary and the
//! integration tests.

pub mod collection;
pub mod crypto;
pub mod error;
pub mod gpg;
pub mod item;
pub mod service;
pub mod session;
pub mod store;

pub use error::{Error, Result};
