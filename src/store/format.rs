//! Store identifier validation, recovery filename grammar, record decoding, and digests.

use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

use super::{CollectionMeta, DEFAULT_COLLECTION_ID, ItemMeta};

/// Recognized crash-recovery artifact families in `secrets/`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecoveryKind {
    Create,
    Update,
    Quarantine,
    Backup,
}

impl RecoveryKind {
    const ALL: [Self; 4] = [Self::Create, Self::Update, Self::Quarantine, Self::Backup];

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Update => "update",
            Self::Quarantine => "quarantine",
            Self::Backup => "backup",
        }
    }

    pub(crate) const fn priority(self) -> u8 {
        match self {
            Self::Create | Self::Update => 0,
            Self::Quarantine => 1,
            Self::Backup => 2,
        }
    }

    pub(crate) fn from_file_name(file_name: &str) -> Option<Self> {
        let rest = file_name.strip_prefix(".noirpass-")?;
        Self::ALL.into_iter().find(|kind| {
            rest.strip_prefix(kind.as_str())
                .is_some_and(|tail| tail.starts_with('-'))
        })
    }
}

fn format_sha256(digest: impl AsRef<[u8]>) -> String {
    use std::fmt::Write as _;
    digest
        .as_ref()
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// Lowercase hex SHA-256 digest of `ciphertext`.
pub(super) fn ciphertext_sha256(ciphertext: &[u8]) -> String {
    format_sha256(Sha256::digest(ciphertext))
}

/// Stream a ciphertext file through SHA-256 without buffering the full payload in RAM.
pub(super) fn ciphertext_file_sha256(file: &mut fs::File) -> std::io::Result<String> {
    use std::io::Read as _;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(format_sha256(hasher.finalize()))
}

/// Whether `id` is a canonical collection identifier safe for use as a key.
pub(super) fn is_valid_collection_id(id: &str) -> bool {
    id == DEFAULT_COLLECTION_ID || is_valid_item_id(id)
}

/// Whether `id` is a canonical 32-character lowercase hexadecimal item id.
#[must_use]
pub fn is_valid_item_id(id: &str) -> bool {
    is_lower_hex(id, 32)
}

/// Whether `s` is exactly `len` lowercase hexadecimal characters.
pub(crate) fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn parse_recovery_secret_name(file_name: &str) -> Option<(RecoveryKind, &str)> {
    let kind = RecoveryKind::from_file_name(file_name)?;
    let rest = &file_name[".noirpass-".len() + kind.as_str().len() + 1..];
    let (id, suffix) = rest.split_once('-')?;
    let valid_token = suffix
        .strip_suffix(".gpg")
        .is_some_and(|token| is_lower_hex(token, 16));
    (is_valid_item_id(id) && valid_token).then_some((kind, id))
}

pub(super) fn secret_path(secrets_dir: &Path, id: &str) -> Result<PathBuf> {
    if !is_valid_item_id(id) {
        return Err(Error::Config(format!("invalid item id in store: {id}")));
    }
    Ok(secrets_dir.join(format!("{id}.gpg")))
}

pub(super) fn decode_collection(table_key: &str, value: &[u8]) -> Result<CollectionMeta> {
    if !is_valid_collection_id(table_key) {
        return Err(Error::Config(format!(
            "invalid collection id in store: {table_key}"
        )));
    }
    let metadata: CollectionMeta = serde_json::from_slice(value)?;
    if metadata.id != table_key {
        return Err(Error::Config(format!(
            "collection metadata id {} does not match table key {table_key}",
            metadata.id
        )));
    }
    Ok(metadata)
}

pub(super) fn decode_item(table_key: &str, value: &[u8]) -> Result<ItemMeta> {
    if !is_valid_item_id(table_key) {
        return Err(Error::Config(format!(
            "item table key is not canonical: {table_key}"
        )));
    }
    let metadata: ItemMeta = serde_json::from_slice(value)?;
    if metadata.id != table_key {
        return Err(Error::Config(format!(
            "item metadata id {} does not match table key {table_key}",
            metadata.id
        )));
    }
    Ok(metadata)
}
