//! Persistent metadata schema and integrity findings.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Metadata describing a collection (a named group of items).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionMeta {
    /// Stable identifier (either `"default"` or 16 random bytes as hex).
    pub id: String,
    /// Human-readable label.
    pub label: String,
    /// Creation time, seconds since the Unix epoch.
    pub created: u64,
    /// Last modification time, seconds since the Unix epoch.
    pub modified: u64,
}

/// Metadata describing a single stored secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemMeta {
    /// Stable identifier (16 random bytes as hex).
    pub id: String,
    /// Id of the owning collection.
    pub collection: String,
    /// Human-readable label.
    pub label: String,
    /// Lookup attributes; the Secret Service search key/value pairs.
    pub attributes: HashMap<String, String>,
    /// MIME-ish content type of the stored secret.
    pub content_type: String,
    /// SHA-256 of ciphertext used to resolve interrupted atomic updates.
    #[serde(default)]
    pub ciphertext_sha256: Option<String>,
    /// Creation time, seconds since the Unix epoch.
    pub created: u64,
    /// Last modification time, seconds since the Unix epoch.
    pub modified: u64,
}

/// Parsed item metadata paired with its authoritative redb table key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedItem {
    /// Authoritative item identity from the redb table key.
    pub table_key: String,
    /// Parsed metadata stored under `table_key`.
    pub metadata: ItemMeta,
}

/// Object identities removed by one collection deletion transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletedCollection {
    /// Item table keys removed with the collection.
    pub item_ids: Vec<String>,
    /// Alias names removed because they targeted the collection.
    pub aliases: Vec<String>,
}

/// Corrupt collection record that cannot safely be served over D-Bus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorruptCollection {
    /// Authoritative collection identity from the redb table key.
    pub table_key: String,
    /// Human-readable corruption detail.
    pub error: String,
}

/// Corrupt item record that cannot safely be treated as normal metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorruptItem {
    /// Authoritative item identity from the redb table key.
    pub table_key: String,
    /// Parsed metadata when JSON was valid but its embedded id mismatched.
    pub metadata: Option<ItemMeta>,
    /// Human-readable corruption detail.
    pub error: String,
}

/// Cross-check result for redb item metadata and `.gpg` files.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct IntegrityReport {
    /// Collection records with malformed, mismatched, or path-unsafe ids.
    pub corrupt_collections: Vec<CorruptCollection>,
    /// Items retained in redb whose ciphertext file is absent.
    pub missing_secret_items: Vec<IndexedItem>,
    /// Item records with malformed metadata or mismatched ids.
    pub corrupt_items: Vec<CorruptItem>,
    /// Valid item records whose ciphertext digest does not match metadata.
    pub ciphertext_mismatches: Vec<IndexedItem>,
    /// Valid item records whose collection owner is missing or corrupt.
    pub items_with_invalid_collection: Vec<CorruptItem>,
    /// Aliases that target a missing collection.
    pub corrupt_aliases: Vec<(String, String)>,
    /// Aliases retained because their target collection record is corrupt.
    pub aliases_with_corrupt_collection: Vec<(String, String)>,
    /// Ciphertext files that have no matching item table key.
    pub orphan_secret_files: Vec<String>,
    /// Recoverable backup/quarantine files left by interrupted maintenance.
    pub recovery_secret_files: Vec<String>,
}

impl IntegrityReport {
    /// True when every indexed item has one ciphertext file and no orphan exists.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.corrupt_collections.is_empty()
            && self.missing_secret_items.is_empty()
            && self.corrupt_items.is_empty()
            && self.ciphertext_mismatches.is_empty()
            && self.items_with_invalid_collection.is_empty()
            && self.corrupt_aliases.is_empty()
            && self.aliases_with_corrupt_collection.is_empty()
            && self.orphan_secret_files.is_empty()
            && self.recovery_secret_files.is_empty()
    }
}
