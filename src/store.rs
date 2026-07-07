//! On-disk storage: a redb metadata index plus one `.gpg` file per secret.
//!
//! The store keeps all searchable metadata (labels, attributes, timestamps,
//! collection membership, aliases) in a single `index.redb` database, and
//! writes each secret's ciphertext to `secrets/<item_id>.gpg`. The ciphertext
//! is produced by the caller (the `GnuPG` layer); the store never sees plaintext.
//!
//! All directories are created `0700` and all secret files `0600`. The redb
//! [`Database`] is `Send + Sync`, so every method takes `&self` and performs
//! its own short-lived transaction.

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// id → `serde_json(CollectionMeta)`
const COLLECTIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("collections");
/// id → `serde_json(ItemMeta)`
const ITEMS: TableDefinition<&str, &[u8]> = TableDefinition::new("items");
/// alias name → collection id
const ALIASES: TableDefinition<&str, &str> = TableDefinition::new("aliases");

/// The well-known id, label and alias of the default collection.
pub const DEFAULT_COLLECTION_ID: &str = "default";

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
    /// Creation time, seconds since the Unix epoch.
    pub created: u64,
    /// Last modification time, seconds since the Unix epoch.
    pub modified: u64,
}

/// A handle to the persistent metadata index and secret files.
#[derive(Debug)]
pub struct Store {
    db: Database,
    secrets_dir: PathBuf,
}

/// Seconds since the Unix epoch (saturating at 0 for pre-epoch clocks).
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Lowercase hex encoding of a byte slice.
fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// A fresh random 128-bit identifier rendered as 32 hex characters.
fn random_id() -> String {
    let bytes: [u8; 16] = rand::random();
    to_hex(&bytes)
}

/// Create `dir` (if absent) and force its permissions to `0700`.
fn ensure_dir_0700(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

impl Store {
    /// Open (creating if necessary) a store rooted at `dir`.
    ///
    /// Creates `dir` and `dir/secrets/` as `0700` directories and opens (or
    /// creates) `dir/index.redb`.
    pub fn open(dir: &Path) -> Result<Self> {
        ensure_dir_0700(dir)?;
        let secrets_dir = dir.join("secrets");
        ensure_dir_0700(&secrets_dir)?;

        let db = Database::create(dir.join("index.redb"))?;
        // Ensure all tables exist so read-only transactions never fail on a
        // brand-new database.
        {
            let txn = db.begin_write()?;
            txn.open_table(COLLECTIONS)?;
            txn.open_table(ITEMS)?;
            txn.open_table(ALIASES)?;
            txn.commit()?;
        }

        Ok(Self { db, secrets_dir })
    }

    /// Path of the `.gpg` secret file backing item `id`.
    fn secret_path(&self, id: &str) -> PathBuf {
        self.secrets_dir.join(format!("{id}.gpg"))
    }

    // --- collections -----------------------------------------------------

    /// Create a new collection with the given label, optionally registering an
    /// alias that points at it.
    pub fn create_collection(&self, label: &str, alias: Option<&str>) -> Result<CollectionMeta> {
        let now = now_secs();
        let meta = CollectionMeta {
            id: random_id(),
            label: label.to_string(),
            created: now,
            modified: now,
        };

        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(COLLECTIONS)?;
            let bytes = serde_json::to_vec(&meta)?;
            table.insert(meta.id.as_str(), bytes.as_slice())?;
        }
        if let Some(alias) = alias {
            let mut aliases = txn.open_table(ALIASES)?;
            aliases.insert(alias, meta.id.as_str())?;
        }
        txn.commit()?;
        Ok(meta)
    }

    /// Fetch a single collection by id.
    pub fn get_collection(&self, id: &str) -> Result<CollectionMeta> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(COLLECTIONS)?;
        match table.get(id)? {
            Some(v) => Ok(serde_json::from_slice(v.value())?),
            None => Err(Error::NotFound(format!("collection {id}"))),
        }
    }

    /// List every collection, in id order.
    pub fn list_collections(&self) -> Result<Vec<CollectionMeta>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(COLLECTIONS)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (_, v) = entry?;
            out.push(serde_json::from_slice(v.value())?);
        }
        Ok(out)
    }

    /// Delete a collection together with all its items, their `.gpg` files and
    /// any aliases pointing at it. Returns [`Error::NotFound`] if the
    /// collection does not exist.
    pub fn delete_collection(&self, id: &str) -> Result<()> {
        let txn = self.db.begin_write()?;
        let removed_item_ids = {
            let mut collections = txn.open_table(COLLECTIONS)?;
            if collections.remove(id)?.is_none() {
                return Err(Error::NotFound(format!("collection {id}")));
            }

            // Collect this collection's item ids first, then remove them.
            let mut items = txn.open_table(ITEMS)?;
            let mut to_remove = Vec::new();
            for entry in items.iter()? {
                let (k, v) = entry?;
                let meta: ItemMeta = serde_json::from_slice(v.value())?;
                if meta.collection == id {
                    to_remove.push(k.value().to_string());
                }
            }
            for item_id in &to_remove {
                items.remove(item_id.as_str())?;
            }

            // Drop aliases that resolve to this collection.
            let mut aliases = txn.open_table(ALIASES)?;
            let mut dead_aliases = Vec::new();
            for entry in aliases.iter()? {
                let (k, v) = entry?;
                if v.value() == id {
                    dead_aliases.push(k.value().to_string());
                }
            }
            for alias in dead_aliases {
                aliases.remove(alias.as_str())?;
            }
            to_remove
        };
        txn.commit()?;

        // Remove secret files outside the transaction; missing files are fine.
        for item_id in removed_item_ids {
            let path = self.secret_path(&item_id);
            if let Err(e) = fs::remove_file(&path)
                && e.kind() != std::io::ErrorKind::NotFound
            {
                return Err(e.into());
            }
        }
        Ok(())
    }

    /// Ensure the well-known `default` collection (and its `default` alias)
    /// exist, creating them if missing. Returns the collection metadata.
    pub fn ensure_default(&self) -> Result<CollectionMeta> {
        if let Ok(meta) = self.get_collection(DEFAULT_COLLECTION_ID) {
            return Ok(meta);
        }
        let now = now_secs();
        let meta = CollectionMeta {
            id: DEFAULT_COLLECTION_ID.to_string(),
            label: "Default".to_string(),
            created: now,
            modified: now,
        };
        let txn = self.db.begin_write()?;
        {
            let mut collections = txn.open_table(COLLECTIONS)?;
            // Re-check under the write lock to avoid clobbering a racing writer.
            if collections.get(DEFAULT_COLLECTION_ID)?.is_none() {
                let bytes = serde_json::to_vec(&meta)?;
                collections.insert(DEFAULT_COLLECTION_ID, bytes.as_slice())?;
                let mut aliases = txn.open_table(ALIASES)?;
                aliases.insert("default", DEFAULT_COLLECTION_ID)?;
            }
        }
        txn.commit()?;
        self.get_collection(DEFAULT_COLLECTION_ID)
    }

    /// Change a collection's label and bump its modified timestamp.
    pub fn set_collection_label(&self, id: &str, label: &str) -> Result<CollectionMeta> {
        let mut meta = self.get_collection(id)?;
        meta.label = label.to_string();
        meta.modified = now_secs();
        let txn = self.db.begin_write()?;
        {
            let mut collections = txn.open_table(COLLECTIONS)?;
            let bytes = serde_json::to_vec(&meta)?;
            collections.insert(meta.id.as_str(), bytes.as_slice())?;
        }
        txn.commit()?;
        Ok(meta)
    }

    // --- aliases ---------------------------------------------------------

    /// Set (`Some`) or remove (`None`) the alias `name`.
    pub fn set_alias(&self, name: &str, collection_id: Option<&str>) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut aliases = txn.open_table(ALIASES)?;
            match collection_id {
                Some(id) => {
                    aliases.insert(name, id)?;
                }
                None => {
                    aliases.remove(name)?;
                }
            }
        }
        txn.commit()?;
        Ok(())
    }

    /// Resolve alias `name` to a collection id, or `None` if unset.
    pub fn read_alias(&self, name: &str) -> Result<Option<String>> {
        let txn = self.db.begin_read()?;
        let aliases = txn.open_table(ALIASES)?;
        Ok(aliases.get(name)?.map(|v| v.value().to_string()))
    }

    // --- items -----------------------------------------------------------

    /// Create an item in `collection`, writing its ciphertext to a fresh
    /// `0600` secret file. The collection must already exist.
    pub fn create_item(
        &self,
        collection: &str,
        label: &str,
        attributes: HashMap<String, String>,
        content_type: &str,
        secret_ciphertext: &[u8],
    ) -> Result<ItemMeta> {
        // Guard against orphan items in a non-existent collection.
        self.get_collection(collection)?;

        let now = now_secs();
        let meta = ItemMeta {
            id: random_id(),
            collection: collection.to_string(),
            label: label.to_string(),
            attributes,
            content_type: content_type.to_string(),
            created: now,
            modified: now,
        };

        self.write_secret_file(&meta.id, secret_ciphertext)?;

        let txn = self.db.begin_write()?;
        {
            let mut items = txn.open_table(ITEMS)?;
            let bytes = serde_json::to_vec(&meta)?;
            items.insert(meta.id.as_str(), bytes.as_slice())?;
        }
        txn.commit()?;
        Ok(meta)
    }

    /// Fetch a single item by id.
    pub fn get_item(&self, id: &str) -> Result<ItemMeta> {
        let txn = self.db.begin_read()?;
        let items = txn.open_table(ITEMS)?;
        match items.get(id)? {
            Some(v) => Ok(serde_json::from_slice(v.value())?),
            None => Err(Error::NotFound(format!("item {id}"))),
        }
    }

    /// List every item in `collection`, in id order.
    pub fn list_items(&self, collection: &str) -> Result<Vec<ItemMeta>> {
        let txn = self.db.begin_read()?;
        let items = txn.open_table(ITEMS)?;
        let mut out = Vec::new();
        for entry in items.iter()? {
            let (_, v) = entry?;
            let meta: ItemMeta = serde_json::from_slice(v.value())?;
            if meta.collection == collection {
                out.push(meta);
            }
        }
        Ok(out)
    }

    /// Find an item in `collection` whose attribute set is *exactly* `attrs`.
    ///
    /// Used to implement Secret Service "replace" semantics: a create with
    /// `replace = true` overwrites the item matching on the full attribute set.
    pub fn find_item_by_attrs_exact(
        &self,
        collection: &str,
        attrs: &HashMap<String, String>,
    ) -> Result<Option<ItemMeta>> {
        let txn = self.db.begin_read()?;
        let items = txn.open_table(ITEMS)?;
        for entry in items.iter()? {
            let (_, v) = entry?;
            let meta: ItemMeta = serde_json::from_slice(v.value())?;
            if meta.collection == collection && &meta.attributes == attrs {
                return Ok(Some(meta));
            }
        }
        Ok(None)
    }

    /// Search all items for those whose attributes are a superset of `attrs`.
    ///
    /// An item matches when every `(k, v)` in `attrs` is present with the same
    /// value; an empty query therefore matches every item. This is a full
    /// table scan, which is acceptable for the expected data sizes.
    pub fn search_items(&self, attrs: &HashMap<String, String>) -> Result<Vec<ItemMeta>> {
        let txn = self.db.begin_read()?;
        let items = txn.open_table(ITEMS)?;
        let mut out = Vec::new();
        for entry in items.iter()? {
            let (_, v) = entry?;
            let meta: ItemMeta = serde_json::from_slice(v.value())?;
            let matches = attrs
                .iter()
                .all(|(k, val)| meta.attributes.get(k).is_some_and(|got| got == val));
            if matches {
                out.push(meta);
            }
        }
        Ok(out)
    }

    /// Update an item's label, attributes, content type and/or secret and bump
    /// its modified timestamp. `None` fields are left unchanged; a `Some`
    /// secret rewrites the `.gpg` file.
    pub fn update_item(
        &self,
        id: &str,
        label: Option<&str>,
        attributes: Option<HashMap<String, String>>,
        content_type: Option<&str>,
        secret_ciphertext: Option<&[u8]>,
    ) -> Result<ItemMeta> {
        let mut meta = self.get_item(id)?;
        if let Some(label) = label {
            meta.label = label.to_string();
        }
        if let Some(attrs) = attributes {
            meta.attributes = attrs;
        }
        if let Some(ct) = content_type {
            meta.content_type = ct.to_string();
        }
        meta.modified = now_secs();

        if let Some(secret) = secret_ciphertext {
            self.write_secret_file(id, secret)?;
        }

        let txn = self.db.begin_write()?;
        {
            let mut items = txn.open_table(ITEMS)?;
            let bytes = serde_json::to_vec(&meta)?;
            items.insert(meta.id.as_str(), bytes.as_slice())?;
        }
        txn.commit()?;
        Ok(meta)
    }

    /// Delete an item and its secret file. Returns [`Error::NotFound`] if the
    /// item does not exist.
    pub fn delete_item(&self, id: &str) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut items = txn.open_table(ITEMS)?;
            if items.remove(id)?.is_none() {
                return Err(Error::NotFound(format!("item {id}")));
            }
        }
        txn.commit()?;

        let path = self.secret_path(id);
        if let Err(e) = fs::remove_file(&path)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            return Err(e.into());
        }
        Ok(())
    }

    // --- secret files ----------------------------------------------------

    /// Write `ciphertext` to `secrets/<id>.gpg` with `0600` permissions.
    fn write_secret_file(&self, id: &str, ciphertext: &[u8]) -> Result<()> {
        let path = self.secret_path(id);
        fs::write(&path, ciphertext)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    /// Read the raw ciphertext of item `id`'s secret file.
    pub fn read_secret_file(&self, id: &str) -> Result<Vec<u8>> {
        let path = self.secret_path(id);
        match fs::read(&path) {
            Ok(bytes) => Ok(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(Error::NotFound(format!("secret file for item {id}")))
            }
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attrs(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn open_creates_dirs_with_0700() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("store");
        let store = Store::open(&root).unwrap();
        assert_eq!(mode(&root), 0o700);
        assert_eq!(mode(&store.secrets_dir), 0o700);
    }

    #[test]
    fn collection_crud() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();

        let c = store
            .create_collection("Personal", Some("personal"))
            .unwrap();
        assert_eq!(c.label, "Personal");
        assert_eq!(store.get_collection(&c.id).unwrap(), c);
        assert_eq!(store.read_alias("personal").unwrap(), Some(c.id.clone()));

        let all = store.list_collections().unwrap();
        assert_eq!(all.len(), 1);

        let relabelled = store.set_collection_label(&c.id, "Work").unwrap();
        assert_eq!(relabelled.label, "Work");
        assert!(relabelled.modified >= c.modified);
        assert_eq!(store.get_collection(&c.id).unwrap().label, "Work");

        store.delete_collection(&c.id).unwrap();
        assert!(matches!(
            store.get_collection(&c.id),
            Err(Error::NotFound(_))
        ));
        assert!(matches!(
            store.delete_collection(&c.id),
            Err(Error::NotFound(_))
        ));
    }

    #[test]
    fn ensure_default_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let a = store.ensure_default().unwrap();
        let b = store.ensure_default().unwrap();
        assert_eq!(a, b);
        assert_eq!(a.id, DEFAULT_COLLECTION_ID);
        assert_eq!(
            store.read_alias("default").unwrap().as_deref(),
            Some(DEFAULT_COLLECTION_ID)
        );
        assert_eq!(store.list_collections().unwrap().len(), 1);
    }

    #[test]
    fn alias_set_read_remove() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        assert_eq!(store.read_alias("missing").unwrap(), None);

        store.set_alias("session", Some("abc")).unwrap();
        assert_eq!(store.read_alias("session").unwrap().as_deref(), Some("abc"));

        store.set_alias("session", None).unwrap();
        assert_eq!(store.read_alias("session").unwrap(), None);
    }

    #[test]
    fn item_crud_and_secret_perms() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let c = store.create_collection("c", None).unwrap();

        let item = store
            .create_item(
                &c.id,
                "wifi",
                attrs(&[("service", "wifi"), ("user", "me")]),
                "text/plain",
                b"CIPHERTEXT-1",
            )
            .unwrap();

        assert_eq!(store.get_item(&item.id).unwrap(), item);
        assert_eq!(store.read_secret_file(&item.id).unwrap(), b"CIPHERTEXT-1");
        assert_eq!(mode(&store.secret_path(&item.id)), 0o600);
        assert_eq!(store.list_items(&c.id).unwrap().len(), 1);

        let updated = store
            .update_item(
                &item.id,
                Some("wifi-home"),
                None,
                None,
                Some(b"CIPHERTEXT-2"),
            )
            .unwrap();
        assert_eq!(updated.label, "wifi-home");
        assert!(updated.modified >= item.modified);
        assert_eq!(store.read_secret_file(&item.id).unwrap(), b"CIPHERTEXT-2");

        store.delete_item(&item.id).unwrap();
        assert!(matches!(store.get_item(&item.id), Err(Error::NotFound(_))));
        assert!(matches!(
            store.read_secret_file(&item.id),
            Err(Error::NotFound(_))
        ));
    }

    #[test]
    fn create_item_in_missing_collection_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        assert!(matches!(
            store.create_item("nope", "x", HashMap::new(), "text/plain", b"c"),
            Err(Error::NotFound(_))
        ));
    }

    #[test]
    fn find_item_by_attrs_exact_matches_full_set_only() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let c = store.create_collection("c", None).unwrap();
        let a = attrs(&[("service", "mail"), ("user", "a")]);
        let item = store
            .create_item(&c.id, "mail", a.clone(), "text/plain", b"c")
            .unwrap();

        assert_eq!(
            store
                .find_item_by_attrs_exact(&c.id, &a)
                .unwrap()
                .unwrap()
                .id,
            item.id
        );
        // A strict subset is not an exact match.
        let subset = attrs(&[("service", "mail")]);
        assert!(
            store
                .find_item_by_attrs_exact(&c.id, &subset)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn search_subset_semantics() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let c = store.create_collection("c", None).unwrap();

        store
            .create_item(
                &c.id,
                "one",
                attrs(&[("service", "mail"), ("user", "a")]),
                "text/plain",
                b"1",
            )
            .unwrap();
        store
            .create_item(
                &c.id,
                "two",
                attrs(&[("service", "mail"), ("user", "b")]),
                "text/plain",
                b"2",
            )
            .unwrap();
        store
            .create_item(
                &c.id,
                "three",
                attrs(&[("service", "chat"), ("user", "a")]),
                "text/plain",
                b"3",
            )
            .unwrap();

        // Empty query matches everything.
        assert_eq!(store.search_items(&HashMap::new()).unwrap().len(), 3);
        // Single attribute subset.
        assert_eq!(
            store
                .search_items(&attrs(&[("service", "mail")]))
                .unwrap()
                .len(),
            2
        );
        // Multiple attributes must all match.
        assert_eq!(
            store
                .search_items(&attrs(&[("service", "mail"), ("user", "a")]))
                .unwrap()
                .len(),
            1
        );
        // No match.
        assert_eq!(
            store
                .search_items(&attrs(&[("service", "vpn")]))
                .unwrap()
                .len(),
            0
        );
    }

    #[test]
    fn delete_collection_cascades() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let c = store.create_collection("c", Some("c-alias")).unwrap();
        let other = store.create_collection("other", None).unwrap();

        let i1 = store
            .create_item(&c.id, "a", attrs(&[("k", "v")]), "text/plain", b"1")
            .unwrap();
        let i2 = store
            .create_item(&c.id, "b", attrs(&[("k", "w")]), "text/plain", b"2")
            .unwrap();
        let survivor = store
            .create_item(&other.id, "s", attrs(&[("k", "x")]), "text/plain", b"3")
            .unwrap();

        let p1 = store.secret_path(&i1.id);
        let p2 = store.secret_path(&i2.id);
        assert!(p1.exists() && p2.exists());

        store.delete_collection(&c.id).unwrap();

        // Items and secret files gone, alias gone.
        assert!(matches!(store.get_item(&i1.id), Err(Error::NotFound(_))));
        assert!(matches!(store.get_item(&i2.id), Err(Error::NotFound(_))));
        assert!(!p1.exists() && !p2.exists());
        assert_eq!(store.read_alias("c-alias").unwrap(), None);

        // The other collection and its item survive.
        assert!(store.get_collection(&other.id).is_ok());
        assert!(store.get_item(&survivor.id).is_ok());
    }
}
