//! Item metadata and ciphertext persistence operations.

use std::collections::HashMap;
use std::path::Path;

use redb::{ReadableDatabase, ReadableTable};

use crate::error::{Error, Result};

use super::{
    COLLECTIONS, CollectionMeta, ITEMS, ItemMeta, PersistError, Store, ciphertext_sha256,
    decode_item, definite, is_valid_collection_id, now_secs, random_id,
};

impl Store {
    /// Create an item in `collection`, writing its ciphertext to a fresh
    /// `0600` secret file. The collection must already exist.
    #[cfg(test)]
    pub(crate) fn create_item(
        &self,
        collection: &str,
        label: &str,
        attributes: HashMap<String, String>,
        content_type: &str,
        secret_ciphertext: &[u8],
    ) -> Result<ItemMeta> {
        if !is_valid_collection_id(collection) {
            return Err(Error::NotFound(format!("collection {collection}")));
        }
        let (_mutation_guard, txn) = self.begin_write_checked()?;
        Self::validate_item_collection(&txn, collection)?;
        self.create_item_locked(
            txn,
            collection,
            label,
            attributes,
            content_type,
            secret_ciphertext,
        )
    }

    /// Create an item or atomically replace an exact attribute match.
    pub fn create_or_replace_item(
        &self,
        collection: &str,
        label: &str,
        attributes: HashMap<String, String>,
        content_type: &str,
        secret_ciphertext: &[u8],
        replace: bool,
    ) -> Result<(ItemMeta, bool)> {
        self.create_or_replace_item_after_initial_check(
            collection,
            label,
            attributes,
            content_type,
            secret_ciphertext,
            replace,
            || {},
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "test hook preserves production replace inputs while controlling gate contention"
    )]
    pub(super) fn create_or_replace_item_after_initial_check(
        &self,
        collection: &str,
        label: &str,
        attributes: HashMap<String, String>,
        content_type: &str,
        secret_ciphertext: &[u8],
        replace: bool,
        after_initial_check: impl FnOnce(),
    ) -> Result<(ItemMeta, bool)> {
        if !is_valid_collection_id(collection) {
            return Err(Error::NotFound(format!("collection {collection}")));
        }
        let (_mutation_guard, txn) =
            self.begin_write_checked_after_initial_check(after_initial_check)?;
        Self::validate_item_collection(&txn, collection)?;
        let existing = if replace {
            Self::find_item_by_attrs_exact_locked(&txn, collection, &attributes)?
        } else {
            None
        };
        match existing {
            Some(metadata) => self
                .update_item_locked(
                    txn,
                    &metadata.id,
                    Some(label),
                    None,
                    Some(content_type),
                    Some(secret_ciphertext),
                )
                .map(|metadata| (metadata, true)),
            None => self
                .create_item_locked(
                    txn,
                    collection,
                    label,
                    attributes,
                    content_type,
                    secret_ciphertext,
                )
                .map(|metadata| (metadata, false)),
        }
    }

    fn validate_item_collection(txn: &redb::WriteTransaction, collection: &str) -> Result<()> {
        let collections = txn.open_table(COLLECTIONS)?;
        let metadata: CollectionMeta = collections
            .get(collection)?
            .map(|value| serde_json::from_slice(value.value()))
            .transpose()?
            .ok_or_else(|| Error::NotFound(format!("collection {collection}")))?;
        if metadata.id != collection {
            return Err(Error::Config(format!(
                "collection metadata id {} does not match table key {collection}",
                metadata.id
            )));
        }
        Ok(())
    }

    fn find_item_by_attrs_exact_locked(
        txn: &redb::WriteTransaction,
        collection: &str,
        attrs: &HashMap<String, String>,
    ) -> Result<Option<ItemMeta>> {
        let items = txn.open_table(ITEMS)?;
        for entry in items.iter()? {
            let (key, value) = entry?;
            let metadata = decode_item(key.value(), value.value())?;
            if metadata.collection == collection && &metadata.attributes == attrs {
                return Ok(Some(metadata));
            }
        }
        Ok(None)
    }

    fn create_item_locked(
        &self,
        txn: redb::WriteTransaction,
        collection: &str,
        label: &str,
        attributes: HashMap<String, String>,
        content_type: &str,
        secret_ciphertext: &[u8],
    ) -> Result<ItemMeta> {
        let now = now_secs();
        let meta = ItemMeta {
            id: random_id(),
            collection: collection.to_string(),
            label: label.to_string(),
            attributes,
            content_type: content_type.to_string(),
            ciphertext_sha256: Some(ciphertext_sha256(secret_ciphertext)),
            created: now,
            modified: now,
        };
        let create_marker = self.write_secret_file(&meta.id, secret_ciphertext)?;
        let persist_result = (|| -> std::result::Result<(), PersistError> {
            {
                let mut items = txn.open_table(ITEMS).map_err(definite)?;
                let bytes = serde_json::to_vec(&meta).map_err(definite)?;
                items
                    .insert(meta.id.as_str(), bytes.as_slice())
                    .map_err(definite)?;
            }
            txn.commit()
                .map_err(|err| PersistError::Indeterminate(err.into()))
        })();
        self.finish_create_persist(&meta.id, &create_marker, persist_result)?;
        Ok(meta)
    }

    pub(super) fn finish_create_persist(
        &self,
        id: &str,
        create_marker: &Path,
        persist_result: std::result::Result<(), PersistError>,
    ) -> Result<()> {
        match persist_result {
            Ok(()) => {
                self.finish_post_commit_cleanup(Self::remove_recovery_file(
                    create_marker,
                    "item metadata committed",
                    |path| self.remove_secret_file(path),
                ))?;
                self.finish_post_commit_cleanup(self.sync_secrets_dir())
            }
            Err(PersistError::Definite(err)) => {
                let path = self.secret_path(id)?;
                if let Err(cleanup_err) = self.remove_secret_file(&path) {
                    return self.poison_error(Error::Config(format!(
                        "item metadata write failed: {err}; unindexed ciphertext cleanup failed at {}: {cleanup_err}",
                        path.display()
                    )));
                }
                if let Err(sync_err) = self.sync_secrets_dir() {
                    return self.poison_error(Error::Config(format!(
                        "item metadata write failed: {err}; unindexed ciphertext was removed, but directory sync failed: {sync_err}"
                    )));
                }
                if let Err(cleanup_err) = self.remove_secret_file(create_marker) {
                    return self.poison_error(Error::Config(format!(
                        "item metadata write failed: {err}; create marker cleanup failed at {}: {cleanup_err}",
                        create_marker.display()
                    )));
                }
                match self.sync_secrets_dir() {
                    Ok(()) => Err(err),
                    Err(sync_err) => self.poison_error(Error::Config(format!(
                        "item metadata write failed: {err}; create marker was removed, but directory sync failed: {sync_err}"
                    ))),
                }
            }
            Err(PersistError::Indeterminate(err)) => {
                self.poison();
                Err(Error::Config(format!(
                    "item metadata commit outcome is indeterminate: {err}; ciphertext retained for restart reconciliation"
                )))
            }
        }
    }

    /// Fetch a single item by id.
    pub fn get_item(&self, id: &str) -> Result<ItemMeta> {
        self.ensure_not_poisoned()?;
        self.secret_path(id)?;
        let txn = self.db.begin_read()?;
        let items = txn.open_table(ITEMS)?;
        let metadata: ItemMeta = match items.get(id)? {
            Some(value) => serde_json::from_slice(value.value())?,
            None => return Err(Error::NotFound(format!("item {id}"))),
        };
        if metadata.id != id {
            return Err(Error::Config(format!(
                "item metadata id {} does not match table key {id}",
                metadata.id
            )));
        }
        Ok(metadata)
    }

    /// List every item in `collection`, in id order.
    pub fn list_items(&self, collection: &str) -> Result<Vec<ItemMeta>> {
        self.ensure_not_poisoned()?;
        let txn = self.db.begin_read()?;
        let items = txn.open_table(ITEMS)?;
        let mut out = Vec::new();
        for entry in items.iter()? {
            let (key, value) = entry?;
            let metadata = decode_item(key.value(), value.value())?;
            if metadata.collection == collection {
                out.push(metadata);
            }
        }
        Ok(out)
    }

    /// Find an item in `collection` whose attribute set is *exactly* `attrs`.
    #[cfg(test)]
    pub(super) fn find_item_by_attrs_exact(
        &self,
        collection: &str,
        attrs: &HashMap<String, String>,
    ) -> Result<Option<ItemMeta>> {
        self.ensure_not_poisoned()?;
        let txn = self.db.begin_read()?;
        let items = txn.open_table(ITEMS)?;
        for entry in items.iter()? {
            let (key, value) = entry?;
            let metadata = decode_item(key.value(), value.value())?;
            if metadata.collection == collection && &metadata.attributes == attrs {
                return Ok(Some(metadata));
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
        self.search_items_matching(None, attrs)
    }

    /// Search only matches in the selected collection without building a global result vector.
    pub(crate) fn search_collection_items(
        &self,
        collection: &str,
        attrs: &HashMap<String, String>,
    ) -> Result<Vec<ItemMeta>> {
        self.search_items_matching(Some(collection), attrs)
    }

    fn search_items_matching(
        &self,
        collection: Option<&str>,
        attrs: &HashMap<String, String>,
    ) -> Result<Vec<ItemMeta>> {
        // ponytail: existing item keys are global; retain validated full scans until profiling justifies an index.
        self.ensure_not_poisoned()?;
        let txn = self.db.begin_read()?;
        let items = txn.open_table(ITEMS)?;
        let mut out = Vec::new();
        for entry in items.iter()? {
            let (key, value) = entry?;
            let metadata = decode_item(key.value(), value.value())?;
            if collection.is_some_and(|id| metadata.collection != id) {
                continue;
            }
            let matches = attrs.iter().all(|(name, expected)| {
                metadata
                    .attributes
                    .get(name)
                    .is_some_and(|actual| actual == expected)
            });
            if matches {
                out.push(metadata);
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
        self.secret_path(id)?;
        let (_mutation_guard, txn) = self.begin_write_checked()?;
        self.update_item_locked(txn, id, label, attributes, content_type, secret_ciphertext)
    }

    fn update_item_locked(
        &self,
        txn: redb::WriteTransaction,
        id: &str,
        label: Option<&str>,
        attributes: Option<HashMap<String, String>>,
        content_type: Option<&str>,
        secret_ciphertext: Option<&[u8]>,
    ) -> Result<ItemMeta> {
        let mut meta = {
            let items = txn.open_table(ITEMS)?;
            let bytes = items
                .get(id)?
                .map(|value| value.value().to_vec())
                .ok_or_else(|| Error::NotFound(format!("item {id}")))?;
            decode_item(id, &bytes)?
        };
        if let Some(label) = label {
            meta.label = label.to_string();
        }
        if let Some(attrs) = attributes {
            meta.attributes = attrs;
        }
        if let Some(content_type) = content_type {
            meta.content_type = content_type.to_string();
        }
        if let Some(secret) = secret_ciphertext {
            meta.ciphertext_sha256 = Some(ciphertext_sha256(secret));
        }
        meta.modified = now_secs();

        let bytes = serde_json::to_vec(&meta)?;
        let commit = || -> std::result::Result<(), PersistError> {
            {
                let mut items = txn.open_table(ITEMS).map_err(definite)?;
                items.insert(id, bytes.as_slice()).map_err(definite)?;
            }
            txn.commit()
                .map_err(|err| PersistError::Indeterminate(err.into()))
        };
        if let Some(secret) = secret_ciphertext {
            let path = self.secret_path(id)?;
            let staged = self.stage_secret_file(id, secret, "update")?;
            self.replace_then_commit(&path, &staged, commit)?;
        } else {
            match commit() {
                Ok(()) => {}
                Err(PersistError::Definite(err)) => return Err(err),
                Err(PersistError::Indeterminate(err)) => {
                    self.poison();
                    return Err(Error::Config(format!(
                        "item metadata commit outcome is indeterminate: {err}"
                    )));
                }
            }
        }
        Ok(meta)
    }

    /// Delete an item and its secret file. Returns [`Error::NotFound`] if the
    /// item does not exist.
    pub fn delete_item(&self, id: &str) -> Result<()> {
        let path = self.secret_path(id)?;
        let (_mutation_guard, txn) = self.begin_write_checked()?;
        {
            let items = txn.open_table(ITEMS)?;
            if items.get(id)?.is_none() {
                return Err(Error::NotFound(format!("item {id}")));
            }
        }
        let commit = || -> std::result::Result<(), PersistError> {
            {
                let mut items = txn
                    .open_table(ITEMS)
                    .map_err(|err| PersistError::Definite(err.into()))?;
                items
                    .remove(id)
                    .map_err(|err| PersistError::Definite(err.into()))?;
            }
            txn.commit()
                .map_err(|err| PersistError::Indeterminate(err.into()))
        };
        self.quarantine_then_commit(&path, commit)
    }

    /// Delete only an item metadata record using its authoritative redb key.
    ///
    /// Used by integrity repair for noncanonical keys that must never become
    /// filesystem paths.
    pub fn delete_item_metadata(&self, table_key: &str) -> Result<()> {
        let (_mutation_guard, txn) = self.begin_write_checked()?;
        {
            let mut items = txn.open_table(ITEMS)?;
            if items.remove(table_key)?.is_none() {
                return Err(Error::NotFound(format!("item {table_key}")));
            }
        }
        self.finish_metadata_commit(txn.commit())?;
        Ok(())
    }
}
