//! Collection and alias metadata operations.

use std::collections::HashMap;

use redb::{ReadableDatabase, ReadableTable};

use super::{
    ALIASES, COLLECTIONS, CollectionMeta, DEFAULT_COLLECTION_ID, DeletedCollection, Error, ITEMS,
    ItemMeta, PersistError, Result, Store, decode_collection, decode_item, definite,
    is_valid_collection_id, now_secs,
};
use crate::random_hex_id;

impl Store {
    pub(super) fn decode_collection_from_table(
        collections: &impl ReadableTable<&'static str, &'static [u8]>,
        id: &str,
    ) -> Result<CollectionMeta> {
        if !is_valid_collection_id(id) {
            return Err(Error::NotFound(format!("collection {id}")));
        }
        let value = collections
            .get(id)?
            .ok_or_else(|| Error::NotFound(format!("collection {id}")))?;
        decode_collection(id, value.value())
    }

    pub(super) fn validate_collection_in_txn(
        txn: &redb::WriteTransaction,
        id: &str,
    ) -> Result<CollectionMeta> {
        let collections = txn.open_table(COLLECTIONS)?;
        Self::decode_collection_from_table(&collections, id)
    }

    /// Create a new collection with the given label, optionally registering an
    /// alias that points at it.
    pub fn create_collection(&self, label: &str, alias: Option<&str>) -> Result<CollectionMeta> {
        let now = now_secs();
        let meta = CollectionMeta {
            id: random_hex_id(),
            label: label.to_string(),
            created: now,
            modified: now,
        };

        let (mut mutation_guard, txn) = self.begin_write_checked()?;
        {
            let mut table = txn.open_table(COLLECTIONS)?;
            let bytes = serde_json::to_vec(&meta)?;
            table.insert(meta.id.as_str(), bytes.as_slice())?;
        }
        if let Some(alias) = alias {
            let mut aliases = txn.open_table(ALIASES)?;
            aliases.insert(alias, meta.id.as_str())?;
        }
        self.finish_metadata_commit(txn.commit())?;
        mutation_guard.preserve_index();
        Ok(meta)
    }

    /// Fetch a single collection by id.
    pub fn get_collection(&self, id: &str) -> Result<CollectionMeta> {
        self.ensure_not_poisoned()?;
        let txn = self.db.begin_read()?;
        let table = txn.open_table(COLLECTIONS)?;
        Self::decode_collection_from_table(&table, id)
    }

    /// List every collection, in id order.
    pub fn list_collections(&self) -> Result<Vec<CollectionMeta>> {
        self.ensure_not_poisoned()?;
        let txn = self.db.begin_read()?;
        let table = txn.open_table(COLLECTIONS)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            out.push(decode_collection(key.value(), value.value())?);
        }
        Ok(out)
    }

    /// Delete a collection together with all its items, their `.gpg` files and
    /// any aliases pointing at it. Returns [`Error::NotFound`] if the
    /// collection does not exist.
    pub fn delete_collection(&self, id: &str) -> Result<DeletedCollection> {
        if !is_valid_collection_id(id) {
            return Err(Error::NotFound(format!("collection {id}")));
        }
        let (mut mutation_guard, txn) = self.begin_write_checked()?;
        Self::validate_collection_in_txn(&txn, id)?;

        let metadata_to_remove =
            Self::collection_items_locked(&txn, mutation_guard.index.as_ref(), id)?;
        let item_ids: Vec<_> = metadata_to_remove
            .iter()
            .map(|meta| meta.id.clone())
            .collect();
        let paths = item_ids
            .iter()
            .map(|item_id| self.secret_path(item_id))
            .collect::<Result<Vec<_>>>()?;
        let aliases = {
            let aliases_table = txn.open_table(ALIASES)?;
            let mut aliases = Vec::new();
            for entry in aliases_table.iter()? {
                let (key, value) = entry?;
                if value.value() == id {
                    aliases.push(key.value().to_string());
                }
            }
            aliases
        };

        let commit = || -> std::result::Result<(), PersistError> {
            {
                let mut collections = txn.open_table(COLLECTIONS).map_err(definite)?;
                collections.remove(id).map_err(definite)?;
            }
            {
                let mut items = txn.open_table(ITEMS).map_err(definite)?;
                for item_id in &item_ids {
                    items.remove(item_id.as_str()).map_err(definite)?;
                }
            }
            {
                let mut aliases_table = txn.open_table(ALIASES).map_err(definite)?;
                for alias in &aliases {
                    aliases_table.remove(alias.as_str()).map_err(definite)?;
                }
            }
            txn.commit()
                .map_err(|err| PersistError::Indeterminate(err.into()))
        };
        self.quarantine_many_then_commit(&paths, commit)?;
        if let Some(index) = mutation_guard.index.as_mut() {
            for metadata in &metadata_to_remove {
                index.remove(metadata);
            }
        }
        mutation_guard.preserve_index();
        Ok(DeletedCollection { item_ids, aliases })
    }

    fn collection_items_locked(
        txn: &redb::WriteTransaction,
        index: Option<&super::items::ItemIndex>,
        id: &str,
    ) -> Result<Vec<ItemMeta>> {
        let mut metadata_to_remove = Vec::new();
        {
            let items = txn.open_table(ITEMS)?;
            let mut collect = |table_key: &str, bytes: &[u8]| -> Result<()> {
                let metadata = decode_item(table_key, bytes)?;
                if metadata.collection == id {
                    metadata_to_remove.push(metadata);
                }
                Ok(())
            };
            if let Some(candidates) =
                index.and_then(|index| index.selective_candidates(Some(id), &HashMap::new()))
            {
                for item_id in candidates {
                    let value = items.get(item_id.as_str())?.ok_or_else(|| {
                        Error::Config(format!(
                            "item lookup index references missing item {item_id}"
                        ))
                    })?;
                    collect(item_id, value.value())?;
                }
            } else {
                for entry in items.iter()? {
                    let (key, value) = entry?;
                    collect(key.value(), value.value())?;
                }
            }
        }
        Ok(metadata_to_remove)
    }

    /// Ensure the well-known `default` collection exists and bootstrap its
    /// `default` alias when absent. Returns the collection metadata.
    pub fn ensure_default(&self) -> Result<CollectionMeta> {
        let (mut mutation_guard, txn) = self.begin_write_checked()?;
        let meta = {
            let mut collections = txn.open_table(COLLECTIONS)?;
            let existing = collections
                .get(DEFAULT_COLLECTION_ID)?
                .map(|value| value.value().to_vec());
            let meta = if let Some(bytes) = existing {
                decode_collection(DEFAULT_COLLECTION_ID, &bytes)?
            } else {
                let now = now_secs();
                let meta = CollectionMeta {
                    id: DEFAULT_COLLECTION_ID.to_string(),
                    label: "Default".to_string(),
                    created: now,
                    modified: now,
                };
                let bytes = serde_json::to_vec(&meta)?;
                collections.insert(DEFAULT_COLLECTION_ID, bytes.as_slice())?;
                meta
            };
            let mut aliases = txn.open_table(ALIASES)?;
            if aliases.get(DEFAULT_COLLECTION_ID)?.is_none() {
                aliases.insert(DEFAULT_COLLECTION_ID, DEFAULT_COLLECTION_ID)?;
            }
            meta
        };
        self.finish_metadata_commit(txn.commit())?;
        mutation_guard.preserve_index();
        Ok(meta)
    }

    /// Change a collection's label and bump its modified timestamp.
    pub fn set_collection_label(&self, id: &str, label: &str) -> Result<CollectionMeta> {
        if !is_valid_collection_id(id) {
            return Err(Error::NotFound(format!("collection {id}")));
        }
        let (mut mutation_guard, txn) = self.begin_write_checked()?;
        let mut meta = Self::validate_collection_in_txn(&txn, id)?;
        meta.label = label.to_string();
        meta.modified = now_secs();
        {
            let mut collections = txn.open_table(COLLECTIONS)?;
            let bytes = serde_json::to_vec(&meta)?;
            collections.insert(id, bytes.as_slice())?;
        }
        self.finish_metadata_commit(txn.commit())?;
        mutation_guard.preserve_index();
        Ok(meta)
    }

    /// Set (`Some`) or remove (`None`) the alias `name`.
    pub fn set_alias(&self, name: &str, collection_id: Option<&str>) -> Result<()> {
        let (mut mutation_guard, txn) = self.begin_write_checked()?;
        if let Some(id) = collection_id {
            Self::validate_collection_in_txn(&txn, id)?;
        }
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
        self.finish_metadata_commit(txn.commit())?;
        mutation_guard.preserve_index();
        Ok(())
    }

    /// Resolve alias `name` to a collection id, or `None` if unset.
    pub fn read_alias(&self, name: &str) -> Result<Option<String>> {
        self.ensure_not_poisoned()?;
        let txn = self.db.begin_read()?;
        let aliases = txn.open_table(ALIASES)?;
        Ok(aliases.get(name)?.map(|v| v.value().to_string()))
    }

    /// List every alias as `(name, collection_id)` pairs.
    pub fn list_aliases(&self) -> Result<Vec<(String, String)>> {
        self.ensure_not_poisoned()?;
        let txn = self.db.begin_read()?;
        let aliases = txn.open_table(ALIASES)?;
        let mut out = Vec::new();
        for entry in aliases.iter()? {
            let (k, v) = entry?;
            out.push((k.value().to_string(), v.value().to_string()));
        }
        Ok(out)
    }
}
