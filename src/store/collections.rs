//! Collection and alias metadata operations.

use redb::{ReadableDatabase, ReadableTable};

use super::{
    ALIASES, COLLECTIONS, CollectionMeta, DEFAULT_COLLECTION_ID, DeletedCollection, Error, ITEMS,
    ItemMeta, PersistError, Result, Store, definite, is_valid_collection_id, now_secs, random_id,
};

impl Store {
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

        let (_mutation_guard, txn) = self.begin_write_checked()?;
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
        Ok(meta)
    }

    /// Fetch a single collection by id.
    pub fn get_collection(&self, id: &str) -> Result<CollectionMeta> {
        self.ensure_not_poisoned()?;
        if !is_valid_collection_id(id) {
            return Err(Error::NotFound(format!("collection {id}")));
        }
        let txn = self.db.begin_read()?;
        let table = txn.open_table(COLLECTIONS)?;
        let metadata: CollectionMeta = match table.get(id)? {
            Some(value) => serde_json::from_slice(value.value())?,
            None => return Err(Error::NotFound(format!("collection {id}"))),
        };
        if metadata.id != id {
            return Err(Error::Config(format!(
                "collection metadata id {} does not match table key {id}",
                metadata.id
            )));
        }
        Ok(metadata)
    }

    /// List every collection, in id order.
    pub fn list_collections(&self) -> Result<Vec<CollectionMeta>> {
        self.ensure_not_poisoned()?;
        let txn = self.db.begin_read()?;
        let table = txn.open_table(COLLECTIONS)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            let table_key = key.value();
            if !is_valid_collection_id(table_key) {
                return Err(Error::Config(format!(
                    "invalid collection id in store: {table_key}"
                )));
            }
            let metadata: CollectionMeta = serde_json::from_slice(value.value())?;
            if metadata.id != table_key {
                return Err(Error::Config(format!(
                    "collection metadata id {} does not match table key {table_key}",
                    metadata.id
                )));
            }
            out.push(metadata);
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
        let (_mutation_guard, txn) = self.begin_write_checked()?;
        {
            let collections = txn.open_table(COLLECTIONS)?;
            let metadata: CollectionMeta = collections
                .get(id)?
                .map(|value| serde_json::from_slice(value.value()))
                .transpose()?
                .ok_or_else(|| Error::NotFound(format!("collection {id}")))?;
            if metadata.id != id {
                return Err(Error::Config(format!(
                    "collection metadata id {} does not match table key {id}",
                    metadata.id
                )));
            }
        }

        let mut item_ids = Vec::new();
        {
            let items = txn.open_table(ITEMS)?;
            for entry in items.iter()? {
                let (key, value) = entry?;
                let metadata: ItemMeta = serde_json::from_slice(value.value())?;
                if metadata.collection == id {
                    let item_id = key.value().to_string();
                    self.secret_path(&item_id)?;
                    if metadata.id != item_id {
                        return Err(Error::Config(format!(
                            "item metadata id {} does not match table key {item_id}",
                            metadata.id
                        )));
                    }
                    item_ids.push(item_id);
                }
            }
        }
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
        Ok(DeletedCollection { item_ids, aliases })
    }

    /// Ensure the well-known `default` collection exists and bootstrap its
    /// `default` alias when absent. Returns the collection metadata.
    pub fn ensure_default(&self) -> Result<CollectionMeta> {
        let (_mutation_guard, txn) = self.begin_write_checked()?;
        let meta = {
            let mut collections = txn.open_table(COLLECTIONS)?;
            let existing = collections
                .get(DEFAULT_COLLECTION_ID)?
                .map(|value| value.value().to_vec());
            let meta = if let Some(bytes) = existing {
                let metadata: CollectionMeta = serde_json::from_slice(&bytes)?;
                if metadata.id != DEFAULT_COLLECTION_ID {
                    return Err(Error::Config(format!(
                        "collection metadata id {} does not match table key {DEFAULT_COLLECTION_ID}",
                        metadata.id
                    )));
                }
                metadata
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
            if aliases.get("default")?.is_none() {
                aliases.insert("default", DEFAULT_COLLECTION_ID)?;
            }
            meta
        };
        self.finish_metadata_commit(txn.commit())?;
        Ok(meta)
    }

    /// Change a collection's label and bump its modified timestamp.
    pub fn set_collection_label(&self, id: &str, label: &str) -> Result<CollectionMeta> {
        if !is_valid_collection_id(id) {
            return Err(Error::NotFound(format!("collection {id}")));
        }
        let (_mutation_guard, txn) = self.begin_write_checked()?;
        let meta = {
            let mut collections = txn.open_table(COLLECTIONS)?;
            let bytes = collections
                .get(id)?
                .map(|value| value.value().to_vec())
                .ok_or_else(|| Error::NotFound(format!("collection {id}")))?;
            let mut meta: CollectionMeta = serde_json::from_slice(&bytes)?;
            if meta.id != id {
                return Err(Error::Config(format!(
                    "collection metadata id {} does not match table key {id}",
                    meta.id
                )));
            }
            meta.label = label.to_string();
            meta.modified = now_secs();
            let bytes = serde_json::to_vec(&meta)?;
            collections.insert(id, bytes.as_slice())?;
            meta
        };
        self.finish_metadata_commit(txn.commit())?;
        Ok(meta)
    }

    // --- aliases ---------------------------------------------------------

    /// Set (`Some`) or remove (`None`) the alias `name`.
    pub fn set_alias(&self, name: &str, collection_id: Option<&str>) -> Result<()> {
        let (_mutation_guard, txn) = self.begin_write_checked()?;
        if let Some(id) = collection_id {
            if !is_valid_collection_id(id) {
                return Err(Error::NotFound(format!("collection {id}")));
            }
            let collections = txn.open_table(COLLECTIONS)?;
            let metadata: CollectionMeta = collections
                .get(id)?
                .map(|value| serde_json::from_slice(value.value()))
                .transpose()?
                .ok_or_else(|| Error::NotFound(format!("collection {id}")))?;
            if metadata.id != id {
                return Err(Error::Config(format!(
                    "collection metadata id {} does not match table key {id}",
                    metadata.id
                )));
            }
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
