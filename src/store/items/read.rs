//! Item metadata lookup, listing, and attribute searches.

use std::collections::HashMap;

use redb::{ReadableDatabase, ReadableTable};

use crate::error::{Error, Result};
use crate::store::{ITEMS, ItemMeta, Store, decode_item};

impl Store {
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
    pub(in crate::store) fn find_item_by_attrs_exact(
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
}
