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
        self.search_items_matching(Some(collection), &HashMap::new())
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
    /// value; an empty query therefore matches every item. Collection and
    /// attribute indexes are derived in memory from validated metadata. The
    /// first query after a write rebuilds them; nothing changes on disk.
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
        let _read_guard = self.read_guard_checked_after_initial_check(|| {})?;
        let txn = self.db.begin_read()?;
        let items = txn.open_table(ITEMS)?;
        let matches = |metadata: &ItemMeta| {
            collection.is_none_or(|id| metadata.collection == id)
                && attrs
                    .iter()
                    .all(|(name, expected)| metadata.attributes.get(name) == Some(expected))
        };
        if self
            .item_index
            .read()
            .map_err(|_| Error::Config("item lookup index is poisoned".into()))?
            .is_none()
        {
            let mut cache = self
                .item_index
                .write()
                .map_err(|_| Error::Config("item lookup index is poisoned".into()))?;
            if cache.is_none() {
                let mut index = ItemIndex::default();
                let mut out = Vec::new();
                // Validate every authoritative key/record before publishing an
                // index, even when the requested collection or attribute is absent.
                for entry in items.iter()? {
                    let (key, value) = entry?;
                    let metadata = decode_item(key.value(), value.value())?;
                    index.insert(&metadata);
                    if matches(&metadata) {
                        out.push(metadata);
                    }
                }
                *cache = Some(index);
                return Ok(out);
            }
        }
        let cache = self
            .item_index
            .read()
            .map_err(|_| Error::Config("item lookup index is poisoned".into()))?;
        let index = cache
            .as_ref()
            .expect("shared transaction gate prevents invalidation");
        let Some(candidates) = index
            .candidates(collection, attrs)
            .filter(|candidates| candidates.len() < index.ids.len())
        else {
            // A query covering every candidate gains nothing from individual
            // B-tree lookups. Keep sequential traversal for broad queries.
            let mut out = Vec::new();
            for entry in items.iter()? {
                let (key, value) = entry?;
                let metadata = decode_item(key.value(), value.value())?;
                if matches(&metadata) {
                    out.push(metadata);
                }
            }
            return Ok(out);
        };
        let mut out = Vec::new();
        for &position in candidates {
            let id = &index.ids[position];
            let value = items.get(id.as_str())?.ok_or_else(|| {
                Error::Config(format!("item lookup index references missing item {id}"))
            })?;
            let metadata = decode_item(id, value.value())?;
            if matches(&metadata) {
                out.push(metadata);
            }
        }
        Ok(out)
    }
}

/// Derived candidate lists contain positions in the authoritative table's id
/// order. Only ids, collection names and attribute pairs are retained; labels,
/// ciphertext and secret values never enter this index. The Store transaction
/// gate protects its lifetime, and writer admission invalidates it centrally.
#[derive(Debug, Default)]
pub(in crate::store) struct ItemIndex {
    ids: Vec<String>,
    collections: HashMap<String, Vec<usize>>,
    attributes: HashMap<String, HashMap<String, Vec<usize>>>,
}

impl ItemIndex {
    fn insert(&mut self, metadata: &ItemMeta) {
        let position = self.ids.len();
        self.ids.push(metadata.id.clone());
        self.collections
            .entry(metadata.collection.clone())
            .or_default()
            .push(position);
        for (name, value) in &metadata.attributes {
            self.attributes
                .entry(name.clone())
                .or_default()
                .entry(value.clone())
                .or_default()
                .push(position);
        }
    }

    /// Start from the smallest candidate list, then verify all filters against
    /// current redb metadata. Missing keys/values yield an empty candidate list.
    fn candidates(
        &self,
        collection: Option<&str>,
        attrs: &HashMap<String, String>,
    ) -> Option<&[usize]> {
        let mut smallest =
            collection.map(|id| self.collections.get(id).map_or(&[][..], Vec::as_slice));
        for (name, value) in attrs {
            let candidates = self
                .attributes
                .get(name)
                .and_then(|values| values.get(value))
                .map_or(&[][..], Vec::as_slice);
            if smallest.is_none_or(|current| candidates.len() < current.len()) {
                smallest = Some(candidates);
            }
        }
        smallest
    }
}
