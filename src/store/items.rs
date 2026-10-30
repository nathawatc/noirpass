//! Item metadata and ciphertext persistence operations.

mod read;

pub(super) use read::ItemIndex;

use std::collections::HashMap;
use std::path::Path;

use redb::ReadableTable;

use crate::error::{Error, Result};

use super::{
    COLLECTIONS, CollectionMeta, ITEMS, ItemMeta, PersistError, Store, StoreTransaction,
    StoreWriteGuard, ciphertext_sha256, decode_item, definite, is_valid_collection_id, now_secs,
    random_id,
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
        let (mut mutation_guard, txn) = self.begin_write_checked()?;
        Self::validate_collection_in_txn(&txn, collection)?;
        let metadata = self.create_item_locked(
            txn,
            collection,
            label,
            attributes,
            content_type,
            secret_ciphertext,
        )?;
        if let Some(index) = mutation_guard.index.as_mut() {
            index.insert(&metadata);
        }
        mutation_guard.preserve_index();
        Ok(metadata)
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
        let (mut mutation_guard, txn) =
            self.begin_write_checked_after_initial_check(after_initial_check)?;
        Self::validate_collection_in_txn(&txn, collection)?;
        let existing = if replace {
            Self::find_item_by_attrs_exact_locked(
                &txn,
                mutation_guard.index.as_ref(),
                collection,
                &attributes,
            )?
        } else {
            None
        };
        let result = match existing {
            Some(metadata) => self
                .update_item_locked(
                    &mut mutation_guard,
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
        }?;
        if !result.1
            && let Some(index) = mutation_guard.index.as_mut()
        {
            index.insert(&result.0);
        }
        mutation_guard.preserve_index();
        Ok(result)
    }

    fn touch_item_collection(
        txn: &redb::WriteTransaction,
        collection: &str,
        modified: u64,
    ) -> Result<()> {
        let mut collections = txn.open_table(COLLECTIONS)?;
        let metadata = collections
            .get(collection)?
            .and_then(|value| serde_json::from_slice::<CollectionMeta>(value.value()).ok());
        // Integrity repair may remove items with missing or corrupt parents.
        // Update only an existing, valid parent; preserve invalid metadata for repair.
        if let Some(mut metadata) = metadata
            && metadata.id == collection
            && is_valid_collection_id(collection)
        {
            metadata.modified = modified;
            let bytes = serde_json::to_vec(&metadata)?;
            collections.insert(collection, bytes.as_slice())?;
        }
        Ok(())
    }

    fn remove_item_metadata_locked(txn: &redb::WriteTransaction, id: &str) -> Result<()> {
        let collection = {
            let mut items = txn.open_table(ITEMS)?;
            let value = items
                .remove(id)?
                .ok_or_else(|| Error::NotFound(format!("item {id}")))?;
            decode_item(id, value.value())
                .ok()
                .map(|meta| meta.collection)
        };
        if let Some(collection) = collection {
            Self::touch_item_collection(txn, &collection, now_secs())?;
        }
        Ok(())
    }

    fn find_item_by_attrs_exact_locked(
        txn: &redb::WriteTransaction,
        index: Option<&ItemIndex>,
        collection: &str,
        attrs: &HashMap<String, String>,
    ) -> Result<Option<ItemMeta>> {
        let items = txn.open_table(ITEMS)?;
        if let Some(candidates) = index.and_then(|index| index.candidates(Some(collection), attrs))
        {
            for id in candidates {
                let value = items.get(id.as_str())?.ok_or_else(|| {
                    Error::Config(format!("item lookup index references missing item {id}"))
                })?;
                let metadata = decode_item(id, value.value())?;
                if metadata.collection == collection && &metadata.attributes == attrs {
                    return Ok(Some(metadata));
                }
            }
            return Ok(None);
        }
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
        txn: StoreTransaction<'_>,
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
            Self::touch_item_collection(&txn, collection, meta.modified).map_err(definite)?;
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
        let (mut mutation_guard, txn) = self.begin_write_checked()?;
        let metadata = self.update_item_locked(
            &mut mutation_guard,
            txn,
            id,
            label,
            attributes,
            content_type,
            secret_ciphertext,
        )?;
        mutation_guard.preserve_index();
        Ok(metadata)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the write guard owns post-commit lookup updates"
    )]
    fn update_item_locked(
        &self,
        mutation_guard: &mut StoreWriteGuard<'_>,
        txn: StoreTransaction<'_>,
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
        let previous = meta.clone();
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
            Self::touch_item_collection(&txn, &meta.collection, meta.modified).map_err(definite)?;
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
        if let Some(index) = mutation_guard.index.as_mut()
            && previous.attributes != meta.attributes
        {
            index.remove(&previous);
            index.insert(&meta);
        }
        Ok(meta)
    }

    /// Delete an item and its secret file. Returns [`Error::NotFound`] if the
    /// item does not exist.
    pub fn delete_item(&self, id: &str) -> Result<()> {
        let path = self.secret_path(id)?;
        let (mut mutation_guard, txn) = self.begin_write_checked()?;
        let previous = {
            let items = txn.open_table(ITEMS)?;
            let value = items
                .get(id)?
                .ok_or_else(|| Error::NotFound(format!("item {id}")))?;
            // Integrity repair also deletes malformed records. A warm index can
            // only contain validated metadata; otherwise leave it invalidated.
            decode_item(id, value.value()).ok()
        };
        let commit = || -> std::result::Result<(), PersistError> {
            Self::remove_item_metadata_locked(&txn, id).map_err(definite)?;
            txn.commit()
                .map_err(|err| PersistError::Indeterminate(err.into()))
        };
        self.quarantine_then_commit(&path, commit)?;
        if let Some(previous) = previous {
            if let Some(index) = mutation_guard.index.as_mut() {
                index.remove(&previous);
            }
            mutation_guard.preserve_index();
        }
        Ok(())
    }

    /// Delete only an item metadata record using its authoritative redb key.
    ///
    /// Used by integrity repair for noncanonical keys that must never become
    /// filesystem paths.
    pub fn delete_item_metadata(&self, table_key: &str) -> Result<()> {
        let (_mutation_guard, txn) = self.begin_write_checked()?;
        Self::remove_item_metadata_locked(&txn, table_key)?;
        self.finish_metadata_commit(txn.commit())?;
        Ok(())
    }
}
