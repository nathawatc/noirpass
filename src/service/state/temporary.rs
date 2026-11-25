//! Process-local collection aliases, metadata, and zeroizing secret values.

use std::collections::HashMap;

use zeroize::Zeroizing;

use super::{
    MAX_SESSION_ALIAS_BYTES, MAX_SESSION_ALIASES, MAX_SESSION_ITEMS, MAX_SESSION_STRING_BYTES,
    SESSION_ITEM_ALLOCATION_ATTEMPTS, ServiceState, SessionItem, now_secs, session_item_bytes,
};
use crate::random_hex_id;
use crate::service::{SESSION_COLLECTION_ALIAS, SESSION_COLLECTION_ID, SecretError};
use crate::store::{CollectionMeta, ItemMeta};

impl ServiceState {
    /// Resolve reserved and runtime aliases before persisted aliases.
    pub(crate) fn read_alias(&self, name: &str) -> crate::Result<Option<String>> {
        if self.is_session_alias(name) {
            return Ok(Some(SESSION_COLLECTION_ID.to_string()));
        }
        self.store.read_alias(name)
    }

    pub(crate) fn is_session_alias(&self, name: &str) -> bool {
        name == SESSION_COLLECTION_ALIAS
            || self
                .session_collection
                .lock()
                .expect("session collection lock poisoned")
                .aliases
                .contains(name)
    }

    /// All aliases for temporary items, including the reserved built-in alias.
    pub(crate) fn session_collection_aliases(&self) -> Vec<String> {
        let collection = self
            .session_collection
            .lock()
            .expect("session collection lock poisoned");
        let mut aliases: Vec<_> = collection.aliases.iter().cloned().collect();
        aliases.push(SESSION_COLLECTION_ALIAS.to_string());
        aliases.sort();
        aliases
    }

    /// Replace any persisted target with a bounded, process-local session target.
    /// The caller holds object lifecycle serialization through registration and signals.
    pub(crate) fn set_session_alias(&self, name: &str) -> Result<(), SecretError> {
        {
            let collection = self
                .session_collection
                .lock()
                .expect("session collection lock poisoned");
            if name.len() > MAX_SESSION_ALIAS_BYTES
                || (!collection.aliases.contains(name)
                    && collection.aliases.len() >= MAX_SESSION_ALIASES)
            {
                return Err(SecretError::LimitsExceeded(
                    "temporary collection exceeds alias limits".into(),
                ));
            }
        }
        // Never persist the session target, or leave an old target to reappear after restart.
        // Validate capacity before the Store mutation, release the mutex across the disk commit,
        // and update memory only after a definite commit.
        self.store.set_alias(name, None)?;
        let mut collection = self
            .session_collection
            .lock()
            .expect("session collection lock poisoned");
        if !collection.aliases.contains(name) && collection.aliases.len() >= MAX_SESSION_ALIASES {
            return Err(SecretError::LimitsExceeded(
                "temporary collection exceeds alias limits".into(),
            ));
        }
        collection.aliases.insert(name.to_string());
        Ok(())
    }

    pub(crate) fn remove_session_alias(&self, name: &str) {
        self.session_collection
            .lock()
            .expect("session collection lock poisoned")
            .aliases
            .remove(name);
    }

    /// Metadata for the built-in in-memory session collection.
    pub(crate) fn session_collection_meta(&self) -> CollectionMeta {
        self.session_collection
            .lock()
            .expect("session collection lock poisoned")
            .metadata
            .clone()
    }

    /// Update the session collection label without persisting it.
    pub(crate) fn set_session_collection_label(
        &self,
        label: &str,
    ) -> Result<CollectionMeta, SecretError> {
        if label.len() > MAX_SESSION_STRING_BYTES {
            return Err(SecretError::LimitsExceeded(
                "temporary collection label exceeds size limit".into(),
            ));
        }
        let mut collection = self
            .session_collection
            .lock()
            .expect("session collection lock poisoned");
        collection.metadata.label = label.to_string();
        collection.metadata.modified = now_secs();
        Ok(collection.metadata.clone())
    }

    /// List temporary items in stable id order.
    pub(crate) fn list_session_items(&self) -> Vec<ItemMeta> {
        let collection = self
            .session_collection
            .lock()
            .expect("session collection lock poisoned");
        let mut items: Vec<_> = collection
            .items
            .values()
            .map(|item| item.metadata.clone())
            .collect();
        items.sort_by(|left, right| left.id.cmp(&right.id));
        items
    }

    /// Search temporary items by Secret Service superset attribute semantics.
    pub(crate) fn search_session_items(&self, attrs: &HashMap<String, String>) -> Vec<ItemMeta> {
        let collection = self
            .session_collection
            .lock()
            .expect("session collection lock poisoned");
        let mut items: Vec<_> = collection
            .items
            .values()
            .filter(|item| {
                attrs.iter().all(|(name, expected)| {
                    item.metadata
                        .attributes
                        .get(name)
                        .is_some_and(|actual| actual == expected)
                })
            })
            .map(|item| item.metadata.clone())
            .collect();
        items.sort_by(|left, right| left.id.cmp(&right.id));
        items
    }

    /// Fetch temporary item metadata.
    pub(crate) fn get_session_item(&self, id: &str) -> crate::Result<ItemMeta> {
        self.session_collection
            .lock()
            .expect("session collection lock poisoned")
            .items
            .get(id)
            .map(|item| item.metadata.clone())
            .ok_or_else(|| crate::Error::NotFound(format!("item {id}")))
    }

    /// Fetch temporary item metadata and a zeroizing copy of its secret.
    pub(crate) fn read_session_item_secret(
        &self,
        id: &str,
    ) -> crate::Result<(ItemMeta, Zeroizing<Vec<u8>>)> {
        self.session_collection
            .lock()
            .expect("session collection lock poisoned")
            .items
            .get(id)
            .map(|item| (item.metadata.clone(), item.secret.clone()))
            .ok_or_else(|| crate::Error::NotFound(format!("item {id}")))
    }

    /// Create or replace an exact attribute match in the temporary collection.
    pub(crate) fn create_or_replace_session_item(
        &self,
        label: &str,
        attributes: HashMap<String, String>,
        content_type: &str,
        secret: Zeroizing<Vec<u8>>,
        replace: bool,
    ) -> Result<(ItemMeta, bool), SecretError> {
        let replacement_bytes = session_item_bytes(label, &attributes, content_type, secret.len())?;
        let mut collection = self
            .session_collection
            .lock()
            .expect("session collection lock poisoned");

        let existing_id = if replace {
            collection
                .items
                .values()
                .find(|item| item.metadata.attributes == attributes)
                .map(|item| item.metadata.id.clone())
        } else {
            None
        };

        let previous_bytes = existing_id
            .as_ref()
            .map_or(0, |id| collection.items[id].bytes);
        let retained_bytes = collection.check_capacity(previous_bytes, replacement_bytes)?;
        if existing_id.is_none() && collection.items.len() >= MAX_SESSION_ITEMS {
            return Err(SecretError::LimitsExceeded(
                "temporary collection exceeds item limit".into(),
            ));
        }

        let now = now_secs();
        if let Some(id) = existing_id {
            let metadata = {
                let item = collection.items.get_mut(&id).expect("matched item exists");
                item.metadata.label = label.to_string();
                item.metadata.content_type = content_type.to_string();
                item.metadata.modified = now;
                item.secret = secret;
                item.bytes = replacement_bytes;
                item.metadata.clone()
            };
            collection.retained_bytes = retained_bytes;
            collection.metadata.modified = now;
            return Ok((metadata, true));
        }

        let id = (0..SESSION_ITEM_ALLOCATION_ATTEMPTS)
            .map(|_| random_hex_id())
            .find(|candidate| !collection.items.contains_key(candidate))
            .ok_or_else(|| {
                SecretError::Failed(format!(
                    "could not allocate temporary item id after {SESSION_ITEM_ALLOCATION_ATTEMPTS} attempts"
                ))
            })?;
        let metadata = ItemMeta {
            id: id.clone(),
            collection: SESSION_COLLECTION_ID.to_string(),
            label: label.to_string(),
            attributes,
            content_type: content_type.to_string(),
            ciphertext_sha256: None,
            created: now,
            modified: now,
        };
        collection.items.insert(
            id,
            SessionItem {
                metadata: metadata.clone(),
                secret,
                bytes: replacement_bytes,
            },
        );
        collection.retained_bytes = retained_bytes;
        collection.metadata.modified = now;
        Ok((metadata, false))
    }

    /// Update fields of a temporary item, zeroizing any replaced secret.
    pub(crate) fn update_session_item(
        &self,
        id: &str,
        label: Option<&str>,
        attributes: Option<HashMap<String, String>>,
        content_type: Option<&str>,
        secret: Option<Zeroizing<Vec<u8>>>,
    ) -> Result<ItemMeta, SecretError> {
        let mut collection = self
            .session_collection
            .lock()
            .expect("session collection lock poisoned");
        let item = collection
            .items
            .get(id)
            .ok_or_else(|| SecretError::NoSuchObject(format!("item {id}")))?;
        let replacement_bytes = session_item_bytes(
            label.unwrap_or(&item.metadata.label),
            attributes.as_ref().unwrap_or(&item.metadata.attributes),
            content_type.unwrap_or(&item.metadata.content_type),
            secret
                .as_ref()
                .map_or(item.secret.len(), |secret| secret.len()),
        )?;
        let retained_bytes = collection.check_capacity(item.bytes, replacement_bytes)?;
        let now = now_secs();
        let metadata = {
            let item = collection
                .items
                .get_mut(id)
                .ok_or_else(|| SecretError::NoSuchObject(format!("item {id}")))?;
            if let Some(label) = label {
                item.metadata.label = label.to_string();
            }
            if let Some(attributes) = attributes {
                item.metadata.attributes = attributes;
            }
            if let Some(content_type) = content_type {
                item.metadata.content_type = content_type.to_string();
            }
            if let Some(secret) = secret {
                item.secret = secret;
            }
            item.metadata.modified = now;
            item.bytes = replacement_bytes;
            item.metadata.clone()
        };
        collection.retained_bytes = retained_bytes;
        collection.metadata.modified = now;
        Ok(metadata)
    }

    /// Delete a temporary item; dropping it zeroizes the secret bytes.
    pub(crate) fn delete_session_item(&self, id: &str) -> Result<(), SecretError> {
        let mut collection = self
            .session_collection
            .lock()
            .expect("session collection lock poisoned");
        let previous = collection
            .items
            .get(id)
            .ok_or_else(|| SecretError::NoSuchObject(format!("item {id}")))?
            .bytes;
        let retained_bytes = collection.check_capacity(previous, 0)?;
        collection.items.remove(id);
        collection.retained_bytes = retained_bytes;
        collection.metadata.modified = now_secs();
        Ok(())
    }

    /// Number of temporary secrets currently pinning the daemon to this login session.
    #[must_use]
    #[cfg(test)]
    pub(crate) fn session_secret_count(&self) -> usize {
        self.session_collection
            .lock()
            .expect("session collection lock poisoned")
            .items
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gpg::test_support::TestGnupg;
    use crate::service::state::MAX_SESSION_SECRET_BYTES;
    use crate::service::tests::test_state;

    fn assert_accounting(state: &ServiceState) -> usize {
        let collection = state.session_collection.lock().unwrap();
        let expected: usize = collection
            .items
            .values()
            .map(|item| {
                let bytes = session_item_bytes(
                    &item.metadata.label,
                    &item.metadata.attributes,
                    &item.metadata.content_type,
                    item.secret.len(),
                )
                .unwrap();
                assert_eq!(item.bytes, bytes);
                bytes
            })
            .sum();
        assert_eq!(collection.retained_bytes, expected);
        expected
    }

    #[test]
    fn retained_bytes_follow_mutations_and_rejected_changes() {
        let gnupg = TestGnupg::new();
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(&gnupg, tmp.path());
        assert_eq!(assert_accounting(&state), 0);
        let attrs = HashMap::from([("user".into(), "猫".into())]);
        let (first, _) = state
            .create_or_replace_session_item(
                "first",
                attrs.clone(),
                "text/plain",
                Zeroizing::new(vec![1; 12]),
                false,
            )
            .unwrap();
        assert_accounting(&state);
        let (other, _) = state
            .create_or_replace_session_item(
                "other",
                HashMap::new(),
                "text/plain",
                Zeroizing::new(vec![2; 15]),
                false,
            )
            .unwrap();
        assert_accounting(&state);
        let (replacement, replaced) = state
            .create_or_replace_session_item(
                "replacement",
                attrs,
                "",
                Zeroizing::new(vec![3; 3]),
                true,
            )
            .unwrap();
        assert!(replaced);
        assert_eq!(replacement.id, first.id);
        assert_accounting(&state);
        state
            .update_session_item(
                &first.id,
                Some(""),
                Some(HashMap::new()),
                Some(""),
                Some(Zeroizing::new(Vec::new())),
            )
            .unwrap();
        let before = assert_accounting(&state);
        assert!(
            state
                .update_session_item(
                    &first.id,
                    None,
                    None,
                    None,
                    Some(Zeroizing::new(vec![0; MAX_SESSION_SECRET_BYTES + 1]))
                )
                .is_err()
        );
        assert!(state.delete_session_item("missing").is_err());
        assert_eq!(assert_accounting(&state), before);
        state.delete_session_item(&other.id).unwrap();
        assert_eq!(assert_accounting(&state), 0);
        state.delete_session_item(&first.id).unwrap();
        assert_eq!(assert_accounting(&state), 0);
    }
}
