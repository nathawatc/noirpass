//! Ciphertext persistence entry points.

use crate::error::{Error, Result};

use super::{ItemMeta, Store, ciphertext_sha256};

impl Store {
    /// Read item metadata and ciphertext under one shared transaction guard.
    pub fn read_item_secret(&self, id: &str) -> Result<(ItemMeta, Vec<u8>)> {
        self.read_item_secret_after_initial_check(id, || {})
    }

    pub(super) fn read_item_secret_after_initial_check(
        &self,
        id: &str,
        after_initial_check: impl FnOnce(),
    ) -> Result<(ItemMeta, Vec<u8>)> {
        let _read_guard = self.read_guard_checked_after_initial_check(after_initial_check)?;
        let metadata = self.get_item(id)?;
        let ciphertext = self.read_secret_file_unlocked(id)?;
        if let Some(expected_hash) = &metadata.ciphertext_sha256
            && ciphertext_sha256(&ciphertext) != *expected_hash
        {
            return Err(Error::Config(format!(
                "ciphertext digest does not match metadata for item {id}"
            )));
        }
        Ok((metadata, ciphertext))
    }

    /// Read the raw ciphertext of item `id`'s secret file.
    #[cfg(test)]
    pub(super) fn read_secret_file(&self, id: &str) -> Result<Vec<u8>> {
        self.read_secret_file_after_initial_check(id, || {})
    }

    #[cfg(test)]
    pub(super) fn read_secret_file_after_initial_check(
        &self,
        id: &str,
        after_initial_check: impl FnOnce(),
    ) -> Result<Vec<u8>> {
        let _read_guard = self.read_guard_checked_after_initial_check(after_initial_check)?;
        self.read_secret_file_unlocked(id)
    }
}
