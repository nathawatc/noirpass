//! Owned-session secret encoding and bounded persistent retrieval.

use std::sync::Arc;

use zbus::fdo;
use zbus::zvariant::OwnedObjectPath;
use zeroize::Zeroizing;

use super::ServiceState;
use crate::crypto::SessionCipher;
use crate::service::session::Secret;
use crate::service::{MAX_BULK_SECRET_BYTES, SESSION_COLLECTION_ID, SecretError, parse_item_path};

impl ServiceState {
    /// Decrypt an incoming [`Secret`] with the transport session cipher.
    pub fn secret_to_plaintext(
        &self,
        secret: &Secret,
        owner: &str,
    ) -> Result<Zeroizing<Vec<u8>>, SecretError> {
        let cipher = self
            .session_cipher(&secret.session, owner)
            .ok_or_else(|| SecretError::NoSession(format!("no session {}", secret.session)))?;
        if matches!(cipher.as_ref(), SessionCipher::Plain) && !secret.parameters.is_empty() {
            return Err(
                fdo::Error::InvalidArgs("plain Secret parameters must be empty".into()).into(),
            );
        }
        Ok(cipher.decrypt(&secret.parameters, &secret.value)?)
    }

    /// Encrypt already-authorized zeroizing plaintext off the executor, before lifecycle locking.
    pub(crate) async fn encrypt_secret(
        self: &Arc<Self>,
        plaintext: Zeroizing<Vec<u8>>,
    ) -> Result<Vec<u8>, SecretError> {
        self.blocking(None, move |state| Ok(state.gpg.encrypt(&plaintext)?))
            .await
    }

    /// Encode plaintext for transport under an owned Secret Service session.
    pub fn plaintext_to_secret(
        &self,
        session: &OwnedObjectPath,
        plaintext: &[u8],
        content_type: &str,
        owner: &str,
    ) -> Result<Secret, SecretError> {
        let cipher = self
            .session_cipher(session, owner)
            .ok_or_else(|| SecretError::NoSession(format!("no session {session}")))?;
        let (parameters, value) = cipher.encrypt(plaintext);
        Ok(Secret {
            session: session.clone(),
            parameters,
            value,
            content_type: content_type.to_string(),
        })
    }

    /// Keep ciphertext, plaintext, and transport encoding within one worker reservation.
    pub(crate) async fn persistent_secret(
        self: &Arc<Self>,
        collection: &str,
        item: &str,
        session: &OwnedObjectPath,
        owner: &str,
        maximum: Option<usize>,
    ) -> Result<Secret, SecretError> {
        if self.session_cipher(session, owner).is_none() {
            return Err(SecretError::NoSession(format!("no session {session}")));
        }
        let collection = collection.to_owned();
        let item = item.to_owned();
        let session = session.clone();
        let owner = owner.to_owned();
        self.blocking(None, move |state| {
            if state.session_cipher(&session, &owner).is_none() {
                return Err(SecretError::NoSession(format!("no session {session}")));
            }
            let (meta, ciphertext) = state.store().read_item_secret(&item)?;
            if meta.collection != collection {
                return Err(SecretError::NoSuchObject(format!(
                    "no item {item} in collection {collection}"
                )));
            }
            // The session can close during the filesystem read.
            if state.session_cipher(&session, &owner).is_none() {
                return Err(SecretError::NoSession(format!("no session {session}")));
            }
            let plaintext = state.gpg.decrypt_blocking(&ciphertext)?;
            if maximum.is_some_and(|maximum| plaintext.len() > maximum) {
                return Err(SecretError::LimitsExceeded(
                    "bulk secret response exceeds 8 MiB; request individual secrets".into(),
                ));
            }
            state.plaintext_to_secret(&session, &plaintext, &meta.content_type, &owner)
        })
        .await
    }

    /// Resolve one bulk-request path; missing and mismatched items are skipped.
    pub(crate) async fn secret_for_item_path(
        self: &Arc<Self>,
        path: &OwnedObjectPath,
        session: &OwnedObjectPath,
        owner: &str,
    ) -> Result<Option<Secret>, SecretError> {
        if self.session_cipher(session, owner).is_none() {
            return Err(SecretError::NoSession(format!("no session {session}")));
        }
        let Some((collection_id, item_id)) = parse_item_path(path.as_str()) else {
            return Ok(None);
        };
        if collection_id == SESSION_COLLECTION_ID {
            let (meta, plaintext) = match self.read_session_item_secret(&item_id) {
                Ok(item) => item,
                Err(crate::Error::NotFound(_)) => return Ok(None),
                Err(err) => return Err(err.into()),
            };
            return self
                .plaintext_to_secret(session, &plaintext, &meta.content_type, owner)
                .map(Some);
        }
        match self
            .persistent_secret(
                &collection_id,
                &item_id,
                session,
                owner,
                Some(MAX_BULK_SECRET_BYTES),
            )
            .await
        {
            Ok(secret) => Ok(Some(secret)),
            Err(SecretError::NoSuchObject(_)) => Ok(None),
            Err(err) => Err(err),
        }
    }
}
