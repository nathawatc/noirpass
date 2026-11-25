//! Ordered bulk retrieval with bounded concurrency and encoded response size.

use std::collections::HashMap;
use std::sync::Arc;

use zbus::OwnedObjectPath;
use zbus::fdo;

use super::session::Secret;
use super::state::{MAX_BLOCKING_WORKERS, RequestGuard};
use super::{SecretError, ServiceState};

pub(super) const MAX_BULK_SECRET_BYTES: usize = 8 * 1024 * 1024;

// Count each dictionary entry with its trailing eight-byte alignment padding.
// This slightly overestimates the wire size without copying secret bytes.
pub(super) fn secret_entry_bytes(
    path: &OwnedObjectPath,
    secret: &Secret,
) -> Result<usize, SecretError> {
    let size = zbus::wire::serialized_size(
        zbus::wire::serialized::Context::new(zbus::wire::LE, 0),
        &(path, secret),
    )
    .map_err(|err| SecretError::Failed(err.to_string()))?
    .size();
    size.checked_add(7)
        .map(|size| size & !7)
        .ok_or_else(|| SecretError::LimitsExceeded("bulk secret response is too large".into()))
}

pub(super) fn insert_bulk_secret(
    out: &mut HashMap<OwnedObjectPath, Secret>,
    retained_bytes: &mut usize,
    path: OwnedObjectPath,
    secret: Secret,
) -> Result<(), SecretError> {
    let previous = out
        .get(&path)
        .map(|secret| secret_entry_bytes(&path, secret))
        .transpose()?
        .unwrap_or(0);
    let next = (*retained_bytes - previous)
        .checked_add(secret_entry_bytes(&path, &secret)?)
        .filter(|size| *size <= MAX_BULK_SECRET_BYTES)
        .ok_or_else(|| {
            SecretError::LimitsExceeded(
                "bulk secret response exceeds 8 MiB; request fewer items".into(),
            )
        })?;
    out.insert(path, secret);
    *retained_bytes = next;
    Ok(())
}

pub(super) async fn get_secrets(
    state: &Arc<ServiceState>,
    request: &Arc<RequestGuard>,
    items: &[OwnedObjectPath],
    session: &OwnedObjectPath,
    owner: &str,
) -> Result<HashMap<OwnedObjectPath, Secret>, SecretError> {
    if state.session_cipher(session, owner).is_none() {
        return Err(SecretError::NoSession(format!("no session {session}")));
    }

    let mut out = HashMap::new();
    // Dictionary array length plus padding before its first entry.
    let mut retained_bytes = 8;
    // Four in-flight items per request; the shared worker pool also bounds all callers.
    // Drain each batch in input order so repeated paths retain their last result.
    for batch in items.chunks(MAX_BLOCKING_WORKERS) {
        let mut tasks = tokio::task::JoinSet::new();
        for (index, path) in batch.iter().cloned().enumerate() {
            let state = state.clone();
            let session = session.clone();
            let owner = owner.to_owned();
            let request = request.clone();
            tasks.spawn(request.run(async move {
                let result = state
                    .secret_for_item_path(&path, &session, &owner)
                    .await
                    .map(|secret| secret.map(|secret| (path, secret)));
                (index, result)
            }));
        }
        let mut results = Vec::with_capacity(batch.len());
        while let Some(result) = tasks.join_next().await {
            results.push(
                result.map_err(|_| fdo::Error::Failed("secret retrieval task failed".into()))?,
            );
        }
        results.sort_by_key(|(index, _)| *index);
        for (_, result) in results {
            if let Some((path, secret)) = result? {
                insert_bulk_secret(&mut out, &mut retained_bytes, path, secret)?;
            }
        }
    }
    Ok(out)
}
