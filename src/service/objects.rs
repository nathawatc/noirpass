//! D-Bus object paths and object-server registration.

use std::future::Future;
use std::sync::Arc;

use zbus::fdo;
use zbus::object_server::ObjectServer;
use zbus::zvariant::OwnedObjectPath;

use super::ServiceState;
use crate::crypto::SessionCipher;
use crate::service::session::Session;

/// Path of the service object.
pub const SERVICE_PATH: &str = "/org/freedesktop/secrets";

/// The DH session algorithm identifier from the Secret Service spec.
pub const ALGORITHM_DH: &str = "dh-ietf1024-sha256-aes128-cbc-pkcs7";

/// The plain (no transport encryption) session algorithm identifier.
pub const ALGORITHM_PLAIN: &str = "plain";

/// Built-in temporary collection id and well-known alias used by libsecret.
pub const SESSION_COLLECTION_ID: &str = "session";
pub const SESSION_COLLECTION_ALIAS: &str = "session";

// --- path helpers ---------------------------------------------------------

/// The "no object" path used for prompt-less returns and unset aliases.
pub(super) fn root_path() -> OwnedObjectPath {
    OwnedObjectPath::try_from("/").expect("/ is a valid object path")
}

/// D-Bus path of a collection. Collection ids are hex strings, `default`, or
/// the built-in `session` id; all are valid path elements.
#[must_use]
pub fn collection_path(collection_id: &str) -> OwnedObjectPath {
    OwnedObjectPath::try_from(format!("{SERVICE_PATH}/collection/{collection_id}"))
        .expect("collection ids are valid path elements")
}

/// D-Bus path of an item inside a collection.
#[must_use]
pub fn item_path(collection_id: &str, item_id: &str) -> OwnedObjectPath {
    OwnedObjectPath::try_from(format!(
        "{SERVICE_PATH}/collection/{collection_id}/{item_id}"
    ))
    .expect("ids are valid path elements")
}

/// D-Bus path of session number `n`.
#[must_use]
pub fn session_path(n: u128) -> OwnedObjectPath {
    OwnedObjectPath::try_from(format!("{SERVICE_PATH}/session/s{n}"))
        .expect("session numbers are valid path elements")
}

/// D-Bus alias path (`.../aliases/<name>`), per the Secret Service spec.
///
/// Fails for alias names that are not valid path elements; such aliases are
/// still stored and resolvable through `ReadAlias`, they just get no object.
pub fn alias_path(name: &str) -> zbus::Result<OwnedObjectPath> {
    Ok(OwnedObjectPath::try_from(format!(
        "{SERVICE_PATH}/aliases/{name}"
    ))?)
}

/// Extract the collection id from a collection path, if it is one.
#[must_use]
pub fn parse_collection_path(path: &str) -> Option<String> {
    let rest = path.strip_prefix("/org/freedesktop/secrets/collection/")?;
    if rest.is_empty() || rest.contains('/') {
        return None;
    }
    Some(rest.to_string())
}

/// Extract `(collection_id, item_id)` from an item path, if it is one.
#[must_use]
pub fn parse_item_path(path: &str) -> Option<(String, String)> {
    let rest = path.strip_prefix("/org/freedesktop/secrets/collection/")?;
    let (collection, item) = rest.split_once('/')?;
    if collection.is_empty() || item.is_empty() || item.contains('/') {
        return None;
    }
    Some((collection.to_string(), item.to_string()))
}

// --- object registration -----------------------------------------------------

pub(super) async fn register_session_object_with<F>(
    server: &ObjectServer,
    state: &Arc<ServiceState>,
    cipher: SessionCipher,
    owner: String,
    next_id: F,
) -> fdo::Result<OwnedObjectPath>
where
    F: FnMut() -> u128,
{
    // Reserve map state before exposing the D-Bus object. Never hold the
    // synchronous session mutex across ObjectServer::at().
    let path = state.register_session_with(cipher, owner.clone(), next_id)?;
    match server
        .at(&path, Session::new(state.clone(), path.clone()))
        .await
    {
        Ok(true) if state.session_cipher(&path, &owner).is_some() => Ok(path),
        Ok(true) => {
            // Owner disconnected while ObjectServer::at() yielded.
            let _ = server.remove::<Session, _>(&path).await;
            Err(fdo::Error::Failed(
                "session owner disconnected during registration".into(),
            ))
        }
        Ok(false) => {
            state.remove_session(&path, &owner);
            Err(fdo::Error::Failed(format!(
                "session object path {path} is already registered"
            )))
        }
        Err(err) => {
            state.remove_session(&path, &owner);
            // ObjectServer::at() can add the interface before a later signal
            // emission fails. Best-effort removal restores both registries.
            let _ = server.remove::<Session, _>(&path).await;
            Err(err.into())
        }
    }
}

/// Reject a session if its unique owner vanished before or during registration.
pub(super) async fn validate_session_owner(
    server: &ObjectServer,
    state: &Arc<ServiceState>,
    path: &OwnedObjectPath,
    owner: &str,
    owner_present: impl Future<Output = fdo::Result<bool>>,
) -> fdo::Result<()> {
    let result = owner_present.await;
    if matches!(result, Ok(true)) {
        return Ok(());
    }
    // A vanished-owner notification may have been processed before map insertion.
    // Fail closed and remove both registries even if the presence query itself fails.
    state.remove_session(path, owner);
    object_removed_or_absent(server.remove::<Session, _>(path).await)?;
    match result {
        Ok(_) => Err(fdo::Error::AccessDenied(
            "session owner disconnected during registration".into(),
        )),
        Err(err) => Err(err),
    }
}

/// Serve a [`crate::service::collection::Collection`] object for `collection_id`.
pub async fn register_collection(
    server: &ObjectServer,
    state: &Arc<ServiceState>,
    collection_id: &str,
) -> zbus::Result<OwnedObjectPath> {
    let path = collection_path(collection_id);
    server
        .at(
            &path,
            crate::service::collection::Collection::new(state.clone(), collection_id.to_string()),
        )
        .await?;
    Ok(path)
}

/// Serve a [`crate::service::item::Item`] object for `item_id` in `collection_id`.
pub async fn register_item(
    server: &ObjectServer,
    state: &Arc<ServiceState>,
    collection_id: &str,
    item_id: &str,
) -> zbus::Result<OwnedObjectPath> {
    let path = item_path(collection_id, item_id);
    server
        .at(
            &path,
            crate::service::item::Item::new(
                state.clone(),
                collection_id.to_string(),
                item_id.to_string(),
            ),
        )
        .await?;
    Ok(path)
}

/// Serve a [`crate::service::collection::Collection`] object at the alias path
/// `/org/freedesktop/secrets/aliases/<name>` that resolves `name` at call
/// time. Alias names that are not valid path elements are skipped.
pub async fn register_alias(
    server: &ObjectServer,
    state: &Arc<ServiceState>,
    name: &str,
) -> zbus::Result<()> {
    if let Ok(path) = alias_path(name) {
        server
            .at(
                &path,
                crate::service::collection::Collection::for_alias(state.clone(), name.to_string()),
            )
            .await?;
    }
    Ok(())
}

/// Treat an `ObjectServer` interface as successfully removed when already absent.
pub(crate) fn object_removed_or_absent(result: zbus::Result<bool>) -> zbus::Result<()> {
    match result {
        Ok(_) | Err(zbus::Error::InterfaceNotFound) => Ok(()),
        Err(err) => Err(err),
    }
}

/// Remove the alias object at `/org/freedesktop/secrets/aliases/<name>`,
/// if it exists.
pub async fn unregister_alias(server: &ObjectServer, name: &str) -> zbus::Result<()> {
    if name == SESSION_COLLECTION_ALIAS {
        return Ok(());
    }
    if let Ok(path) = alias_path(name) {
        object_removed_or_absent(
            server
                .remove::<crate::service::collection::Collection, _>(&path)
                .await,
        )?;
    }
    Ok(())
}

/// Serve objects for every collection, item and alias already in the store.
///
/// Called once at startup, after the service object itself is up but before
/// the well-known name is requested.
pub async fn register_existing(
    server: &ObjectServer,
    state: &Arc<ServiceState>,
) -> zbus::Result<()> {
    // The libsecret session collection is process-memory-only and always
    // exists for the lifetime of this daemon. Register it before persistent
    // objects so the reserved alias can never resolve to legacy store data.
    register_collection(server, state, SESSION_COLLECTION_ID).await?;
    register_alias(server, state, SESSION_COLLECTION_ALIAS).await?;

    let collections = state
        .store()
        .list_collections()
        .map_err(|e| zbus::Error::FDO(Box::new(e.into())))?;
    for collection in collections {
        register_collection(server, state, &collection.id).await?;
        let items = state
            .store()
            .list_items(&collection.id)
            .map_err(|e| zbus::Error::FDO(Box::new(e.into())))?;
        for item in items {
            register_item(server, state, &collection.id, &item.id).await?;
        }
    }
    let aliases = state
        .store()
        .list_aliases()
        .map_err(|e| zbus::Error::FDO(Box::new(e.into())))?;
    for (name, _) in aliases {
        if name != SESSION_COLLECTION_ALIAS {
            register_alias(server, state, &name).await?;
        }
    }
    Ok(())
}
