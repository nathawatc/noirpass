//! Collection property notifications across canonical and alias object paths.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use zbus::fdo;
use zbus::names::InterfaceName;
use zbus::object_server::{ObjectServer, SignalEmitter};
use zbus::{OwnedObjectPath, Variant};

use super::Collection;
use crate::service::state::MutationGuard;
use crate::service::{
    COLLECTION_INTERFACE, SERVICE_PATH, SESSION_COLLECTION_ID, Service, ServiceState, alias_path,
    collection_path, emit_property_changed, item_path,
};

/// Return the canonical path and every valid persisted alias path for `id`.
fn collection_object_paths_for_id(
    state: &ServiceState,
    id: &str,
) -> fdo::Result<Vec<OwnedObjectPath>> {
    let mut paths = vec![collection_path(id)];
    if id == SESSION_COLLECTION_ID {
        for name in state.session_collection_aliases() {
            if let Ok(path) = alias_path(&name) {
                paths.push(path);
            }
        }
        return Ok(paths);
    }
    for (name, target) in state.store().list_aliases().map_err(fdo::Error::from)? {
        if !state.is_session_alias(&name)
            && target == id
            && let Ok(path) = alias_path(&name)
        {
            paths.push(path);
        }
    }
    Ok(paths)
}

async fn resolve_collection_paths(
    state: &Arc<ServiceState>,
    id: &str,
    lifecycle: Arc<MutationGuard>,
) -> fdo::Result<Vec<OwnedObjectPath>> {
    if id == SESSION_COLLECTION_ID {
        return collection_object_paths_for_id(state, id);
    }
    let id = id.to_owned();
    Ok(state
        .blocking(Some(lifecycle), move |state| {
            Ok(collection_object_paths_for_id(state, &id)?)
        })
        .await?)
}

/// Emit Label and Modified for every served path representing `id` from already-updated metadata.
pub(crate) async fn emit_collection_label_modified(
    state: &Arc<ServiceState>,
    server: &ObjectServer,
    connection: &zbus::Connection,
    id: &str,
    label: &str,
    modified: u64,
    lifecycle: Arc<MutationGuard>,
) -> fdo::Result<()> {
    for path in resolve_collection_paths(state, id, lifecycle).await? {
        // Preserve failure when a required collection interface is missing.
        let _collection_ref = server.interface::<_, Collection>(&path).await?;
        let emitter = SignalEmitter::new(connection, path)?;
        emit_property_changed(
            &emitter,
            COLLECTION_INTERFACE,
            "Label",
            Variant::from(label),
        )
        .await?;
        emit_property_changed(
            &emitter,
            COLLECTION_INTERFACE,
            "Modified",
            Variant::from(modified),
        )
        .await?;
    }
    Ok(())
}

/// Emit Items using the mutation's existing worker reservation. Calling the
/// generated property getter here could wait forever when all worker slots are
/// held by mutations that have reached publication.
#[cfg(test)]
pub(crate) async fn emit_collection_items_changed(
    state: &Arc<ServiceState>,
    server: &ObjectServer,
    connection: &zbus::Connection,
    id: &str,
    lifecycle: Arc<MutationGuard>,
) -> fdo::Result<()> {
    let (items, paths) = if id == SESSION_COLLECTION_ID {
        (
            state
                .list_session_items()
                .into_iter()
                .map(|meta| item_path(&meta.collection, &meta.id))
                .collect::<Vec<_>>(),
            collection_object_paths_for_id(state, id)?,
        )
    } else {
        let id = id.to_owned();
        state
            .blocking(Some(lifecycle), move |state| {
                Ok((
                    state
                        .store()
                        .list_items(&id)?
                        .into_iter()
                        .map(|meta| item_path(&meta.collection, &meta.id))
                        .collect::<Vec<_>>(),
                    collection_object_paths_for_id(state, &id)?,
                ))
            })
            .await?
    };
    emit_items_to_paths(server, connection, &paths, &items).await
}

async fn emit_items_to_paths(
    server: &ObjectServer,
    connection: &zbus::Connection,
    paths: &[OwnedObjectPath],
    items: &[OwnedObjectPath],
) -> fdo::Result<()> {
    for path in paths {
        // Preserve failure when a required collection interface is missing.
        let _collection_ref = server.interface::<_, Collection>(path).await?;
        let emitter = SignalEmitter::new(connection, path.clone())?;
        emit_property_changed(
            &emitter,
            COLLECTION_INTERFACE,
            "Items",
            Variant::from(items),
        )
        .await?;
    }
    Ok(())
}

async fn emit_modified_to_paths(
    connection: &zbus::Connection,
    id: &str,
    paths: &[OwnedObjectPath],
    modified: u64,
) -> fdo::Result<()> {
    for path in paths {
        let emitter = SignalEmitter::new(connection, path.clone())?;
        emit_property_changed(
            &emitter,
            COLLECTION_INTERFACE,
            "Modified",
            Variant::from(modified),
        )
        .await?;
    }
    let emitter = SignalEmitter::new(connection, SERVICE_PATH)?;
    Service::collection_changed(&emitter, collection_path(id)).await?;
    Ok(())
}

/// Emit Items, Modified, and `CollectionChanged` using a single blocking store read.
pub(crate) async fn emit_collection_items_and_modified(
    state: &Arc<ServiceState>,
    server: &ObjectServer,
    connection: &zbus::Connection,
    id: &str,
    lifecycle: Arc<MutationGuard>,
) -> fdo::Result<()> {
    let (items, modified, paths) = if id == SESSION_COLLECTION_ID {
        (
            state
                .list_session_items()
                .into_iter()
                .map(|meta| item_path(&meta.collection, &meta.id))
                .collect::<Vec<_>>(),
            state.session_collection_meta().modified,
            collection_object_paths_for_id(state, id)?,
        )
    } else {
        let id = id.to_owned();
        state
            .blocking(Some(lifecycle), move |state| {
                Ok((
                    state
                        .store()
                        .list_items(&id)?
                        .into_iter()
                        .map(|meta| item_path(&meta.collection, &meta.id))
                        .collect::<Vec<_>>(),
                    state.store().get_collection(&id)?.modified,
                    collection_object_paths_for_id(state, &id)?,
                ))
            })
            .await?
    };
    emit_items_to_paths(server, connection, &paths, &items).await?;
    emit_modified_to_paths(connection, id, &paths, modified).await
}

/// Notify clients when an item mutation modifies its parent collection.
pub(crate) async fn emit_collection_modified(
    state: &Arc<ServiceState>,
    connection: &zbus::Connection,
    id: &str,
    modified: u64,
    lifecycle: Arc<MutationGuard>,
) -> fdo::Result<()> {
    let paths = resolve_collection_paths(state, id, lifecycle).await?;
    emit_modified_to_paths(connection, id, &paths, modified).await
}

/// Invalidate alias properties that resolve through its persisted target.
pub(crate) async fn emit_alias_target_invalidated(
    connection: &zbus::Connection,
    name: &str,
) -> fdo::Result<()> {
    let Ok(path) = alias_path(name) else {
        return Ok(());
    };
    let emitter = SignalEmitter::new(connection, path)?;
    fdo::Properties::properties_changed(
        &emitter,
        InterfaceName::from_static_str_unchecked(COLLECTION_INTERFACE),
        HashMap::new(),
        Cow::Borrowed(&["Items", "Label", "Created", "Modified"]),
    )
    .await?;
    Ok(())
}
