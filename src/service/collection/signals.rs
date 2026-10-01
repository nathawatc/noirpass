//! Collection property notifications across canonical and alias object paths.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use zbus::fdo;
use zbus::names::InterfaceName;
use zbus::object_server::{ObjectServer, SignalEmitter};
use zbus::zvariant::{OwnedObjectPath, Value};

use super::{COLLECTION_INTERFACE, Collection};
use crate::service::state::MutationGuard;
use crate::service::{
    SERVICE_PATH, SESSION_COLLECTION_ID, Service, ServiceState, alias_path, collection_path,
    item_path,
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

/// Emit Label and Modified for every served path representing `id`.
pub(crate) async fn emit_collection_label_modified(
    state: &ServiceState,
    server: &ObjectServer,
    connection: &zbus::Connection,
    id: &str,
) -> fdo::Result<()> {
    for path in collection_object_paths_for_id(state, id)? {
        let collection_ref = server.interface::<_, Collection>(&path).await?;
        let collection = collection_ref.get().await;
        let emitter = SignalEmitter::new(connection, path)?;
        collection.emit_label_changed(&emitter).await?;
        collection.modified_changed(&emitter).await?;
    }
    Ok(())
}

/// Emit Items using the mutation's existing worker reservation. Calling the
/// generated property getter here could wait forever when all worker slots are
/// held by mutations that have reached publication.
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
            .await
            .map_err(|err| fdo::Error::Failed(err.to_string()))?
    };
    for path in paths {
        // Preserve failure when a required collection interface is missing.
        let _collection_ref = server.interface::<_, Collection>(&path).await?;
        let emitter = SignalEmitter::new(connection, path)?;
        fdo::Properties::properties_changed(
            &emitter,
            InterfaceName::from_static_str_unchecked(COLLECTION_INTERFACE),
            HashMap::from([("Items", Value::from(items.as_slice()))]),
            Cow::Borrowed(&[]),
        )
        .await?;
    }
    Ok(())
}

/// Notify clients when an item mutation modifies its parent collection.
pub(crate) async fn emit_collection_modified(
    state: &Arc<ServiceState>,
    connection: &zbus::Connection,
    id: &str,
    lifecycle: Arc<MutationGuard>,
) -> fdo::Result<()> {
    let (modified, paths) = if id == SESSION_COLLECTION_ID {
        (
            state.session_collection_meta().modified,
            collection_object_paths_for_id(state, id)?,
        )
    } else {
        let id = id.to_owned();
        state
            .blocking(Some(lifecycle), move |state| {
                Ok((
                    state.store().get_collection(&id)?.modified,
                    collection_object_paths_for_id(state, &id)?,
                ))
            })
            .await
            .map_err(|err| fdo::Error::Failed(err.to_string()))?
    };
    for path in paths {
        let emitter = SignalEmitter::new(connection, path)?;
        fdo::Properties::properties_changed(
            &emitter,
            InterfaceName::from_static_str_unchecked(COLLECTION_INTERFACE),
            HashMap::from([("Modified", Value::from(modified))]),
            Cow::Borrowed(&[]),
        )
        .await?;
    }
    let emitter = SignalEmitter::new(connection, SERVICE_PATH)?;
    Service::collection_changed(&emitter, collection_path(id)).await?;
    Ok(())
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
