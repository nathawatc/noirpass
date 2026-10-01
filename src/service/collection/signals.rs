//! Collection property notifications across canonical and alias object paths.

use std::borrow::Cow;
use std::collections::HashMap;

use zbus::fdo;
use zbus::names::InterfaceName;
use zbus::object_server::{ObjectServer, SignalEmitter};
use zbus::zvariant::{OwnedObjectPath, Value};

use super::{COLLECTION_INTERFACE, Collection};
use crate::service::{
    SERVICE_PATH, SESSION_COLLECTION_ID, Service, ServiceState, alias_path, collection_path,
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

/// Emit Items for every served path representing `id`.
pub(crate) async fn emit_collection_items_changed(
    state: &ServiceState,
    server: &ObjectServer,
    connection: &zbus::Connection,
    id: &str,
) -> fdo::Result<()> {
    for path in collection_object_paths_for_id(state, id)? {
        let collection_ref = server.interface::<_, Collection>(&path).await?;
        let collection = collection_ref.get().await;
        let emitter = SignalEmitter::new(connection, path)?;
        collection.items_changed(&emitter).await?;
    }
    Ok(())
}

/// Notify clients when an item mutation modifies the temporary collection.
pub(crate) async fn emit_session_collection_modified(
    state: &ServiceState,
    connection: &zbus::Connection,
    id: &str,
) -> fdo::Result<()> {
    if id != SESSION_COLLECTION_ID {
        return Ok(());
    }
    let modified = state.session_collection_meta().modified;
    for path in collection_object_paths_for_id(state, id)? {
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
