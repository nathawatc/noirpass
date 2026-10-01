use std::collections::HashMap;
use std::time::Duration;

use zbus::zvariant::{OwnedObjectPath, OwnedValue};

use super::super::{
    SERVICE_PATH, SESSION_COLLECTION_ALIAS, SESSION_COLLECTION_ID, alias_path, collection_path,
    item_path, object_removed_or_absent, register_alias, register_collection, register_existing,
    register_item, unregister_alias,
};
use super::{next_stream_item, p2p_pair, test_state};
use crate::gpg::test_support::TestGnupg;

async fn get_property(
    connection: &zbus::Connection,
    path: &OwnedObjectPath,
    interface: &str,
    property: &str,
) -> OwnedValue {
    connection
        .call_method(
            None::<zbus::names::BusName<'_>>,
            path,
            Some("org.freedesktop.DBus.Properties"),
            "Get",
            &(interface, property),
        )
        .await
        .unwrap()
        .body()
        .deserialize()
        .unwrap()
}

#[tokio::test]
async fn startup_registers_builtin_session_collection_and_alias() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    let legacy = state
        .store()
        .create_collection("legacy-session-alias", Some(SESSION_COLLECTION_ALIAS))
        .unwrap();
    let (server_conn, client_conn) = p2p_pair(state.clone()).await;
    let server = server_conn.object_server();

    register_existing(server, &state).await.unwrap();

    let collection = collection_path(SESSION_COLLECTION_ID);
    let alias = alias_path(SESSION_COLLECTION_ALIAS).unwrap();
    assert!(
        server
            .interface::<_, crate::service::collection::Collection>(&collection)
            .await
            .is_ok()
    );
    assert!(
        server
            .interface::<_, crate::service::collection::Collection>(&alias)
            .await
            .is_ok()
    );
    assert_eq!(
        String::try_from(
            get_property(
                &client_conn,
                &alias,
                "org.freedesktop.Secret.Collection",
                "Label",
            )
            .await,
        )
        .unwrap(),
        "Session"
    );
    assert!(
        state
            .store()
            .list_collections()
            .unwrap()
            .iter()
            .all(|meta| meta.id != SESSION_COLLECTION_ID)
    );
    assert_eq!(
        state.store().read_alias(SESSION_COLLECTION_ALIAS).unwrap(),
        Some(legacy.id),
        "legacy persisted alias may remain on disk but must not shadow the built-in runtime alias"
    );
}

#[tokio::test]
async fn repeated_collection_registration_is_idempotent() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    let collection = state.store().create_collection("repeat", None).unwrap();
    let collections_before = state.store().list_collections().unwrap();
    let (server_conn, client_conn) = p2p_pair(state.clone()).await;
    let server = server_conn.object_server();

    let first_path = register_collection(server, &state, &collection.id)
        .await
        .unwrap();
    let second_path = register_collection(server, &state, &collection.id)
        .await
        .unwrap();

    assert_eq!(first_path, collection_path(&collection.id));
    assert_eq!(second_path, first_path);
    assert!(
        server
            .interface::<_, crate::service::collection::Collection>(&first_path)
            .await
            .is_ok()
    );
    assert_eq!(
        String::try_from(
            get_property(
                &client_conn,
                &first_path,
                "org.freedesktop.Secret.Collection",
                "Label",
            )
            .await,
        )
        .unwrap(),
        collection.label
    );
    assert_eq!(
        state.store().list_collections().unwrap(),
        collections_before
    );
}

#[tokio::test]
async fn repeated_item_registration_is_idempotent() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    let collection = state
        .store()
        .get_collection(crate::store::DEFAULT_COLLECTION_ID)
        .unwrap();
    let attributes = HashMap::from([("kind".to_string(), "repeat".to_string())]);
    let item = state
        .store()
        .create_item(
            &collection.id,
            "before",
            attributes,
            "text/plain",
            b"ciphertext",
        )
        .unwrap();
    let (server_conn, client_conn) = p2p_pair(state.clone()).await;
    let server = server_conn.object_server();

    let first_path = register_item(server, &state, &collection.id, &item.id)
        .await
        .unwrap();
    let second_path = register_item(server, &state, &collection.id, &item.id)
        .await
        .unwrap();

    assert_eq!(first_path, item_path(&collection.id, &item.id));
    assert_eq!(second_path, first_path);
    assert!(
        server
            .interface::<_, crate::service::item::Item>(&first_path)
            .await
            .is_ok()
    );
    assert_eq!(
        String::try_from(
            get_property(
                &client_conn,
                &first_path,
                "org.freedesktop.Secret.Item",
                "Label",
            )
            .await,
        )
        .unwrap(),
        "before"
    );

    let updated_attributes = HashMap::from([("kind".to_string(), "updated".to_string())]);
    let updated = state
        .store()
        .update_item(
            &item.id,
            Some("after"),
            Some(updated_attributes),
            None,
            None,
        )
        .unwrap();
    assert_eq!(updated.collection, collection.id);
    assert_eq!(
        String::try_from(
            get_property(
                &client_conn,
                &first_path,
                "org.freedesktop.Secret.Item",
                "Label",
            )
            .await,
        )
        .unwrap(),
        updated.label
    );
    assert_eq!(
        HashMap::<String, String>::try_from(
            get_property(
                &client_conn,
                &first_path,
                "org.freedesktop.Secret.Item",
                "Attributes",
            )
            .await,
        )
        .unwrap(),
        updated.attributes
    );
}

#[tokio::test]
async fn alias_reregistration_follows_repointed_store_target() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    let collection_a = state.store().create_collection("alias-a", None).unwrap();
    let collection_b = state.store().create_collection("alias-b", None).unwrap();
    let alias = "repeat_alias";
    state
        .store()
        .set_alias(alias, Some(&collection_a.id))
        .unwrap();
    let (server_conn, client_conn) = p2p_pair(state.clone()).await;
    let server = server_conn.object_server();
    register_alias(server, &state, alias).await.unwrap();
    let path = alias_path(alias).unwrap();
    assert!(
        server
            .interface::<_, crate::service::collection::Collection>(&path)
            .await
            .is_ok()
    );
    assert_eq!(
        String::try_from(
            get_property(
                &client_conn,
                &path,
                "org.freedesktop.Secret.Collection",
                "Label",
            )
            .await,
        )
        .unwrap(),
        collection_a.label
    );

    state
        .store()
        .set_alias(alias, Some(&collection_b.id))
        .unwrap();
    let aliases_after_repoint = state.store().list_aliases().unwrap();
    register_alias(server, &state, alias).await.unwrap();

    assert!(
        server
            .interface::<_, crate::service::collection::Collection>(&path)
            .await
            .is_ok()
    );
    assert_eq!(
        String::try_from(
            get_property(
                &client_conn,
                &path,
                "org.freedesktop.Secret.Collection",
                "Label",
            )
            .await,
        )
        .unwrap(),
        collection_b.label
    );
    assert_eq!(
        state.store().read_alias(alias).unwrap(),
        Some(collection_b.id.clone())
    );
    assert_eq!(state.store().list_aliases().unwrap(), aliases_after_repoint);
}

#[tokio::test]
async fn registration_errors_can_leave_persisted_interfaces_served() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    let collection = state.store().create_collection("error", None).unwrap();
    let item = state
        .store()
        .create_item(
            &collection.id,
            "error-item",
            HashMap::new(),
            "text/plain",
            b"ciphertext",
        )
        .unwrap();
    let alias = "error_alias";
    state
        .store()
        .set_alias(alias, Some(&collection.id))
        .unwrap();

    let (server_conn, _client_conn) = p2p_pair(state.clone()).await;
    let server = server_conn.object_server().clone();
    assert!(
        server
            .at(SERVICE_PATH, zbus::fdo::ObjectManager)
            .await
            .unwrap()
    );
    let connection_guard = server_conn.clone();
    server_conn.close().await.unwrap();

    assert!(
        register_collection(&server, &state, &collection.id)
            .await
            .is_err()
    );
    assert_eq!(
        state.store().get_collection(&collection.id).unwrap(),
        collection
    );
    assert!(
        server
            .interface::<_, crate::service::collection::Collection>(&collection_path(
                &collection.id
            ))
            .await
            .is_ok()
    );

    assert!(
        register_item(&server, &state, &collection.id, &item.id)
            .await
            .is_err()
    );
    assert_eq!(state.store().get_item(&item.id).unwrap(), item);
    assert!(
        server
            .interface::<_, crate::service::item::Item>(&item_path(&collection.id, &item.id))
            .await
            .is_ok()
    );

    assert!(register_alias(&server, &state, alias).await.is_err());
    assert_eq!(
        state.store().read_alias(alias).unwrap(),
        Some(collection.id.clone())
    );
    assert!(
        server
            .interface::<_, crate::service::collection::Collection>(&alias_path(alias).unwrap())
            .await
            .is_ok()
    );
    drop(connection_guard);
}

#[tokio::test]
async fn alias_removal_error_leaves_store_cleared_and_interface_absent() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    let collection = state.store().create_collection("clear", None).unwrap();
    let alias = "clear_alias";
    state
        .store()
        .set_alias(alias, Some(&collection.id))
        .unwrap();
    let (server_conn, _client_conn) = p2p_pair(state.clone()).await;
    let server = server_conn.object_server().clone();
    register_alias(&server, &state, alias).await.unwrap();
    let path = alias_path(alias).unwrap();
    assert!(
        server
            .at(SERVICE_PATH, zbus::fdo::ObjectManager)
            .await
            .unwrap()
    );
    let connection_guard = server_conn.clone();
    server_conn.close().await.unwrap();

    state.store().set_alias(alias, None).unwrap();
    assert!(unregister_alias(&server, alias).await.is_err());
    assert_eq!(state.store().read_alias(alias).unwrap(), None);
    assert!(matches!(
        server
            .interface::<_, crate::service::collection::Collection>(&path)
            .await,
        Err(zbus::Error::InterfaceNotFound)
    ));
    drop(connection_guard);
}

#[tokio::test]
async fn alias_removal_is_idempotent() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    let (server_conn, _client_conn) = p2p_pair(state.clone()).await;
    let server = server_conn.object_server();

    unregister_alias(server, "unknown").await.unwrap();
    unregister_alias(server, "unknown").await.unwrap();

    state
        .store()
        .set_alias("twice", Some(crate::store::DEFAULT_COLLECTION_ID))
        .unwrap();
    register_alias(server, &state, "twice").await.unwrap();
    state.store().set_alias("twice", None).unwrap();
    unregister_alias(server, "twice").await.unwrap();
    unregister_alias(server, "twice").await.unwrap();
    assert_eq!(state.store().read_alias("twice").unwrap(), None);
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "single end-to-end regression verifies cleanup, object removal, and both signals"
)]
async fn collection_delete_ignores_already_absent_interface_and_finishes_cleanup() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    let collection = state
        .store()
        .create_collection("delete", Some("delete_alias"))
        .unwrap();
    let first = state
        .store()
        .create_item(
            &collection.id,
            "first",
            HashMap::new(),
            "text/plain",
            b"first",
        )
        .unwrap();
    let second = state
        .store()
        .create_item(
            &collection.id,
            "second",
            HashMap::new(),
            "text/plain",
            b"second",
        )
        .unwrap();
    let (server_conn, client_conn) = p2p_pair(state.clone()).await;
    let server = server_conn.object_server();
    let collection_path = register_collection(server, &state, &collection.id)
        .await
        .unwrap();
    let first_path = register_item(server, &state, &collection.id, &first.id)
        .await
        .unwrap();
    let second_path = register_item(server, &state, &collection.id, &second.id)
        .await
        .unwrap();
    register_alias(server, &state, "delete_alias")
        .await
        .unwrap();
    let alias_object = alias_path("delete_alias").unwrap();
    let deleted_rule = zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .path(SERVICE_PATH)
        .unwrap()
        .interface("org.freedesktop.Secret.Service")
        .unwrap()
        .member("CollectionDeleted")
        .unwrap()
        .build();
    let mut collection_deleted =
        zbus::MessageStream::for_match_rule(deleted_rule, &client_conn, None)
            .await
            .unwrap();
    let properties_rule = zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .path(SERVICE_PATH)
        .unwrap()
        .interface("org.freedesktop.DBus.Properties")
        .unwrap()
        .member("PropertiesChanged")
        .unwrap()
        .build();
    let mut properties_changed =
        zbus::MessageStream::for_match_rule(properties_rule, &client_conn, None)
            .await
            .unwrap();
    object_removed_or_absent(
        server
            .remove::<crate::service::item::Item, _>(&first_path)
            .await,
    )
    .unwrap();

    crate::service::collection::Collection::new(state.clone(), collection.id.clone())
        .delete_for_test(server, &server_conn)
        .await
        .unwrap();

    let deleted_signal = tokio::time::timeout(
        Duration::from_secs(1),
        next_stream_item(&mut collection_deleted),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    let (deleted_path,): (OwnedObjectPath,) = deleted_signal.body().deserialize().unwrap();
    assert_eq!(deleted_path, collection_path);
    let changed_signal = tokio::time::timeout(
        Duration::from_secs(1),
        next_stream_item(&mut properties_changed),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    let (interface, changed, _invalidated): (String, HashMap<String, OwnedValue>, Vec<String>) =
        changed_signal.body().deserialize().unwrap();
    assert_eq!(interface, "org.freedesktop.Secret.Service");
    assert!(changed.contains_key("Collections"));

    assert!(matches!(
        state.store().get_collection(&collection.id),
        Err(crate::Error::NotFound(_))
    ));
    for path in [first_path, second_path] {
        assert!(matches!(
            server
                .interface::<_, crate::service::item::Item>(&path)
                .await,
            Err(zbus::Error::InterfaceNotFound)
        ));
    }
    for path in [collection_path, alias_object] {
        assert!(matches!(
            server
                .interface::<_, crate::service::collection::Collection>(&path)
                .await,
            Err(zbus::Error::InterfaceNotFound)
        ));
    }
}
