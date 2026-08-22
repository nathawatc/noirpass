use std::collections::HashMap;
use std::time::Duration;

use zbus::zvariant::{OwnedObjectPath, OwnedValue};

use super::super::{
    SERVICE_PATH, alias_path, object_removed_or_absent, register_alias, register_collection,
    register_item, unregister_alias,
};
use super::{next_stream_item, p2p_pair, test_state};
use crate::gpg::test_support::TestGnupg;

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
