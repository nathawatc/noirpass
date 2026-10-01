//! Cancellation regressions for the real object server's namespace mutations.

use std::collections::HashMap;
use std::time::Duration;

use zbus::object_server::SignalEmitter;

use super::super::{
    SERVICE_PATH, SESSION_COLLECTION_ID, Service, alias_path, collection::Collection,
    collection_path, item::Item, item_path, objects::root_path, register_existing,
};
use super::{next_stream_item, p2p_pair, support::admit_then_cancel, test_state};
use crate::gpg::test_support::TestGnupg;

async fn service_signals(client: &zbus::Connection, member: &str) -> zbus::MessageStream {
    let rule = zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .interface("org.freedesktop.Secret.Service")
        .unwrap()
        .path(SERVICE_PATH)
        .unwrap()
        .member(member)
        .unwrap()
        .build();
    zbus::MessageStream::for_match_rule(rule, client, None)
        .await
        .unwrap()
}

#[tokio::test]
async fn cancelled_collection_creation_finishes_alias_registration_and_signals() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    let (server, client) = p2p_pair(state.clone()).await;
    register_existing(server.object_server(), &state)
        .await
        .unwrap();
    let mut signals = service_signals(&client, "CollectionCreated").await;
    let object = Service::new(state.clone());
    let emitter = SignalEmitter::new(&server, SERVICE_PATH).unwrap();
    let lifecycle = state.lock_object_lifecycle().await;
    admit_then_cancel(object.create_collection(
        HashMap::new(),
        "cancel_created",
        server.object_server(),
        emitter,
    ))
    .await;
    drop(lifecycle);
    tokio::time::timeout(Duration::from_secs(5), state.wait_for_active_calls())
        .await
        .unwrap();
    let id = state.store().read_alias("cancel_created").unwrap().unwrap();
    for path in [collection_path(&id), alias_path("cancel_created").unwrap()] {
        assert!(
            server
                .object_server()
                .interface::<_, Collection>(&path)
                .await
                .is_ok()
        );
    }
    let message = tokio::time::timeout(Duration::from_secs(2), next_stream_item(&mut signals))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let (path,): (zbus::zvariant::OwnedObjectPath,) = message.body().deserialize().unwrap();
    assert_eq!(path, collection_path(&id));
}

#[tokio::test]
async fn cancelled_alias_mutations_finish_memory_persistence_and_publication() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    let (server, _client) = p2p_pair(state.clone()).await;
    register_existing(server.object_server(), &state)
        .await
        .unwrap();
    let object = Service::new(state.clone());
    let name = "cancel_alias";
    for id in [
        SESSION_COLLECTION_ID,
        crate::store::DEFAULT_COLLECTION_ID,
        "",
    ] {
        let target = if id.is_empty() {
            root_path()
        } else {
            collection_path(id)
        };
        let lifecycle = state.lock_object_lifecycle().await;
        admit_then_cancel(object.set_alias(name, target, server.object_server(), &server)).await;
        drop(lifecycle);
        tokio::time::timeout(Duration::from_secs(5), state.wait_for_active_calls())
            .await
            .unwrap();
        assert_eq!(
            state.read_alias(name).unwrap(),
            (!id.is_empty()).then(|| id.to_string())
        );
        let expected_persisted =
            (id == crate::store::DEFAULT_COLLECTION_ID).then(|| id.to_string());
        assert_eq!(state.store().read_alias(name).unwrap(), expected_persisted);
        let registration = server
            .object_server()
            .interface::<_, Collection>(&alias_path(name).unwrap())
            .await;
        if id.is_empty() {
            assert!(matches!(registration, Err(zbus::Error::InterfaceNotFound)));
        } else {
            assert!(registration.is_ok());
        }
    }
}

#[tokio::test]
async fn cancelled_collection_deletion_removes_items_aliases_and_emits_signal() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    let collection = state
        .store()
        .create_collection("cancel delete", Some("cancel_delete"))
        .unwrap();
    let item = state
        .store()
        .create_item(
            &collection.id,
            "item",
            HashMap::new(),
            "text/plain",
            b"opaque",
        )
        .unwrap();
    let (server, client) = p2p_pair(state.clone()).await;
    register_existing(server.object_server(), &state)
        .await
        .unwrap();
    let mut signals = service_signals(&client, "CollectionDeleted").await;
    let object = Collection::new(state.clone(), collection.id.clone());
    let lifecycle = state.lock_object_lifecycle().await;
    admit_then_cancel(object.delete_for_test(server.object_server(), &server)).await;
    drop(lifecycle);
    tokio::time::timeout(Duration::from_secs(5), state.wait_for_active_calls())
        .await
        .unwrap();
    assert!(matches!(
        state.store().get_collection(&collection.id),
        Err(crate::Error::NotFound(_))
    ));
    assert!(matches!(
        state.store().get_item(&item.id),
        Err(crate::Error::NotFound(_))
    ));
    assert_eq!(state.read_alias("cancel_delete").unwrap(), None);
    assert!(
        !tmp.path()
            .join("secrets")
            .join(format!("{}.gpg", item.id))
            .exists()
    );
    for path in [
        collection_path(&collection.id),
        alias_path("cancel_delete").unwrap(),
    ] {
        assert!(matches!(
            server
                .object_server()
                .interface::<_, Collection>(&path)
                .await,
            Err(zbus::Error::InterfaceNotFound)
        ));
    }
    assert!(matches!(
        server
            .object_server()
            .interface::<_, Item>(&item_path(&collection.id, &item.id))
            .await,
        Err(zbus::Error::InterfaceNotFound)
    ));
    let message = tokio::time::timeout(Duration::from_secs(2), next_stream_item(&mut signals))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let (path,): (zbus::zvariant::OwnedObjectPath,) = message.body().deserialize().unwrap();
    assert_eq!(path, collection_path(&collection.id));
}
