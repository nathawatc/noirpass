use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use super::super::{
    alias_path, collection_path, item_path, register_alias, register_collection, register_item,
    unregister_alias,
};
use super::{p2p_pair, test_state};
use crate::gpg::test_support::TestGnupg;

#[tokio::test]
async fn temporary_mutations_remain_available_while_persistent_workers_are_busy() {
    use super::super::{
        SESSION_COLLECTION_ID, SessionCipher, collection::Collection, session::Secret,
    };
    use zeroize::Zeroizing;

    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    let mut ids = vec![crate::store::DEFAULT_COLLECTION_ID.to_string()];
    for _ in 1..super::super::state::MAX_BLOCKING_WORKERS {
        ids.push(state.store().create_collection("busy", None).unwrap().id);
    }
    let (server, client) = p2p_pair(state.clone()).await;
    super::super::register_existing(server.object_server(), &state)
        .await
        .unwrap();
    let mut tasks = Vec::new();
    let mut releases = Vec::new();
    for id in ids {
        let worker_state = state.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        tasks.push(tokio::spawn(async move {
            let lifecycle = worker_state.lock_owned_collection_lifecycle(&id).await;
            worker_state
                .blocking(Some(lifecycle), move |_| {
                    started_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    Ok(())
                })
                .await
                .unwrap();
        }));
        tokio::time::timeout(Duration::from_secs(2), started_rx)
            .await
            .unwrap()
            .unwrap();
        releases.push(release_tx);
    }
    // A queued namespace write must wait for worker capacity before freezing temporary mutations.
    let namespace = super::super::Service::new(state.clone());
    super::support::admit_then_cancel(namespace.set_alias(
        "queued_namespace",
        super::super::objects::root_path(),
        server.object_server(),
        &server,
    ))
    .await;
    let session = state
        .register_session(SessionCipher::Plain, ":1.7".into())
        .unwrap();
    let collection = Collection::new(state.clone(), SESSION_COLLECTION_ID.into());
    let message = zbus::Message::method_call(collection_path(SESSION_COLLECTION_ID), "CreateItem")
        .unwrap()
        .sender(":1.7")
        .unwrap()
        .build(&())
        .unwrap();
    let secret = Secret {
        session,
        parameters: Vec::new(),
        value: Zeroizing::new(b"temporary".to_vec()),
        content_type: "text/plain".into(),
    };
    let (path, _) = tokio::time::timeout(
        Duration::from_secs(2),
        collection.create_item_for_test(secret, server.object_server(), &server, message.header()),
    )
    .await
    .unwrap()
    .unwrap();
    let item = zbus::Proxy::new(&client, ":1.0", path.clone(), "org.freedesktop.Secret.Item")
        .await
        .unwrap();
    tokio::time::timeout(
        Duration::from_secs(2),
        item.set_property("Label", "changed"),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        item.get_property::<String>("Label").await.unwrap(),
        "changed"
    );
    // Namespace changes still wait for complete commit/publication of active collections.
    assert!(
        tokio::time::timeout(Duration::from_millis(50), state.lock_object_lifecycle())
            .await
            .is_err()
    );
    for release in releases {
        release.send(()).unwrap();
    }
    for task in tasks {
        task.await.unwrap();
    }
    tokio::time::timeout(Duration::from_secs(2), state.wait_for_active_calls())
        .await
        .unwrap();
    let _: zbus::zvariant::OwnedObjectPath = item.call("Delete", &()).await.unwrap();
    assert!(state.list_session_items().is_empty());
}

#[tokio::test]
async fn cancelled_metadata_waiter_finishes_update_and_signals() {
    use super::super::item::Item;
    use std::future::Future;

    let gnupg = TestGnupg::new();
    for shutting_down in [false, true] {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(&gnupg, tmp.path());
        let id = crate::store::DEFAULT_COLLECTION_ID;
        let meta = state
            .store()
            .create_item(id, "old", HashMap::new(), "text/plain", b"opaque")
            .unwrap();
        let (server, client) = p2p_pair(state.clone()).await;
        super::super::register_existing(server.object_server(), &state)
            .await
            .unwrap();
        let object = Item::new(state.clone(), id.into(), meta.id.clone());
        // P2P signals have no bus-assigned sender; match the interface/path directly.
        let rule = zbus::MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .interface("org.freedesktop.Secret.Collection")
            .unwrap()
            .member("ItemChanged")
            .unwrap()
            .path(collection_path(id))
            .unwrap()
            .build();
        let mut signals = zbus::MessageStream::for_match_rule(rule, &client, None)
            .await
            .unwrap();
        let lifecycle = state.lock_collection_lifecycle(id).await;
        {
            let update = object.set_label_for_test("new", &server);
            tokio::pin!(update);
            std::future::poll_fn(|context| {
                assert!(update.as_mut().poll(context).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
        }
        assert_eq!(state.store().get_item(&meta.id).unwrap().label, "old");
        if shutting_down {
            state.begin_shutdown();
            assert!(state.activity().is_err());
        }
        drop(lifecycle);
        tokio::time::timeout(Duration::from_secs(2), state.wait_for_active_calls())
            .await
            .unwrap();
        let signal = tokio::time::timeout(
            Duration::from_secs(2),
            super::next_stream_item(&mut signals),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        let (changed_path,): (zbus::zvariant::OwnedObjectPath,) =
            signal.body().deserialize().unwrap();
        assert_eq!(changed_path, item_path(id, &meta.id));
        let proxy = zbus::Proxy::new(
            &client,
            ":1.0",
            item_path(id, &meta.id),
            "org.freedesktop.Secret.Item",
        )
        .await
        .unwrap();
        assert_eq!(state.store().get_item(&meta.id).unwrap().label, "new");
        if shutting_down {
            assert!(proxy.get_property::<String>("Label").await.is_err());
        } else {
            assert_eq!(proxy.get_property::<String>("Label").await.unwrap(), "new");
        }
    }
}

#[tokio::test]
async fn item_delete_cannot_race_replacement_registration() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    let collection = state
        .store()
        .get_collection(crate::store::DEFAULT_COLLECTION_ID)
        .unwrap();
    let attributes = HashMap::from([("service".to_string(), "mail".to_string())]);
    let item = state
        .store()
        .create_item(
            &collection.id,
            "mail",
            attributes.clone(),
            "text/plain",
            b"old",
        )
        .unwrap();
    let (server_conn, _client_conn) = p2p_pair(state.clone()).await;
    let server = server_conn.object_server().clone();
    register_collection(&server, &state, &collection.id)
        .await
        .unwrap();
    let item_object = register_item(&server, &state, &collection.id, &item.id)
        .await
        .unwrap();
    let committed = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());

    let replacement_state = state.clone();
    let replacement_server = server.clone();
    let replacement_collection = collection.id.clone();
    let replacement_attributes = attributes.clone();
    let replacement_committed = committed.clone();
    let replacement_resume = resume.clone();
    let replacement = tokio::spawn(async move {
        let _lifecycle = replacement_state
            .lock_collection_lifecycle(&replacement_collection)
            .await;
        let (metadata, replaced) = replacement_state
            .store()
            .create_or_replace_item(
                &replacement_collection,
                "updated",
                replacement_attributes,
                "text/plain",
                b"new",
                true,
            )
            .unwrap();
        assert!(replaced);
        replacement_committed.notify_one();
        replacement_resume.notified().await;
        register_item(
            &replacement_server,
            &replacement_state,
            &replacement_collection,
            &metadata.id,
        )
        .await
        .unwrap();
    });
    committed.notified().await;

    let deletion_state = state.clone();
    let deletion_server = server.clone();
    let deletion_item = item.clone();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let deletion = tokio::spawn(async move {
        started_tx.send(()).unwrap();
        let _lifecycle = deletion_state
            .lock_collection_lifecycle(&deletion_item.collection)
            .await;
        deletion_state
            .store()
            .delete_item(&deletion_item.id)
            .unwrap();
        deletion_server
            .remove::<crate::service::item::Item, _>(&item_path(
                &deletion_item.collection,
                &deletion_item.id,
            ))
            .await
            .unwrap();
    });
    started_rx.await.unwrap();
    tokio::task::yield_now().await;
    assert!(!deletion.is_finished());

    resume.notify_one();
    replacement.await.unwrap();
    deletion.await.unwrap();
    assert!(matches!(
        state.store().get_item(&item.id),
        Err(crate::Error::NotFound(_))
    ));
    assert!(matches!(
        server
            .interface::<_, crate::service::item::Item>(&item_object)
            .await,
        Err(zbus::Error::InterfaceNotFound)
    ));
}

#[tokio::test]
async fn collection_delete_removes_concurrently_created_item_object() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    let collection = state.store().create_collection("race", None).unwrap();
    let (server_conn, _client_conn) = p2p_pair(state.clone()).await;
    let server = server_conn.object_server().clone();
    let collection_object = register_collection(&server, &state, &collection.id)
        .await
        .unwrap();
    let committed = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());

    let creation_state = state.clone();
    let creation_server = server.clone();
    let creation_collection = collection.id.clone();
    let creation_committed = committed.clone();
    let creation_resume = resume.clone();
    let creation = tokio::spawn(async move {
        let _lifecycle = creation_state
            .lock_collection_lifecycle(&creation_collection)
            .await;
        let metadata = creation_state
            .store()
            .create_item(
                &creation_collection,
                "created",
                HashMap::new(),
                "text/plain",
                b"ciphertext",
            )
            .unwrap();
        creation_committed.notify_one();
        creation_resume.notified().await;
        register_item(
            &creation_server,
            &creation_state,
            &creation_collection,
            &metadata.id,
        )
        .await
        .unwrap();
        metadata.id
    });
    committed.notified().await;

    let deletion_state = state.clone();
    let deletion_server = server.clone();
    let deletion_collection = collection.id.clone();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let deletion = tokio::spawn(async move {
        started_tx.send(()).unwrap();
        let _lifecycle = deletion_state.lock_object_lifecycle().await;
        let deleted = deletion_state
            .store()
            .delete_collection(&deletion_collection)
            .unwrap();
        for item_id in deleted.item_ids {
            deletion_server
                .remove::<crate::service::item::Item, _>(&item_path(&deletion_collection, &item_id))
                .await
                .unwrap();
        }
        deletion_server
            .remove::<crate::service::collection::Collection, _>(&collection_path(
                &deletion_collection,
            ))
            .await
            .unwrap();
    });
    started_rx.await.unwrap();
    tokio::task::yield_now().await;
    assert!(!deletion.is_finished());

    resume.notify_one();
    let item_id = creation.await.unwrap();
    deletion.await.unwrap();
    assert!(matches!(
        state.store().get_collection(&collection.id),
        Err(crate::Error::NotFound(_))
    ));
    assert!(matches!(
        server
            .interface::<_, crate::service::item::Item>(item_path(&collection.id, &item_id))
            .await,
        Err(zbus::Error::InterfaceNotFound)
    ));
    assert!(matches!(
        server
            .interface::<_, crate::service::collection::Collection>(&collection_object)
            .await,
        Err(zbus::Error::InterfaceNotFound)
    ));
}

#[tokio::test]
async fn collection_delete_removes_concurrently_registered_alias() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    let collection = state.store().create_collection("race", None).unwrap();
    let (server_conn, _client_conn) = p2p_pair(state.clone()).await;
    let server = server_conn.object_server().clone();
    register_collection(&server, &state, &collection.id)
        .await
        .unwrap();
    let alias = "racing_alias";
    let alias_object = alias_path(alias).unwrap();
    let committed = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());

    let alias_state = state.clone();
    let alias_server = server.clone();
    let alias_collection = collection.id.clone();
    let alias_committed = committed.clone();
    let alias_resume = resume.clone();
    let alias_update = tokio::spawn(async move {
        let _lifecycle = alias_state.lock_object_lifecycle().await;
        alias_state
            .store()
            .set_alias(alias, Some(&alias_collection))
            .unwrap();
        alias_committed.notify_one();
        alias_resume.notified().await;
        register_alias(&alias_server, &alias_state, alias)
            .await
            .unwrap();
    });
    committed.notified().await;

    let deletion_state = state.clone();
    let deletion_server = server.clone();
    let deletion_collection = collection.id.clone();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let deletion = tokio::spawn(async move {
        started_tx.send(()).unwrap();
        let _lifecycle = deletion_state.lock_object_lifecycle().await;
        let deleted = deletion_state
            .store()
            .delete_collection(&deletion_collection)
            .unwrap();
        for name in deleted.aliases {
            unregister_alias(&deletion_server, &name).await.unwrap();
        }
        deletion_server
            .remove::<crate::service::collection::Collection, _>(&collection_path(
                &deletion_collection,
            ))
            .await
            .unwrap();
    });
    started_rx.await.unwrap();
    tokio::task::yield_now().await;
    assert!(!deletion.is_finished());

    resume.notify_one();
    alias_update.await.unwrap();
    deletion.await.unwrap();
    assert_eq!(state.store().read_alias(alias).unwrap(), None);
    assert!(matches!(
        server
            .interface::<_, crate::service::collection::Collection>(&alias_object)
            .await,
        Err(zbus::Error::InterfaceNotFound)
    ));
}

#[tokio::test]
async fn cancelled_create_waiter_still_commits_and_registers_item() {
    use super::super::{SessionCipher, collection::Collection, session::Secret};
    use std::future::Future;
    use std::time::Duration;
    use zeroize::Zeroizing;

    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    let (server, _client) = p2p_pair(state.clone()).await;
    let id = crate::store::DEFAULT_COLLECTION_ID;
    register_collection(server.object_server(), &state, id)
        .await
        .unwrap();
    let session = state
        .register_session(SessionCipher::Plain, ":1.7".into())
        .unwrap();
    let collection = Collection::new(state.clone(), id.into());
    let message = zbus::Message::method_call(collection_path(id), "CreateItem")
        .unwrap()
        .sender(":1.7")
        .unwrap()
        .build(&())
        .unwrap();
    let secret = Secret {
        session,
        parameters: Vec::new(),
        value: Zeroizing::new(b"test cancellation".to_vec()),
        content_type: "text/plain".into(),
    };
    let lifecycle = state.lock_object_lifecycle().await;
    // Poll admission once, then drop only the caller future while the mutation task waits.
    {
        let creation = collection.create_item_for_test(
            secret,
            server.object_server(),
            &server,
            message.header(),
        );
        tokio::pin!(creation);
        std::future::poll_fn(|context| {
            assert!(creation.as_mut().poll(context).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
    }
    drop(lifecycle);
    tokio::time::timeout(Duration::from_secs(5), state.wait_for_active_calls())
        .await
        .unwrap();
    let items = state.store().list_items(id).unwrap();
    assert_eq!(items.len(), 1);
    let path = item_path(id, &items[0].id);
    assert!(
        server
            .object_server()
            .interface::<_, super::super::item::Item>(&path)
            .await
            .is_ok()
    );
    assert_eq!(
        state
            .gpg()
            .decrypt(&state.store().read_item_secret(&items[0].id).unwrap().1)
            .await
            .unwrap()
            .as_slice(),
        b"test cancellation"
    );
}
