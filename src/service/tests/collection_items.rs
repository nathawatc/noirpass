use std::collections::HashMap;
use std::time::Duration;

use zbus::{OwnedObjectPath, OwnedVariant};

use super::super::{
    SESSION_COLLECTION_ID, alias_path, collection_path, item_path, register_collection,
    register_existing,
};
use super::{get_property, next_stream_item, p2p_pair, test_state};
use crate::gpg::test_support::TestGnupg;

#[tokio::test]
async fn items_reads_wait_for_workers_while_temporary_reads_remain_available() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    let item = state
        .store()
        .create_item(
            "default",
            "indexed",
            HashMap::new(),
            "text/plain",
            b"ciphertext",
        )
        .unwrap();
    let (server, client) = p2p_pair(state.clone()).await;
    register_existing(server.object_server(), &state)
        .await
        .unwrap();
    let mut workers = Vec::new();
    for n in 0..super::super::state::MAX_BLOCKING_WORKERS {
        workers.push(
            state
                .lock_owned_collection_lifecycle(&format!("busy{n}"))
                .await,
        );
    }
    // Property reads must not reserve request capacity, even while queued.
    let requests: Vec<_> = (0..super::super::state::MAX_PENDING_REQUESTS)
        .map(|_| state.request(&0u8).unwrap())
        .collect();
    let temporary = tokio::time::timeout(
        Duration::from_secs(2),
        get_property(
            &client,
            &collection_path(SESSION_COLLECTION_ID),
            "org.freedesktop.Secret.Collection",
            "Items",
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        Vec::<OwnedObjectPath>::try_from(temporary).unwrap().len(),
        0
    );
    let persistent_path = collection_path("default");
    let property = get_property(
        &client,
        &persistent_path,
        "org.freedesktop.Secret.Collection",
        "Items",
    );
    tokio::pin!(property);
    assert!(
        tokio::time::timeout(Duration::from_millis(25), &mut property)
            .await
            .is_err()
    );
    drop(workers);
    let value = tokio::time::timeout(Duration::from_secs(2), property)
        .await
        .unwrap();
    assert_eq!(
        Vec::<OwnedObjectPath>::try_from(value).unwrap(),
        vec![item_path("default", &item.id)]
    );
    drop(requests);
}

#[tokio::test]
async fn items_signals_reuse_reserved_workers_and_match_canonical_and_alias_values() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    let item = state
        .store()
        .create_item(
            "default",
            "indexed",
            HashMap::new(),
            "text/plain",
            b"ciphertext",
        )
        .unwrap();
    let (server, client) = p2p_pair(state.clone()).await;
    register_existing(server.object_server(), &state)
        .await
        .unwrap();
    let rule = zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .interface("org.freedesktop.DBus.Properties")
        .member("PropertiesChanged")
        .build()
        .unwrap();
    let mut signals = zbus::MessageStream::for_match_rule(rule, &client, None)
        .await
        .unwrap();
    let lifecycle = state.lock_owned_collection_lifecycle("default").await;
    let mut workers = Vec::new();
    for n in 1..super::super::state::MAX_BLOCKING_WORKERS {
        workers.push(
            state
                .lock_owned_collection_lifecycle(&format!("busy{n}"))
                .await,
        );
    }
    // All permits are held. A signal must reuse its own mutation reservation;
    // invoking the generated async Items getter would deadlock here.
    tokio::time::timeout(
        Duration::from_secs(2),
        super::super::collection::emit_collection_items_and_modified(
            &state,
            server.object_server(),
            &server,
            "default",
            lifecycle.clone(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let expected_modified = state.store().get_collection("default").unwrap().modified;
    let mut item_paths = std::collections::HashSet::new();
    let mut modified_paths = std::collections::HashSet::new();
    for _ in 0..4 {
        let signal = tokio::time::timeout(Duration::from_secs(2), next_stream_item(&mut signals))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let path = signal.header().path().unwrap().as_str().to_string();
        let (interface, mut changed, invalidated): (
            String,
            HashMap<String, OwnedVariant>,
            Vec<String>,
        ) = signal.body().deserialize().unwrap();
        assert_eq!(interface, "org.freedesktop.Secret.Collection");
        assert_eq!(invalidated.len(), 0);
        assert_eq!(changed.len(), 1);
        if let Some(items_val) = changed.remove("Items") {
            assert_eq!(
                Vec::<OwnedObjectPath>::try_from(items_val).unwrap(),
                vec![item_path("default", &item.id)]
            );
            item_paths.insert(path);
        } else {
            let modified_val = changed.remove("Modified").unwrap();
            assert_eq!(u64::try_from(modified_val).unwrap(), expected_modified);
            modified_paths.insert(path);
        }
    }
    let expected_paths = std::collections::HashSet::from([
        collection_path("default").to_string(),
        alias_path("default").unwrap().to_string(),
    ]);
    assert_eq!(item_paths, expected_paths);
    assert_eq!(modified_paths, expected_paths);
    drop(workers);
    drop(lifecycle);
}

#[tokio::test]
async fn queued_alias_items_reads_follow_repointing_and_preserve_removed_alias_error() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    let second = state.store().create_collection("second", None).unwrap();
    let item = state
        .store()
        .create_item(
            &second.id,
            "second",
            HashMap::new(),
            "text/plain",
            b"ciphertext",
        )
        .unwrap();
    state.store().set_alias("queued", Some("default")).unwrap();
    let (server, client) = p2p_pair(state.clone()).await;
    register_existing(server.object_server(), &state)
        .await
        .unwrap();
    let path = alias_path("queued").unwrap();
    for removed in [false, true] {
        let mut workers = Vec::new();
        for n in 0..super::super::state::MAX_BLOCKING_WORKERS {
            workers.push(
                state
                    .lock_owned_collection_lifecycle(&format!("busy{n}"))
                    .await,
            );
        }
        let property = client.call_method(
            None::<zbus::names::BusName<'_>>,
            &path,
            Some("org.freedesktop.DBus.Properties"),
            "Get",
            &("org.freedesktop.Secret.Collection", "Items"),
        );
        tokio::pin!(property);
        assert!(
            tokio::time::timeout(Duration::from_millis(25), &mut property)
                .await
                .is_err()
        );
        state
            .store()
            .set_alias("queued", if removed { None } else { Some(&second.id) })
            .unwrap();
        drop(workers);
        let reply = tokio::time::timeout(Duration::from_secs(2), property)
            .await
            .unwrap();
        if removed {
            assert!(matches!(
                reply,
                Err(zbus::Error::FDO(err)) if matches!(*err, zbus::fdo::Error::UnknownObject(_))
            ));
        } else {
            let value: OwnedVariant = reply.unwrap().body().deserialize().unwrap();
            assert_eq!(
                Vec::<OwnedObjectPath>::try_from(value).unwrap(),
                vec![item_path(&second.id, &item.id)]
            );
        }
    }
}

#[tokio::test]
async fn deleted_collection_returns_unknown_object_on_items_and_search() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    let collection = state.store().create_collection("ephemeral", None).unwrap();
    let (server_conn, client_conn) = p2p_pair(state.clone()).await;
    let path = register_collection(server_conn.object_server(), &state, &collection.id)
        .await
        .unwrap();
    state.store().delete_collection(&collection.id).unwrap();

    let items_err = client_conn
        .call_method(
            None::<zbus::names::BusName<'_>>,
            &path,
            Some("org.freedesktop.DBus.Properties"),
            "Get",
            &("org.freedesktop.Secret.Collection", "Items"),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        items_err,
        zbus::Error::FDO(err) if matches!(*err, zbus::fdo::Error::UnknownObject(_))
    ));

    let search_err = client_conn
        .call_method(
            None::<zbus::names::BusName<'_>>,
            &path,
            Some("org.freedesktop.Secret.Collection"),
            "SearchItems",
            &(HashMap::<String, String>::new(),),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        search_err,
        zbus::Error::FDO(err) if matches!(*err, zbus::fdo::Error::UnknownObject(_))
    ));
}
