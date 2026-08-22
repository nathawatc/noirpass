use std::time::Duration;

use zbus::zvariant::OwnedObjectPath;

use super::super::super::helpers::{
    COLLECTION_IFACE, ITEM_IFACE, PROPERTIES_IFACE, SERVICE_NAME, attrs, locked_property,
    next_event, service_proxy,
};

/// Scenario 10: `CollectionCreated` and `ItemCreated` signals fire.
pub(in super::super) async fn s10_signals() {
    let conn = zbus::Connection::session().await.unwrap();
    let proxy = service_proxy(&conn).await;
    let created_stream = proxy.receive_signal("CollectionCreated").await.unwrap();
    let mut created_stream = std::pin::pin!(created_stream);

    let service = oo7::dbus::Service::plain().await.unwrap();
    let collection = service
        .create_collection("s10-col", None, None)
        .await
        .unwrap();
    let col_path = OwnedObjectPath::from(collection.path().to_owned());

    let msg = tokio::time::timeout(Duration::from_secs(10), next_event(created_stream.as_mut()))
        .await
        .expect("timed out waiting for CollectionCreated")
        .expect("signal stream ended");
    let (created,): (OwnedObjectPath,) = msg.body().deserialize().unwrap();
    assert_eq!(created, col_path);

    // ItemCreated on the collection object.
    let col_proxy = zbus::Proxy::new(&conn, SERVICE_NAME, col_path.clone(), COLLECTION_IFACE)
        .await
        .unwrap();
    let item_stream = col_proxy.receive_signal("ItemCreated").await.unwrap();
    let mut item_stream = std::pin::pin!(item_stream);

    let item = collection
        .create_item(
            "s10-item",
            &attrs("s10"),
            oo7::Secret::text("x"),
            true,
            None,
        )
        .await
        .unwrap();
    let item_path = OwnedObjectPath::from(item.path().to_owned());

    let msg = tokio::time::timeout(Duration::from_secs(10), next_event(item_stream.as_mut()))
        .await
        .expect("timed out waiting for ItemCreated")
        .expect("signal stream ended");
    let (created,): (OwnedObjectPath,) = msg.body().deserialize().unwrap();
    assert_eq!(created, item_path);

    collection.delete(None).await.unwrap();
}

/// Scenario 11: lock methods preserve Noirpass's always-unlocked semantics.
pub(in super::super) async fn s11_lock_semantics() {
    let service = oo7::dbus::Service::plain().await.unwrap();
    let collection = service
        .create_collection("s11-lock", None, None)
        .await
        .unwrap();
    let item = collection
        .create_item(
            "s11-item",
            &attrs("s11"),
            oo7::Secret::text("always unlocked"),
            true,
            None,
        )
        .await
        .unwrap();
    let collection_path = OwnedObjectPath::from(collection.path().to_owned());
    let item_path = OwnedObjectPath::from(item.path().to_owned());

    let conn = zbus::Connection::session().await.unwrap();
    let service_proxy = service_proxy(&conn).await;
    let collection_properties = zbus::Proxy::new(
        &conn,
        SERVICE_NAME,
        collection_path.clone(),
        PROPERTIES_IFACE,
    )
    .await
    .unwrap();
    let item_properties =
        zbus::Proxy::new(&conn, SERVICE_NAME, item_path.clone(), PROPERTIES_IFACE)
            .await
            .unwrap();

    assert!(!locked_property(&item_properties, ITEM_IFACE).await);
    let (locked, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = service_proxy
        .call("Lock", &(vec![item_path.clone()],))
        .await
        .unwrap();
    assert!(locked.is_empty());
    assert_eq!(prompt.as_str(), "/");
    assert!(!locked_property(&item_properties, ITEM_IFACE).await);

    assert!(!locked_property(&collection_properties, COLLECTION_IFACE).await);
    let (locked, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = service_proxy
        .call("Lock", &(vec![collection_path.clone()],))
        .await
        .unwrap();
    assert!(locked.is_empty());
    assert_eq!(prompt.as_str(), "/");
    assert!(!locked_property(&collection_properties, COLLECTION_IFACE).await);

    let (locked, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = service_proxy
        .call("Lock", &(vec![collection_path.clone(), item_path.clone()],))
        .await
        .unwrap();
    assert!(locked.is_empty());
    assert_eq!(prompt.as_str(), "/");

    let (unlocked, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = service_proxy
        .call("Unlock", &(vec![item_path.clone()],))
        .await
        .unwrap();
    assert_eq!(unlocked, vec![item_path]);
    assert_eq!(prompt.as_str(), "/");

    collection.delete(None).await.unwrap();
}
