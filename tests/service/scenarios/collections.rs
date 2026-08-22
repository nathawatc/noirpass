use std::collections::HashMap;

use zbus::zvariant::OwnedObjectPath;

use super::super::harness::harness;
use super::super::helpers::{attrs, object_id, service_proxy};

/// Scenario 5: collection lifecycle — creation, listing, cascading delete
/// (D-Bus objects and on-disk `.gpg` files both disappear).
pub(super) async fn s5_collection_lifecycle() {
    let h = harness();
    let service = oo7::dbus::Service::encrypted().await.unwrap();
    let collection = service
        .create_collection("s5-col", None, None)
        .await
        .unwrap();

    let mut labels = Vec::new();
    for c in service.collections().await.unwrap() {
        labels.push(c.label().await.unwrap());
    }
    assert!(labels.contains(&"s5-col".to_string()), "labels: {labels:?}");

    let i1 = collection
        .create_item("s5-a", &attrs("s5"), oo7::Secret::text("a"), false, None)
        .await
        .unwrap();
    let i2 = collection
        .create_item("s5-b", &attrs("s5"), oo7::Secret::text("b"), false, None)
        .await
        .unwrap();

    let f1 = h
        .store_dir
        .join("secrets")
        .join(format!("{}.gpg", object_id(i1.path())));
    let f2 = h
        .store_dir
        .join("secrets")
        .join(format!("{}.gpg", object_id(i2.path())));
    assert!(f1.exists() && f2.exists(), "secret files must exist");

    collection.delete(None).await.unwrap();

    assert!(!f1.exists() && !f2.exists(), "secret files must be removed");
    // The items are unreachable through search.
    let conn = zbus::Connection::session().await.unwrap();
    let proxy = service_proxy(&conn).await;
    let (unlocked, locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) = proxy
        .call(
            "SearchItems",
            &(HashMap::from([("case".to_string(), "s5".to_string())]),),
        )
        .await
        .unwrap();
    assert!(unlocked.is_empty() && locked.is_empty());
    // And the collection is gone from the listing.
    let mut labels = Vec::new();
    for c in service.collections().await.unwrap() {
        labels.push(c.label().await.unwrap());
    }
    assert!(!labels.contains(&"s5-col".to_string()));
}
