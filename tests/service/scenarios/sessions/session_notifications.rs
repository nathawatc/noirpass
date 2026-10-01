use std::collections::HashMap;
use std::time::Duration;

use noirpass::service::session::Secret;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zeroize::Zeroizing;

use super::super::super::helpers::{
    COLLECTION_IFACE, ITEM_IFACE, PROPERTIES_IFACE, SERVICE_NAME, next_event, next_property_change,
    service_proxy,
};

async fn mutate_item(
    collection: &zbus::Proxy<'_>,
    item: &zbus::Proxy<'_>,
    secret: &Secret,
    step: usize,
) -> OwnedObjectPath {
    match step {
        0 | 1 => {
            let properties: HashMap<String, OwnedValue> = HashMap::new();
            let (path, _): (OwnedObjectPath, OwnedObjectPath) = collection
                .call("CreateItem", &(&properties, secret, step == 1))
                .await
                .unwrap();
            path
        }
        2 => {
            item.call::<_, _, ()>("SetSecret", &(secret,))
                .await
                .unwrap();
            item.path().to_owned().into()
        }
        3 => {
            item.set_property("Attributes", HashMap::from([("updated", "yes")]))
                .await
                .unwrap();
            item.path().to_owned().into()
        }
        4 => {
            item.set_property("Label", "updated").await.unwrap();
            item.path().to_owned().into()
        }
        5 => item.call("Delete", &()).await.unwrap(),
        _ => unreachable!(),
    }
}

/// Every temporary item mutation must update cached collection timestamps on both served paths.
#[allow(
    clippy::too_many_lines,
    reason = "one private-bus scenario covers notifications for every temporary item mutation"
)]
pub(in super::super) async fn s6d_session_collection_notifications() {
    let conn = zbus::Connection::session().await.unwrap();
    let service = service_proxy(&conn).await;
    let (_, session): (OwnedValue, OwnedObjectPath) = service
        .call("OpenSession", &("plain", Value::from("")))
        .await
        .unwrap();
    let canonical = zbus::Proxy::new(
        &conn,
        SERVICE_NAME,
        "/org/freedesktop/secrets/collection/session",
        COLLECTION_IFACE,
    )
    .await
    .unwrap();
    let alias = zbus::Proxy::new(
        &conn,
        SERVICE_NAME,
        "/org/freedesktop/secrets/aliases/session",
        COLLECTION_IFACE,
    )
    .await
    .unwrap();
    let before: u64 = canonical.get_property("Modified").await.unwrap();
    assert_eq!(alias.get_property::<u64>("Modified").await.unwrap(), before);
    let canonical_properties = zbus::Proxy::new(
        &conn,
        SERVICE_NAME,
        canonical.path().to_owned(),
        PROPERTIES_IFACE,
    )
    .await
    .unwrap();
    let alias_properties = zbus::Proxy::new(
        &conn,
        SERVICE_NAME,
        alias.path().to_owned(),
        PROPERTIES_IFACE,
    )
    .await
    .unwrap();
    let mut canonical_changes = std::pin::pin!(
        canonical_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let mut alias_changes = std::pin::pin!(
        alias_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let mut service_changes =
        std::pin::pin!(service.receive_signal("CollectionChanged").await.unwrap());
    // One wait establishes a distinct timestamp; every step still requires its own notification.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let secret = Secret {
        session,
        parameters: Vec::new(),
        value: Zeroizing::new(b"test secret".to_vec()),
        content_type: "text/plain".into(),
    };
    let mut path = OwnedObjectPath::try_from("/").unwrap();
    for step in 0..6 {
        let item = zbus::Proxy::new(&conn, SERVICE_NAME, path.clone(), ITEM_IFACE)
            .await
            .unwrap();
        let next_path = mutate_item(&canonical, &item, &secret, step).await;
        if step == 1 {
            assert_eq!(next_path, path, "replacement must keep item path");
        }
        path = next_path;
        let mut timestamps = Vec::new();
        for stream in [canonical_changes.as_mut(), alias_changes.as_mut()] {
            let mut stream = stream;
            loop {
                let (name, value) = next_property_change(stream.as_mut(), COLLECTION_IFACE).await;
                if name == "Modified" {
                    timestamps.push(u64::try_from(value).unwrap());
                    break;
                }
                assert_eq!(name, "Items");
            }
        }
        assert_eq!(timestamps[0], timestamps[1]);
        assert!(timestamps[0] > before);
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if canonical.get_property::<u64>("Modified").await.unwrap() == timestamps[0]
                    && alias.get_property::<u64>("Modified").await.unwrap() == timestamps[0]
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("collection property caches did not update");
        let message =
            tokio::time::timeout(Duration::from_secs(2), next_event(service_changes.as_mut()))
                .await
                .unwrap()
                .unwrap();
        let (changed,): (OwnedObjectPath,) = message.body().deserialize().unwrap();
        assert_eq!(changed.as_str(), canonical.path().as_str());
    }
}
