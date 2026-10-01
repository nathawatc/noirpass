use std::collections::HashMap;

use noirpass::service::{parse_item_path, session::Secret as WireSecret};
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zeroize::Zeroizing;

use super::super::super::harness::harness;
use super::super::super::helpers::{
    COLLECTION_IFACE, ITEM_IFACE, NO_SESSION_ERROR, PROPERTIES_IFACE, SERVICE_NAME,
    assert_method_error, next_item_changed, next_property_change, next_property_name,
    service_proxy,
};

fn item_properties(attributes: &HashMap<String, String>) -> HashMap<String, OwnedValue> {
    HashMap::from([
        (
            "org.freedesktop.Secret.Item.Label".to_string(),
            Value::from("s6c temporary LUKS passphrase")
                .try_to_owned()
                .unwrap(),
        ),
        (
            "org.freedesktop.Secret.Item.Attributes".to_string(),
            Value::from(attributes.clone()).try_to_owned().unwrap(),
        ),
    ])
}

async fn exercise_properties(
    conn: &zbus::Connection,
    collection: &zbus::Proxy<'_>,
    item: &zbus::Proxy<'_>,
    attributes: &HashMap<String, String>,
) {
    let path = OwnedObjectPath::from(item.path().to_owned());
    let properties = zbus::Proxy::new(conn, SERVICE_NAME, path.clone(), PROPERTIES_IFACE)
        .await
        .unwrap();
    let canonical = zbus::Proxy::new(
        conn,
        SERVICE_NAME,
        "/org/freedesktop/secrets/collection/session",
        COLLECTION_IFACE,
    )
    .await
    .unwrap();
    let mut changed = std::pin::pin!(canonical.receive_signal("ItemChanged").await.unwrap());
    let mut properties_changed = std::pin::pin!(
        properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    item.set_property("Label", "temporary renamed")
        .await
        .unwrap();
    assert_eq!(
        next_property_name(properties_changed.as_mut()).await,
        "Label"
    );
    assert_eq!(
        next_property_name(properties_changed.as_mut()).await,
        "Modified"
    );
    next_item_changed(changed.as_mut(), &path).await;
    item.set_property("Attributes", HashMap::from([("changed", "yes")]))
        .await
        .unwrap();
    assert_eq!(
        item.get_property::<HashMap<String, String>>("Attributes")
            .await
            .unwrap(),
        HashMap::from([("changed".into(), "yes".into())])
    );
    item.set_property("Attributes", attributes.clone())
        .await
        .unwrap();
    assert!(!item.get_property::<bool>("Locked").await.unwrap());
    assert!(item.get_property::<u64>("Created").await.unwrap() > 0);
    assert!(item.get_property::<u64>("Modified").await.unwrap() > 0);
    collection.set_property("Label", "Temporary").await.unwrap();
    assert_eq!(
        collection.get_property::<String>("Label").await.unwrap(),
        "Temporary"
    );
}

async fn exercise_temporary_item(
    conn: &zbus::Connection,
    collection: &zbus::Proxy<'_>,
    item: &zbus::Proxy<'_>,
    session: &OwnedObjectPath,
    attributes: &HashMap<String, String>,
) {
    exercise_properties(conn, collection, item, attributes).await;
    let path = OwnedObjectPath::from(item.path().to_owned());
    let service = service_proxy(conn).await;
    let secret = WireSecret {
        session: session.clone(),
        parameters: Vec::new(),
        value: Zeroizing::new(b"replacement".to_vec()),
        content_type: "application/octet-stream".into(),
    };
    item.call::<_, _, ()>("SetSecret", &(&secret,))
        .await
        .unwrap();
    let (roundtrip,): (WireSecret,) = item.call("GetSecret", &(session,)).await.unwrap();
    assert_eq!(roundtrip.value.as_slice(), b"replacement");
    assert_eq!(roundtrip.content_type, secret.content_type);
    let (replacement, _): (OwnedObjectPath, OwnedObjectPath) = collection
        .call("CreateItem", &(item_properties(attributes), &secret, true))
        .await
        .unwrap();
    assert_eq!(replacement, path);
    let found: Vec<OwnedObjectPath> = collection
        .call("SearchItems", &(attributes,))
        .await
        .unwrap();
    assert_eq!(found, std::slice::from_ref(&path));
    let (found, locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) =
        service.call("SearchItems", &(attributes,)).await.unwrap();
    assert_eq!(found, std::slice::from_ref(&path));
    assert!(locked.is_empty());
    let bulk: HashMap<OwnedObjectPath, WireSecret> = service
        .call("GetSecrets", &(&found, session))
        .await
        .unwrap();
    assert_eq!(bulk[&path].value.as_slice(), b"replacement");
    let attacker = zbus::Connection::session().await.unwrap();
    let foreign_item = zbus::Proxy::new(&attacker, SERVICE_NAME, path.clone(), ITEM_IFACE)
        .await
        .unwrap();
    let error = foreign_item
        .call::<_, _, (WireSecret,)>("GetSecret", &(session,))
        .await
        .unwrap_err();
    assert_method_error(&error, NO_SESSION_ERROR);
    let error = foreign_item
        .call::<_, _, ()>("SetSecret", &(&secret,))
        .await
        .unwrap_err();
    assert_method_error(&error, NO_SESSION_ERROR);
    let (after,): (WireSecret,) = item.call("GetSecret", &(session,)).await.unwrap();
    assert_eq!(after.value.as_slice(), b"replacement");
    let (duplicate, _): (OwnedObjectPath, OwnedObjectPath) = collection
        .call("CreateItem", &(item_properties(attributes), &after, false))
        .await
        .unwrap();
    let duplicate_item = zbus::Proxy::new(conn, SERVICE_NAME, duplicate, ITEM_IFACE)
        .await
        .unwrap();
    let alias_properties = zbus::Proxy::new(
        conn,
        SERVICE_NAME,
        collection.path().to_owned(),
        PROPERTIES_IFACE,
    )
    .await
    .unwrap();
    let mut membership_changed = std::pin::pin!(
        alias_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let prompt: OwnedObjectPath = duplicate_item.call("Delete", &()).await.unwrap();
    assert_eq!(prompt.as_str(), "/");
    let (name, value) = next_property_change(membership_changed.as_mut(), COLLECTION_IFACE).await;
    assert_eq!(name, "Items");
    let remaining = Vec::<OwnedObjectPath>::try_from(value).unwrap();
    assert_eq!(remaining, [path]);
}

/// Scenario 6c: the standard `session` alias stores secrets only in daemon
/// memory and loses them when the daemon process ends.
pub(in super::super) async fn s6c_temporary_session_collection() {
    let h = harness();
    let conn = zbus::Connection::session().await.unwrap();
    let service = service_proxy(&conn).await;

    let session_collection: OwnedObjectPath =
        service.call("ReadAlias", &("session",)).await.unwrap();
    assert_eq!(
        session_collection.as_str(),
        "/org/freedesktop/secrets/collection/session"
    );

    let collections: Vec<OwnedObjectPath> = service.get_property("Collections").await.unwrap();
    assert!(collections.contains(&session_collection));

    let (_output, transport_session): (OwnedValue, OwnedObjectPath) = service
        .call("OpenSession", &("plain", Value::from("")))
        .await
        .unwrap();
    let collection = zbus::Proxy::new(
        &conn,
        SERVICE_NAME,
        "/org/freedesktop/secrets/aliases/session",
        COLLECTION_IFACE,
    )
    .await
    .unwrap();

    let attributes = HashMap::from([
        (
            "xdg:schema".to_string(),
            "org.freedesktop.UDisks2.Encrypted".to_string(),
        ),
        ("drive".to_string(), "s6c-luks".to_string()),
    ]);
    let item_properties = item_properties(&attributes);
    let secret = WireSecret {
        session: transport_session.clone(),
        parameters: Vec::new(),
        value: Zeroizing::new(b"temporary passphrase".to_vec()),
        content_type: "text/plain".to_string(),
    };
    let (item_path, prompt): (OwnedObjectPath, OwnedObjectPath) = collection
        .call("CreateItem", &(&item_properties, &secret, true))
        .await
        .unwrap();
    assert_eq!(prompt.as_str(), "/");

    let (_, item_id) = parse_item_path(item_path.as_str()).unwrap();
    assert!(
        !h.store_dir
            .join("secrets")
            .join(format!("{item_id}.gpg"))
            .exists(),
        "temporary session secret must not get a .gpg file"
    );

    let item = zbus::Proxy::new(&conn, SERVICE_NAME, item_path, ITEM_IFACE)
        .await
        .unwrap();
    let (roundtrip,): (WireSecret,) = item
        .call("GetSecret", &(&transport_session,))
        .await
        .unwrap();
    assert_eq!(roundtrip.value.as_slice(), b"temporary passphrase");
    exercise_temporary_item(&conn, &collection, &item, &transport_session, &attributes).await;

    tokio::task::spawn_blocking(move || {
        h.stop_daemon();
        let store = noirpass::store::Store::open(&h.store_dir).unwrap();
        assert!(
            store.get_item(&item_id).is_err(),
            "temporary item must not enter redb"
        );
        drop(store);
        h.respawn_daemon();
    })
    .await
    .unwrap();

    let fresh_conn = zbus::Connection::session().await.unwrap();
    let fresh_service = service_proxy(&fresh_conn).await;
    let fresh_session_collection: OwnedObjectPath = fresh_service
        .call("ReadAlias", &("session",))
        .await
        .unwrap();
    assert_eq!(fresh_session_collection, session_collection);
    let fresh_collection = zbus::Proxy::new(
        &fresh_conn,
        SERVICE_NAME,
        fresh_session_collection,
        COLLECTION_IFACE,
    )
    .await
    .unwrap();
    let found: Vec<OwnedObjectPath> = fresh_collection
        .call("SearchItems", &(&attributes,))
        .await
        .unwrap();
    assert!(
        found.is_empty(),
        "temporary item must not survive daemon restart"
    );
}
