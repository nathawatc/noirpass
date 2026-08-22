use std::collections::HashMap;

use noirpass::service::session::Secret as WireSecret;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zeroize::Zeroizing;

use super::super::super::helpers::{
    COLLECTION_IFACE, NO_SESSION_ERROR, SERVICE_NAME, UNKNOWN_OBJECT_ERROR, assert_method_error,
    attrs, service_proxy,
};

async fn assert_foreign_item_operations_rejected(
    attacker: &zbus::Connection,
    collection_path: &OwnedObjectPath,
    item_path: &OwnedObjectPath,
    session: &OwnedObjectPath,
) {
    let attacker_item = zbus::Proxy::new(
        attacker,
        SERVICE_NAME,
        item_path.clone(),
        "org.freedesktop.Secret.Item",
    )
    .await
    .unwrap();
    let err = attacker_item
        .call::<_, _, (WireSecret,)>("GetSecret", &(&session,))
        .await
        .unwrap_err();
    assert_method_error(&err, NO_SESSION_ERROR);

    let foreign_secret = WireSecret {
        session: session.clone(),
        parameters: Vec::new(),
        value: Zeroizing::new(b"foreign session value".to_vec()),
        content_type: "text/plain".to_string(),
    };
    let err = attacker_item
        .call::<_, _, ()>("SetSecret", &(&foreign_secret,))
        .await
        .unwrap_err();
    assert_method_error(&err, NO_SESSION_ERROR);

    let attacker_collection = zbus::Proxy::new(
        attacker,
        SERVICE_NAME,
        collection_path.clone(),
        COLLECTION_IFACE,
    )
    .await
    .unwrap();
    let properties: HashMap<String, OwnedValue> = HashMap::new();
    let err = attacker_collection
        .call::<_, _, (OwnedObjectPath, OwnedObjectPath)>(
            "CreateItem",
            &(&properties, &foreign_secret, false),
        )
        .await
        .unwrap_err();
    assert_method_error(&err, NO_SESSION_ERROR);
}

/// Scenario 6b: session handles belong only to opening D-Bus sender.
pub(in super::super) async fn s6b_cross_client_session_rejected() {
    let service = oo7::dbus::Service::encrypted().await.unwrap();
    let collection = service.default_collection().await.unwrap();
    let collection_path = OwnedObjectPath::from(collection.path().to_owned());
    let item = collection
        .create_item(
            "s6b-label",
            &attrs("s6b"),
            oo7::Secret::text("isolated session value"),
            true,
            None,
        )
        .await
        .unwrap();
    let item_path = OwnedObjectPath::from(item.path().to_owned());

    let owner = zbus::Connection::session().await.unwrap();
    let attacker = zbus::Connection::session().await.unwrap();
    assert_ne!(owner.unique_name(), attacker.unique_name());
    let owner_service = service_proxy(&owner).await;
    let attacker_service = service_proxy(&attacker).await;
    let (_, session): (OwnedValue, OwnedObjectPath) = owner_service
        .call("OpenSession", &("plain", Value::from("")))
        .await
        .unwrap();

    let owner_item = zbus::Proxy::new(
        &owner,
        SERVICE_NAME,
        item_path.clone(),
        "org.freedesktop.Secret.Item",
    )
    .await
    .unwrap();
    let _: (WireSecret,) = owner_item
        .call("GetSecret", &(&session,))
        .await
        .expect("session owner must retrieve item");

    assert_foreign_item_operations_rejected(&attacker, &collection_path, &item_path, &session)
        .await;

    let requested_items = vec![item_path.clone()];
    let err = attacker_service
        .call::<_, _, HashMap<OwnedObjectPath, WireSecret>>(
            "GetSecrets",
            &(&requested_items, &session),
        )
        .await
        .unwrap_err();
    assert_method_error(&err, NO_SESSION_ERROR);

    let attacker_session = zbus::Proxy::new(
        &attacker,
        SERVICE_NAME,
        session.clone(),
        "org.freedesktop.Secret.Session",
    )
    .await
    .unwrap();
    let err = attacker_session
        .call::<_, _, ()>("Close", &())
        .await
        .unwrap_err();
    assert_method_error(&err, NO_SESSION_ERROR);

    let secrets: HashMap<OwnedObjectPath, WireSecret> = owner_service
        .call("GetSecrets", &(&requested_items, &session))
        .await
        .unwrap();
    assert_eq!(secrets.len(), 1, "owner's session must remain usable");

    let owner_session = zbus::Proxy::new(
        &owner,
        SERVICE_NAME,
        session.clone(),
        "org.freedesktop.Secret.Session",
    )
    .await
    .unwrap();
    owner_session.call::<_, _, ()>("Close", &()).await.unwrap();
    let err = owner_session
        .call::<_, _, ()>("Close", &())
        .await
        .unwrap_err();
    assert_method_error(&err, UNKNOWN_OBJECT_ERROR);
    let closed = owner_service
        .call::<_, _, HashMap<OwnedObjectPath, WireSecret>>(
            "GetSecrets",
            &(&requested_items, &session),
        )
        .await
        .unwrap_err();
    assert_method_error(&closed, NO_SESSION_ERROR);
    item.delete(None).await.unwrap();
}
