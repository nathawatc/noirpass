use std::collections::HashMap;

use noirpass::service::session::Secret as WireSecret;
use zbus::{OwnedObjectPath, OwnedVariant, Variant};
use zeroize::Zeroizing;

use super::super::super::helpers::{
    COLLECTION_IFACE, INVALID_ARGS_ERROR, SERVICE_NAME, assert_method_error, collection_properties,
    service_proxy,
};

/// Scenario 3: strict `plain` session and Secret parameter validation.
#[allow(
    clippy::too_many_lines,
    reason = "one private-bus scenario covers strict session and Secret validation"
)]
pub(in super::super) async fn s3_plain_protocol_validation() {
    let conn = zbus::Connection::session().await.unwrap();
    let service = service_proxy(&conn).await;

    let (output, session): (OwnedVariant, OwnedObjectPath) = service
        .call("OpenSession", &("plain", Variant::from("")))
        .await
        .unwrap();
    assert_eq!(String::try_from(output).unwrap(), "");

    let err = service
        .call::<_, _, (OwnedVariant, OwnedObjectPath)>(
            "OpenSession",
            &("plain", Variant::from("non-empty")),
        )
        .await
        .unwrap_err();
    assert_method_error(&err, INVALID_ARGS_ERROR);

    let err = service
        .call::<_, _, (OwnedVariant, OwnedObjectPath)>(
            "OpenSession",
            &("plain", Variant::from(vec![1_u8])),
        )
        .await
        .unwrap_err();
    assert_method_error(&err, INVALID_ARGS_ERROR);

    let (collection_path, prompt): (OwnedObjectPath, OwnedObjectPath) = service
        .call(
            "CreateCollection",
            &(collection_properties(Some("s3-plain-protocol")), ""),
        )
        .await
        .unwrap();
    assert_eq!(prompt.as_str(), "/");
    let collection = zbus::Proxy::new(&conn, SERVICE_NAME, collection_path, COLLECTION_IFACE)
        .await
        .unwrap();

    let item_properties = HashMap::from([(
        "org.freedesktop.Secret.Item.Label".to_string(),
        Variant::from("s3-initial").try_to_owned().unwrap(),
    )]);
    let initial_secret = WireSecret {
        session: session.clone(),
        parameters: Vec::new(),
        value: Zeroizing::new(b"initial secret".to_vec()),
        content_type: "text/plain".to_string(),
    };
    let (item_path, prompt): (OwnedObjectPath, OwnedObjectPath) = collection
        .call("CreateItem", &(&item_properties, &initial_secret, false))
        .await
        .unwrap();
    assert_eq!(prompt.as_str(), "/");

    let item = zbus::Proxy::new(
        &conn,
        SERVICE_NAME,
        item_path.clone(),
        "org.freedesktop.Secret.Item",
    )
    .await
    .unwrap();
    let (before,): (WireSecret,) = item.call("GetSecret", &(&session,)).await.unwrap();
    assert_eq!(before.parameters.len(), 0);
    assert_eq!(before.value.as_slice(), b"initial secret");

    let rejected_update = WireSecret {
        session: session.clone(),
        parameters: vec![1_u8],
        value: Zeroizing::new(b"must not replace".to_vec()),
        content_type: "text/custom".to_string(),
    };
    let err = item
        .call::<_, _, ()>("SetSecret", &(&rejected_update,))
        .await
        .unwrap_err();
    assert_method_error(&err, INVALID_ARGS_ERROR);

    let (after,): (WireSecret,) = item.call("GetSecret", &(&session,)).await.unwrap();
    assert_eq!(after, before);

    let before_items: Vec<OwnedObjectPath> = collection.get_property("Items").await.unwrap();
    assert_eq!(before_items, vec![item_path.clone()]);
    let rejected_create = WireSecret {
        session: session.clone(),
        parameters: vec![2_u8],
        value: Zeroizing::new(b"must not create".to_vec()),
        content_type: "text/plain".to_string(),
    };
    let empty_properties: HashMap<String, OwnedVariant> = HashMap::new();
    let err = collection
        .call::<_, _, (OwnedObjectPath, OwnedObjectPath)>(
            "CreateItem",
            &(&empty_properties, &rejected_create, false),
        )
        .await
        .unwrap_err();
    assert_method_error(&err, INVALID_ARGS_ERROR);
    let after_items: Vec<OwnedObjectPath> = collection.get_property("Items").await.unwrap();
    assert_eq!(after_items, before_items);

    item.call::<_, _, OwnedObjectPath>("Delete", &())
        .await
        .unwrap();
    collection
        .call::<_, _, OwnedObjectPath>("Delete", &())
        .await
        .unwrap();
    let session_proxy = zbus::Proxy::new(
        &conn,
        SERVICE_NAME,
        session,
        "org.freedesktop.Secret.Session",
    )
    .await
    .unwrap();
    session_proxy.call::<_, _, ()>("Close", &()).await.unwrap();
}
