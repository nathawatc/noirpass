use std::collections::HashMap;

use noirpass::crypto::DhHandshake;
use noirpass::service::session::Secret as WireSecret;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zeroize::Zeroizing;

use super::super::helpers::{
    COLLECTION_IFACE, NO_SESSION_ERROR, SERVICE_NAME, UNKNOWN_OBJECT_ERROR, assert_method_error,
    attrs, collection_properties, service_proxy,
};

/// Scenario 1: encrypted (DH) session roundtrip through oo7.
pub(super) async fn s1_encrypted_roundtrip() {
    let service = oo7::dbus::Service::encrypted().await.expect("encrypted");
    let collection = service.default_collection().await.expect("default");

    let a = attrs("s1");
    let item = collection
        .create_item("s1-label", &a, oo7::Secret::text("s1 secret"), true, None)
        .await
        .expect("create_item");

    assert_eq!(item.label().await.unwrap(), "s1-label");
    assert!(!item.is_locked().await.unwrap());
    assert_eq!(item.secret().await.unwrap().as_bytes(), b"s1 secret");

    let found = collection.search_items(&a).await.unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].secret().await.unwrap().as_bytes(), b"s1 secret");

    item.delete(None).await.unwrap();
    assert!(collection.search_items(&a).await.unwrap().is_empty());
}

/// Scenario 2: plain session roundtrip through oo7.
pub(super) async fn s2_plain_roundtrip() {
    let service = oo7::dbus::Service::plain().await.expect("plain");
    let collection = service.default_collection().await.expect("default");

    let a = attrs("s2");
    let item = collection
        .create_item("s2-label", &a, oo7::Secret::text("s2 secret"), true, None)
        .await
        .expect("create_item");
    assert_eq!(item.secret().await.unwrap().as_bytes(), b"s2 secret");
    item.delete(None).await.unwrap();
}

/// Scenario 3: strict `plain` session and Secret parameter validation.
#[allow(
    clippy::too_many_lines,
    reason = "one private-bus scenario covers strict session and Secret validation"
)]
pub(super) async fn s3_plain_protocol_validation() {
    let conn = zbus::Connection::session().await.unwrap();
    let service = service_proxy(&conn).await;

    let (output, session): (OwnedValue, OwnedObjectPath) = service
        .call("OpenSession", &("plain", Value::from("")))
        .await
        .unwrap();
    assert_eq!(String::try_from(output).unwrap(), "");

    let err = service
        .call::<_, _, (OwnedValue, OwnedObjectPath)>(
            "OpenSession",
            &("plain", Value::from("non-empty")),
        )
        .await
        .unwrap_err();
    assert_method_error(&err, super::super::helpers::INVALID_ARGS_ERROR);

    let err = service
        .call::<_, _, (OwnedValue, OwnedObjectPath)>(
            "OpenSession",
            &("plain", Value::from(vec![1_u8])),
        )
        .await
        .unwrap_err();
    assert_method_error(&err, super::super::helpers::INVALID_ARGS_ERROR);

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
        Value::from("s3-initial").try_to_owned().unwrap(),
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
    assert!(before.parameters.is_empty());
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
    assert_method_error(&err, super::super::helpers::INVALID_ARGS_ERROR);

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
    let empty_properties: HashMap<String, OwnedValue> = HashMap::new();
    let err = collection
        .call::<_, _, (OwnedObjectPath, OwnedObjectPath)>(
            "CreateItem",
            &(&empty_properties, &rejected_create, false),
        )
        .await
        .unwrap_err();
    assert_method_error(&err, super::super::helpers::INVALID_ARGS_ERROR);
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

/// Scenario 6: bulk `GetSecrets` under both session algorithms, plus the
/// `NoSession` error for an unknown session path.
pub(super) async fn s6_get_secrets_bulk() {
    let service = oo7::dbus::Service::encrypted().await.unwrap();
    let collection = service.default_collection().await.unwrap();

    let mut paths = Vec::new();
    let mut expected = HashMap::new();
    for idx in 1..=3u8 {
        let a = vec![
            ("case".to_string(), "s6".to_string()),
            ("idx".to_string(), idx.to_string()),
        ];
        let secret = format!("s6 secret {idx}");
        let item = collection
            .create_item(
                &format!("s6-{idx}"),
                &a,
                oo7::Secret::text(&secret),
                true,
                None,
            )
            .await
            .unwrap();
        let path = OwnedObjectPath::from(item.path().to_owned());
        expected.insert(path.clone(), secret.into_bytes());
        paths.push(path);
    }

    let conn = zbus::Connection::session().await.unwrap();
    let proxy = service_proxy(&conn).await;

    // Plain session: values come back as raw plaintext.
    let (_, plain_session): (OwnedValue, OwnedObjectPath) = proxy
        .call("OpenSession", &("plain", Value::from("")))
        .await
        .unwrap();
    let secrets: HashMap<OwnedObjectPath, WireSecret> = proxy
        .call("GetSecrets", &(&paths, &plain_session))
        .await
        .unwrap();
    assert_eq!(secrets.len(), 3);
    for (path, secret) in &secrets {
        assert!(secret.parameters.is_empty());
        assert_eq!(secret.value.as_slice(), expected[path].as_slice());
        assert_eq!(secret.content_type, "text/plain");
    }

    // A mismatched collection component must not resolve by item id alone.
    let (_, item_id) = noirpass::service::parse_item_path(paths[0].as_str()).unwrap();
    let mismatched_path = OwnedObjectPath::try_from(format!(
        "/org/freedesktop/secrets/collection/not_the_owner/{item_id}"
    ))
    .unwrap();
    let mismatched_paths = vec![mismatched_path];
    let mismatched: HashMap<OwnedObjectPath, WireSecret> = proxy
        .call("GetSecrets", &(&mismatched_paths, &plain_session))
        .await
        .unwrap();
    assert!(mismatched.is_empty());

    // DH session: drive the client side with the library's own handshake.
    let client = DhHandshake::generate();
    let (server_pub, dh_session): (OwnedValue, OwnedObjectPath) = proxy
        .call(
            "OpenSession",
            &(
                "dh-ietf1024-sha256-aes128-cbc-pkcs7",
                Value::from(client.public_bytes()),
            ),
        )
        .await
        .unwrap();
    let server_pub = Vec::<u8>::try_from(server_pub).unwrap();
    let cipher = client.derive(&server_pub).unwrap();
    let secrets: HashMap<OwnedObjectPath, WireSecret> = proxy
        .call("GetSecrets", &(&paths, &dh_session))
        .await
        .unwrap();
    assert_eq!(secrets.len(), 3);
    for (path, secret) in &secrets {
        let plaintext = cipher
            .decrypt(&secret.parameters, secret.value.as_slice())
            .unwrap();
        assert_eq!(&plaintext[..], &expected[path][..]);
    }

    // Unknown session → org.freedesktop.Secret.Error.NoSession.
    let ghost = OwnedObjectPath::try_from("/org/freedesktop/secrets/session/s999999").unwrap();
    let err = proxy
        .call::<_, _, HashMap<OwnedObjectPath, WireSecret>>("GetSecrets", &(&paths, &ghost))
        .await
        .unwrap_err();
    assert_method_error(&err, NO_SESSION_ERROR);

    let ghost_proxy =
        zbus::Proxy::new(&conn, SERVICE_NAME, ghost, "org.freedesktop.Secret.Session")
            .await
            .unwrap();
    let err = ghost_proxy
        .call::<_, _, ()>("Close", &())
        .await
        .unwrap_err();
    assert_method_error(&err, UNKNOWN_OBJECT_ERROR);

    delete_items(paths).await;
}

async fn delete_items(paths: Vec<OwnedObjectPath>) {
    for path in paths {
        let conn = zbus::Connection::session().await.unwrap();
        let proxy = zbus::Proxy::new(&conn, SERVICE_NAME, path, "org.freedesktop.Secret.Item")
            .await
            .unwrap();
        let _: OwnedObjectPath = proxy.call("Delete", &()).await.unwrap();
    }
}

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
pub(super) async fn s6b_cross_client_session_rejected() {
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
