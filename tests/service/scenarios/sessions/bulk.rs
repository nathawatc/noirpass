use std::collections::HashMap;

use noirpass::crypto::DhHandshake;
use noirpass::service::session::Secret as WireSecret;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

use super::super::super::helpers::{
    NO_SESSION_ERROR, SERVICE_NAME, UNKNOWN_OBJECT_ERROR, assert_method_error, service_proxy,
};

/// Scenario 6: bulk `GetSecrets` under both session algorithms, plus the
/// `NoSession` error for an unknown session path.
pub(in super::super) async fn s6_get_secrets_bulk() {
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
