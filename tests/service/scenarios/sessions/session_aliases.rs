use std::{collections::HashMap, time::Duration};

use noirpass::service::alias_path;
use noirpass::service::session::Secret;
use zbus::{OwnedObjectPath, OwnedVariant, Variant};
use zeroize::Zeroizing;

use super::super::super::harness::harness;
use super::super::super::helpers::{
    COLLECTION_IFACE, ITEM_IFACE, PROPERTIES_IFACE, SERVICE_NAME, UNKNOWN_OBJECT_ERROR,
    assert_method_error, collection_properties, next_invalidated_properties, next_property_change,
    service_proxy,
};

async fn assert_retargeted(
    service: &zbus::Proxy<'_>,
    alias: &zbus::Proxy<'_>,
    target: &OwnedObjectPath,
    expected_label: &str,
) {
    let properties = zbus::Proxy::new(
        alias.connection(),
        SERVICE_NAME,
        alias.path().to_owned(),
        PROPERTIES_IFACE,
    )
    .await
    .unwrap();
    let mut invalidated = std::pin::pin!(
        properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    service
        .call::<_, _, ()>("SetAlias", &("s6e_alias", target))
        .await
        .unwrap();
    let mut names = next_invalidated_properties(invalidated.as_mut(), COLLECTION_IFACE).await;
    names.sort();
    assert_eq!(names, ["Created", "Items", "Label", "Modified"]);
    assert_eq!(
        service
            .call::<_, _, OwnedObjectPath>("ReadAlias", &("s6e_alias",))
            .await
            .unwrap(),
        *target
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if alias.get_property::<String>("Label").await.unwrap() == expected_label {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("alias label cache did not follow retargeting");
}

async fn assert_item_notifications(service: &zbus::Proxy<'_>, alias: &zbus::Proxy<'_>) {
    let (_, session): (OwnedVariant, OwnedObjectPath) = service
        .call("OpenSession", &("plain", Variant::from("")))
        .await
        .unwrap();
    let secret = Secret {
        session,
        parameters: Vec::new(),
        value: Zeroizing::new(b"alias-only secret".to_vec()),
        content_type: "text/plain".into(),
    };
    let properties = zbus::Proxy::new(
        alias.connection(),
        SERVICE_NAME,
        alias.path().to_owned(),
        PROPERTIES_IFACE,
    )
    .await
    .unwrap();
    let mut changed = std::pin::pin!(
        properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let (path, _): (OwnedObjectPath, OwnedObjectPath) = alias
        .call(
            "CreateItem",
            &(HashMap::<String, OwnedVariant>::new(), &secret, false),
        )
        .await
        .unwrap();
    let (name, value) = next_property_change(changed.as_mut(), COLLECTION_IFACE).await;
    assert_eq!(name, "Items");
    assert_eq!(
        Vec::<OwnedObjectPath>::try_from(value).unwrap(),
        std::slice::from_ref(&path)
    );
    assert_eq!(
        next_property_change(changed.as_mut(), COLLECTION_IFACE)
            .await
            .0,
        "Modified"
    );
    let item = zbus::Proxy::new(alias.connection(), SERVICE_NAME, path, ITEM_IFACE)
        .await
        .unwrap();
    item.call::<_, _, OwnedObjectPath>("Delete", &())
        .await
        .unwrap();
    let (name, value) = next_property_change(changed.as_mut(), COLLECTION_IFACE).await;
    assert_eq!(name, "Items");
    assert_eq!(Vec::<OwnedObjectPath>::try_from(value).unwrap().len(), 0);
    assert_eq!(
        next_property_change(changed.as_mut(), COLLECTION_IFACE)
            .await
            .0,
        "Modified"
    );
}

/// Temporary aliases resolve, fan out signals, retarget, clear, and disappear at restart.
#[allow(
    clippy::too_many_lines,
    reason = "one private-bus scenario covers the complete temporary alias lifecycle"
)]
pub(in super::super) async fn s6e_session_alias_lifecycle() {
    let conn = zbus::Connection::session().await.unwrap();
    let service = service_proxy(&conn).await;
    let session: OwnedObjectPath = service.call("ReadAlias", &("session",)).await.unwrap();
    let (persisted, _): (OwnedObjectPath, OwnedObjectPath) = service
        .call(
            "CreateCollection",
            &(collection_properties(Some("persistent label")), "s6e_alias"),
        )
        .await
        .unwrap();
    let alias = zbus::Proxy::new(
        &conn,
        SERVICE_NAME,
        alias_path("s6e_alias").unwrap(),
        COLLECTION_IFACE,
    )
    .await
    .unwrap();
    assert_eq!(
        alias.get_property::<String>("Label").await.unwrap(),
        "persistent label"
    );
    assert_retargeted(&service, &alias, &session, "Session").await;
    let properties = zbus::Proxy::new(
        &conn,
        SERVICE_NAME,
        alias.path().to_owned(),
        PROPERTIES_IFACE,
    )
    .await
    .unwrap();
    let mut changed = std::pin::pin!(
        properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let (returned, _): (OwnedObjectPath, OwnedObjectPath) = service
        .call(
            "CreateCollection",
            &(collection_properties(Some("temporary label")), "s6e_alias"),
        )
        .await
        .unwrap();
    assert_eq!(
        returned, session,
        "CreateCollection must reuse the temporary alias target"
    );
    let (name, value) = next_property_change(changed.as_mut(), COLLECTION_IFACE).await;
    assert_eq!(name, "Label");
    assert_eq!(String::try_from(value).unwrap(), "temporary label");
    assert_eq!(
        next_property_change(changed.as_mut(), COLLECTION_IFACE)
            .await
            .0,
        "Modified"
    );
    assert_item_notifications(&service, &alias).await;
    assert_retargeted(&service, &alias, &persisted, "persistent label").await;
    assert_retargeted(&service, &alias, &session, "temporary label").await;
    let root = OwnedObjectPath::try_from("/").unwrap();
    service
        .call::<_, _, ()>("SetAlias", &("s6e_alias", &root))
        .await
        .unwrap();
    assert_eq!(
        service
            .call::<_, _, OwnedObjectPath>("ReadAlias", &("s6e_alias",))
            .await
            .unwrap(),
        root
    );
    let error = properties
        .call::<_, _, OwnedVariant>("Get", &(COLLECTION_IFACE, "Label"))
        .await
        .unwrap_err();
    assert_method_error(&error, UNKNOWN_OBJECT_ERROR);
    service
        .call::<_, _, ()>("SetAlias", &("s6e_alias", &session))
        .await
        .unwrap();
    // Invalid-path aliases remain resolvable through alias methods without an object registration.
    service
        .call::<_, _, ()>("SetAlias", &("s6e-invalid-path", &session))
        .await
        .unwrap();
    assert_eq!(
        service
            .call::<_, _, OwnedObjectPath>("ReadAlias", &("s6e-invalid-path",))
            .await
            .unwrap(),
        session
    );
    let error = service
        .call::<_, _, ()>("SetAlias", &("session", &persisted))
        .await
        .unwrap_err();
    assert_method_error(&error, "org.freedesktop.DBus.Error.NotSupported");
    let error = service
        .call::<_, _, ()>(
            "SetAlias",
            &(
                "s6e_alias",
                OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/missing").unwrap(),
            ),
        )
        .await
        .unwrap_err();
    assert_method_error(&error, "org.freedesktop.Secret.Error.NoSuchObject");
    assert_eq!(
        service
            .call::<_, _, OwnedObjectPath>("ReadAlias", &("s6e_alias",))
            .await
            .unwrap(),
        session
    );
    tokio::task::spawn_blocking(|| {
        let h = harness();
        h.stop_daemon();
        let store = noirpass::store::Store::open(&h.store_dir).unwrap();
        assert!(store.read_alias("s6e_alias").unwrap().is_none());
        assert!(store.read_alias("s6e-invalid-path").unwrap().is_none());
        drop(store);
        h.respawn_daemon();
    })
    .await
    .unwrap();
    let fresh = zbus::Connection::session().await.unwrap();
    let fresh_service = service_proxy(&fresh).await;
    assert_eq!(
        fresh_service
            .call::<_, _, OwnedObjectPath>("ReadAlias", &("s6e_alias",))
            .await
            .unwrap(),
        root
    );
    assert_eq!(
        fresh_service
            .call::<_, _, OwnedObjectPath>("ReadAlias", &("s6e-invalid-path",))
            .await
            .unwrap(),
        root
    );
    assert_eq!(
        fresh_service
            .call::<_, _, OwnedObjectPath>("ReadAlias", &("session",))
            .await
            .unwrap(),
        session
    );
}
