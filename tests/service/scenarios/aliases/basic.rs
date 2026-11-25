use zbus::OwnedObjectPath;

use super::super::super::helpers::service_proxy;

/// Scenario 4: alias handling, including the raw `/` conventions.
pub(in super::super) async fn s4_aliases() {
    let service = oo7::dbus::Service::plain().await.unwrap();
    let collection = service
        .create_collection("s4-col", None, None)
        .await
        .unwrap();
    let col_path = OwnedObjectPath::from(collection.path().to_owned());

    let conn = zbus::Connection::session().await.unwrap();
    let proxy = service_proxy(&conn).await;

    // Unknown alias reads as "/".
    let unknown: OwnedObjectPath = proxy.call("ReadAlias", &("s4-alias",)).await.unwrap();
    assert_eq!(unknown.as_str(), "/");

    // Set → resolves; set "/" → removed.
    proxy
        .call::<_, _, ()>("SetAlias", &("s4-alias", &col_path))
        .await
        .unwrap();
    let resolved: OwnedObjectPath = proxy.call("ReadAlias", &("s4-alias",)).await.unwrap();
    assert_eq!(resolved, col_path);

    let root = OwnedObjectPath::try_from("/").unwrap();
    proxy
        .call::<_, _, ()>("SetAlias", &("s4-alias", &root))
        .await
        .unwrap();
    let removed: OwnedObjectPath = proxy.call("ReadAlias", &("s4-alias",)).await.unwrap();
    assert_eq!(removed.as_str(), "/");

    // Aliasing a non-existent collection is NoSuchObject.
    let bogus =
        OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/doesnotexist").unwrap();
    let err = proxy
        .call::<_, _, ()>("SetAlias", &("s4-alias", &bogus))
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("NoSuchObject"),
        "unexpected error: {err}"
    );

    collection.delete(None).await.unwrap();
}
