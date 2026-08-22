use super::super::super::helpers::attrs;

/// Scenario 1: encrypted (DH) session roundtrip through oo7.
pub(in super::super) async fn s1_encrypted_roundtrip() {
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
pub(in super::super) async fn s2_plain_roundtrip() {
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
