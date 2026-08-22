use super::super::helpers::attrs;

/// Scenario 3: replace semantics — replace=true updates in place,
/// replace=false creates a second item with identical attributes.
pub(super) async fn s3_replace_semantics() {
    let service = oo7::dbus::Service::encrypted().await.unwrap();
    let collection = service.default_collection().await.unwrap();
    let a = attrs("s3");

    let first = collection
        .create_item("s3-one", &a, oo7::Secret::text("v1"), true, None)
        .await
        .unwrap();
    let second = collection
        .create_item("s3-two", &a, oo7::Secret::text("v2"), true, None)
        .await
        .unwrap();
    // Same item path (in-place replace), updated secret and label.
    assert_eq!(first.path(), second.path());
    let found = collection.search_items(&a).await.unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].secret().await.unwrap().as_bytes(), b"v2");
    assert_eq!(found[0].label().await.unwrap(), "s3-two");

    // replace = false with the same attributes creates a distinct item.
    let third = collection
        .create_item("s3-three", &a, oo7::Secret::text("v3"), false, None)
        .await
        .unwrap();
    assert_ne!(third.path(), second.path());
    let found = collection.search_items(&a).await.unwrap();
    assert_eq!(found.len(), 2);

    for item in found {
        item.delete(None).await.unwrap();
    }
}
