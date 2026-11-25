use std::collections::HashMap;
use std::pin::Pin;
use std::time::Duration;

use noirpass::service::session::Secret as WireSecret;
use zbus::export::futures_core::Stream;
use zbus::{OwnedObjectPath, OwnedVariant, Variant};

pub(super) const SERVICE_NAME: &str = "org.freedesktop.secrets";
pub(super) const SERVICE_PATH: &str = "/org/freedesktop/secrets";
pub(super) const SERVICE_IFACE: &str = "org.freedesktop.Secret.Service";
pub(super) const COLLECTION_IFACE: &str = "org.freedesktop.Secret.Collection";
pub(super) const ITEM_IFACE: &str = "org.freedesktop.Secret.Item";
pub(super) const PROPERTIES_IFACE: &str = "org.freedesktop.DBus.Properties";
pub(super) const INVALID_ARGS_ERROR: &str = "org.freedesktop.DBus.Error.InvalidArgs";
pub(super) const NO_SESSION_ERROR: &str = "org.freedesktop.Secret.Error.NoSession";
pub(super) const UNKNOWN_OBJECT_ERROR: &str = "org.freedesktop.DBus.Error.UnknownObject";

/// `StreamExt::next` without a futures-util dependency.
pub(super) async fn next_event<S: Stream>(mut stream: Pin<&mut S>) -> Option<S::Item> {
    std::future::poll_fn(|cx| stream.as_mut().poll_next(cx)).await
}

pub(super) async fn service_proxy(conn: &zbus::Connection) -> zbus::Proxy<'static> {
    zbus::Proxy::new(conn, SERVICE_NAME, SERVICE_PATH, SERVICE_IFACE)
        .await
        .expect("service proxy")
}

pub(super) async fn next_property_change<S>(
    stream: Pin<&mut S>,
    expected_interface: &str,
) -> (String, OwnedVariant)
where
    S: Stream<Item = zbus::Message>,
{
    let message = tokio::time::timeout(Duration::from_secs(10), next_event(stream))
        .await
        .expect("timed out waiting for PropertiesChanged")
        .expect("PropertiesChanged stream ended");
    let (interface, changed, invalidated): (String, HashMap<String, OwnedVariant>, Vec<String>) =
        message.body().deserialize().unwrap();
    assert_eq!(interface, expected_interface);
    assert_eq!(invalidated.len(), 0);
    assert_eq!(changed.len(), 1);
    changed.into_iter().next().unwrap()
}

pub(super) async fn next_invalidated_properties<S>(
    stream: Pin<&mut S>,
    expected_interface: &str,
) -> Vec<String>
where
    S: Stream<Item = zbus::Message>,
{
    let message = tokio::time::timeout(Duration::from_secs(10), next_event(stream))
        .await
        .expect("timed out waiting for invalidated PropertiesChanged")
        .expect("invalidated PropertiesChanged stream ended");
    let (interface, changed, invalidated): (String, HashMap<String, OwnedVariant>, Vec<String>) =
        message.body().deserialize().unwrap();
    assert_eq!(interface, expected_interface);
    assert_eq!(changed.len(), 0);
    invalidated
}

pub(super) async fn next_property_name<S>(stream: Pin<&mut S>) -> String
where
    S: Stream<Item = zbus::Message>,
{
    next_property_change(stream, ITEM_IFACE).await.0
}

pub(super) async fn assert_no_signal<S>(stream: Pin<&mut S>, description: &str)
where
    S: Stream<Item = zbus::Message>,
{
    assert!(
        tokio::time::timeout(Duration::from_millis(250), next_event(stream))
            .await
            .is_err(),
        "unexpected {description}"
    );
}

pub(super) async fn next_item_changed<S>(stream: Pin<&mut S>, expected: &OwnedObjectPath)
where
    S: Stream<Item = zbus::Message>,
{
    let message = tokio::time::timeout(Duration::from_secs(10), next_event(stream))
        .await
        .expect("timed out waiting for ItemChanged")
        .expect("ItemChanged stream ended");
    let (item,): (OwnedObjectPath,) = message.body().deserialize().unwrap();
    assert_eq!(&item, expected);
}

pub(super) async fn locked_property(proxy: &zbus::Proxy<'_>, interface: &str) -> bool {
    let value: OwnedVariant = proxy
        .call::<_, _, OwnedVariant>("Get", &(interface, "Locked"))
        .await
        .expect("Locked property");
    bool::try_from(value).expect("Locked property must be boolean")
}

/// Last path segment = the store id of an item/collection object.
pub(super) fn object_id(path: &str) -> String {
    path.rsplit('/').next().unwrap().to_string()
}

pub(super) fn attrs(case: &str) -> Vec<(String, String)> {
    vec![
        ("app".to_string(), "noirpass-e2e".to_string()),
        ("case".to_string(), case.to_string()),
    ]
}

pub(super) fn collection_properties(label: Option<&str>) -> HashMap<String, OwnedVariant> {
    let Some(label) = label else {
        return HashMap::new();
    };
    HashMap::from([(
        "org.freedesktop.Secret.Collection.Label".to_string(),
        Variant::from(label).try_to_owned().unwrap(),
    )])
}

pub(super) fn item_properties(label: &str, case: &str) -> HashMap<String, OwnedVariant> {
    HashMap::from([
        (
            "org.freedesktop.Secret.Item.Label".to_string(),
            Variant::from(label).try_to_owned().unwrap(),
        ),
        (
            "org.freedesktop.Secret.Item.Attributes".to_string(),
            Variant::from(attrs(case).into_iter().collect::<HashMap<_, _>>())
                .try_to_owned()
                .unwrap(),
        ),
    ])
}

pub(super) fn method_error_name(err: &zbus::Error) -> Option<String> {
    match err {
        zbus::Error::MethodError(name, _, _) => Some(name.as_str().to_owned()),
        zbus::Error::FDO(err) => Some(zbus::DBusError::name(err.as_ref()).as_str().to_owned()),
        _ => None,
    }
}

pub(super) fn assert_method_error(err: &zbus::Error, expected: &str) {
    assert_eq!(
        method_error_name(err).as_deref(),
        Some(expected),
        "expected {expected}, got {err}"
    );
}

pub(super) async fn assert_invalid_item_create(
    collection: &zbus::Proxy<'_>,
    collection_properties: &zbus::Proxy<'_>,
    item_properties: &zbus::Proxy<'_>,
    properties: &HashMap<String, OwnedVariant>,
    secret: &WireSecret,
    replace: bool,
) {
    let mut item_changed = std::pin::pin!(collection.receive_signal("ItemChanged").await.unwrap());
    let mut item_created = std::pin::pin!(collection.receive_signal("ItemCreated").await.unwrap());
    let mut collection_items_changed = std::pin::pin!(
        collection_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let mut item_properties_changed = std::pin::pin!(
        item_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let err = collection
        .call::<_, _, (OwnedObjectPath, OwnedObjectPath)>(
            "CreateItem",
            &(properties, secret, replace),
        )
        .await
        .unwrap_err();
    assert_method_error(&err, INVALID_ARGS_ERROR);
    assert_no_signal(item_changed.as_mut(), "ItemChanged for malformed property").await;
    assert_no_signal(item_created.as_mut(), "ItemCreated for malformed property").await;
    assert_no_signal(
        collection_items_changed.as_mut(),
        "Collection Items change for malformed property",
    )
    .await;
    assert_no_signal(
        item_properties_changed.as_mut(),
        "item PropertiesChanged for malformed property",
    )
    .await;
}
