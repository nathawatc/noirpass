use std::collections::HashMap;

use noirpass::service::session::Secret as WireSecret;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zeroize::Zeroizing;

use super::super::harness::harness;
use super::super::helpers::{
    COLLECTION_IFACE, INVALID_ARGS_ERROR, ITEM_IFACE, PROPERTIES_IFACE, SERVICE_NAME, SERVICE_PATH,
    assert_invalid_item_create, assert_method_error, assert_no_signal, attrs,
    collection_properties, item_properties, service_proxy,
};

/// Scenario 15: malformed known properties fail before collection or item
/// mutation, encryption, object registration, and notification.
#[allow(
    clippy::too_many_lines,
    reason = "one private-bus scenario covers malformed collection and item properties"
)]
pub(super) async fn s15_malformed_known_properties() {
    let h = harness();
    let conn = zbus::Connection::session().await.unwrap();
    let service = service_proxy(&conn).await;
    let service_properties = zbus::Proxy::new(&conn, SERVICE_NAME, SERVICE_PATH, PROPERTIES_IFACE)
        .await
        .unwrap();

    // Wrong collection Label must not create collection or alias.
    let collections_before: Vec<OwnedObjectPath> =
        service.get_property("Collections").await.unwrap();
    let wrong_collection_label = HashMap::from([(
        "org.freedesktop.Secret.Collection.Label".to_string(),
        Value::from(vec![1_u8, 2]).try_to_owned().unwrap(),
    )]);
    let mut collection_created =
        std::pin::pin!(service.receive_signal("CollectionCreated").await.unwrap());
    let mut collections_changed = std::pin::pin!(
        service_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let err = service
        .call::<_, _, (OwnedObjectPath, OwnedObjectPath)>(
            "CreateCollection",
            &(&wrong_collection_label, "s15-malformed-new"),
        )
        .await
        .unwrap_err();
    assert_method_error(&err, INVALID_ARGS_ERROR);
    assert_eq!(
        service
            .call::<_, _, OwnedObjectPath>("ReadAlias", &("s15-malformed-new",))
            .await
            .unwrap()
            .as_str(),
        "/"
    );
    assert_eq!(
        service
            .get_property::<Vec<OwnedObjectPath>>("Collections")
            .await
            .unwrap(),
        collections_before
    );
    assert_no_signal(
        collection_created.as_mut(),
        "CollectionCreated for malformed Label",
    )
    .await;
    assert_no_signal(
        collections_changed.as_mut(),
        "Collections change for malformed Label",
    )
    .await;

    // Establish existing alias state, then reject malformed Label without
    // changing its label, timestamp, target, membership, or signals.
    let (existing_path, _): (OwnedObjectPath, OwnedObjectPath) = service
        .call(
            "CreateCollection",
            &(
                collection_properties(Some("s15-existing-label")),
                "s15-existing-alias",
            ),
        )
        .await
        .unwrap();
    let existing = zbus::Proxy::new(&conn, SERVICE_NAME, existing_path.clone(), COLLECTION_IFACE)
        .await
        .unwrap();
    let existing_properties =
        zbus::Proxy::new(&conn, SERVICE_NAME, existing_path.clone(), PROPERTIES_IFACE)
            .await
            .unwrap();
    let label_before: String = existing.get_property("Label").await.unwrap();
    let modified_before: u64 = existing.get_property("Modified").await.unwrap();
    let items_before: Vec<OwnedObjectPath> = existing.get_property("Items").await.unwrap();
    let alias_before: OwnedObjectPath = service
        .call("ReadAlias", &("s15-existing-alias",))
        .await
        .unwrap();
    let collections_before = service
        .get_property::<Vec<OwnedObjectPath>>("Collections")
        .await
        .unwrap();
    let mut existing_properties_changed = std::pin::pin!(
        existing_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let mut collection_changed_signal =
        std::pin::pin!(service.receive_signal("CollectionChanged").await.unwrap());
    let mut collection_created =
        std::pin::pin!(service.receive_signal("CollectionCreated").await.unwrap());
    let mut collections_changed = std::pin::pin!(
        service_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let err = service
        .call::<_, _, (OwnedObjectPath, OwnedObjectPath)>(
            "CreateCollection",
            &(&wrong_collection_label, "s15-existing-alias"),
        )
        .await
        .unwrap_err();
    assert_method_error(&err, INVALID_ARGS_ERROR);
    assert_eq!(
        existing.get_property::<String>("Label").await.unwrap(),
        label_before
    );
    assert_eq!(
        existing.get_property::<u64>("Modified").await.unwrap(),
        modified_before
    );
    assert_eq!(
        existing
            .get_property::<Vec<OwnedObjectPath>>("Items")
            .await
            .unwrap(),
        items_before
    );
    assert_eq!(
        service
            .call::<_, _, OwnedObjectPath>("ReadAlias", &("s15-existing-alias",))
            .await
            .unwrap(),
        alias_before
    );
    assert_eq!(
        service
            .get_property::<Vec<OwnedObjectPath>>("Collections")
            .await
            .unwrap(),
        collections_before
    );
    assert_no_signal(
        existing_properties_changed.as_mut(),
        "collection PropertiesChanged for malformed Label",
    )
    .await;
    assert_no_signal(
        collection_changed_signal.as_mut(),
        "CollectionChanged for malformed Label",
    )
    .await;
    assert_no_signal(
        collection_created.as_mut(),
        "CollectionCreated for malformed existing-alias Label",
    )
    .await;
    assert_no_signal(
        collections_changed.as_mut(),
        "Collections change for malformed existing-alias Label",
    )
    .await;

    // Open valid plain session and create baseline item for replacement checks.
    let (_, session): (OwnedValue, OwnedObjectPath) = service
        .call("OpenSession", &("plain", Value::from("")))
        .await
        .unwrap();
    let item_attributes = attrs("s15-replace").into_iter().collect::<HashMap<_, _>>();
    let baseline_properties = item_properties("s15-baseline", "s15-replace");
    let baseline_secret = WireSecret {
        session: session.clone(),
        parameters: Vec::new(),
        value: Zeroizing::new(b"s15-baseline-secret".to_vec()),
        content_type: "text/plain".to_string(),
    };
    let (item_path, _): (OwnedObjectPath, OwnedObjectPath) = existing
        .call(
            "CreateItem",
            &(&baseline_properties, &baseline_secret, false),
        )
        .await
        .unwrap();
    let item = zbus::Proxy::new(&conn, SERVICE_NAME, item_path.clone(), ITEM_IFACE)
        .await
        .unwrap();
    let item_properties_proxy =
        zbus::Proxy::new(&conn, SERVICE_NAME, item_path.clone(), PROPERTIES_IFACE)
            .await
            .unwrap();
    let existing_items_before = vec![item_path.clone()];
    let item_label_before: String = item.get_property("Label").await.unwrap();
    let item_modified_before: u64 = item.get_property("Modified").await.unwrap();
    let gpg_before = std::fs::read_to_string(&h.fake_gpg_log).unwrap_or_default();

    // Wrong Item Label must not replace an existing matching item.
    let wrong_item_label = HashMap::from([
        (
            "org.freedesktop.Secret.Item.Label".to_string(),
            Value::from(vec![3_u8]).try_to_owned().unwrap(),
        ),
        (
            "org.freedesktop.Secret.Item.Attributes".to_string(),
            Value::from(item_attributes.clone()).try_to_owned().unwrap(),
        ),
    ]);
    assert_invalid_item_create(
        &existing,
        &existing_properties,
        &item_properties_proxy,
        &wrong_item_label,
        &baseline_secret,
        true,
    )
    .await;
    assert_eq!(
        existing
            .get_property::<Vec<OwnedObjectPath>>("Items")
            .await
            .unwrap(),
        existing_items_before
    );
    assert_eq!(
        item.get_property::<String>("Label").await.unwrap(),
        item_label_before
    );
    assert_eq!(
        item.get_property::<u64>("Modified").await.unwrap(),
        item_modified_before
    );
    assert_eq!(
        std::fs::read_to_string(&h.fake_gpg_log).unwrap_or_default(),
        gpg_before
    );

    // Wrong Item Attributes must not create an item.
    let wrong_item_attributes = HashMap::from([
        (
            "org.freedesktop.Secret.Item.Label".to_string(),
            Value::from("s15-invalid-attributes")
                .try_to_owned()
                .unwrap(),
        ),
        (
            "org.freedesktop.Secret.Item.Attributes".to_string(),
            Value::from("not-a-dict").try_to_owned().unwrap(),
        ),
    ]);
    assert_invalid_item_create(
        &existing,
        &existing_properties,
        &item_properties_proxy,
        &wrong_item_attributes,
        &baseline_secret,
        true,
    )
    .await;
    assert_eq!(
        existing
            .get_property::<Vec<OwnedObjectPath>>("Items")
            .await
            .unwrap(),
        existing_items_before
    );
    assert_eq!(
        std::fs::read_to_string(&h.fake_gpg_log).unwrap_or_default(),
        gpg_before
    );

    // Absent known properties retain empty defaults.
    let empty_properties: HashMap<String, OwnedValue> = HashMap::new();
    let default_secret = WireSecret {
        session,
        parameters: Vec::new(),
        value: Zeroizing::new(b"s15-default-secret".to_vec()),
        content_type: "text/plain".to_string(),
    };
    let (default_item_path, _): (OwnedObjectPath, OwnedObjectPath) = existing
        .call("CreateItem", &(&empty_properties, &default_secret, false))
        .await
        .unwrap();
    let default_item = zbus::Proxy::new(&conn, SERVICE_NAME, default_item_path, ITEM_IFACE)
        .await
        .unwrap();
    assert_eq!(
        default_item.get_property::<String>("Label").await.unwrap(),
        ""
    );
    assert_eq!(
        default_item
            .get_property::<HashMap<String, String>>("Attributes")
            .await
            .unwrap(),
        HashMap::new()
    );

    existing
        .call::<_, _, OwnedObjectPath>("Delete", &())
        .await
        .unwrap();
}
