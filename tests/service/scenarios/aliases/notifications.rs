use std::time::Duration;

use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

use super::super::super::helpers::{
    COLLECTION_IFACE, PROPERTIES_IFACE, SERVICE_NAME, SERVICE_PATH, assert_no_signal,
    collection_properties, item_properties, next_event, next_invalidated_properties,
    next_property_change, service_proxy,
};

/// Scenario 14: collection properties and membership stay coherent across
/// canonical and alias object paths, including alias target changes.
#[allow(
    clippy::too_many_lines,
    reason = "one private-bus scenario covers collection and alias notification semantics"
)]
pub(in super::super) async fn s14_collection_alias_notifications() {
    let conn = zbus::Connection::session().await.unwrap();
    let service = service_proxy(&conn).await;

    let (a_path, prompt): (OwnedObjectPath, OwnedObjectPath) = service
        .call(
            "CreateCollection",
            &(collection_properties(Some("s14-a")), "s14_alias"),
        )
        .await
        .unwrap();
    assert_eq!(prompt.as_str(), "/");
    let (b_path, prompt): (OwnedObjectPath, OwnedObjectPath) = service
        .call(
            "CreateCollection",
            &(collection_properties(Some("s14-b")), ""),
        )
        .await
        .unwrap();
    assert_eq!(prompt.as_str(), "/");

    let alias_path = noirpass::service::alias_path("s14_alias").unwrap();
    // Assert current server state; raw signals can precede updates to the proxy cache.
    let canonical = zbus::proxy::Builder::<zbus::Proxy<'_>>::new(&conn)
        .destination(SERVICE_NAME)
        .unwrap()
        .path(a_path.clone())
        .unwrap()
        .interface(COLLECTION_IFACE)
        .unwrap()
        .cache_properties(zbus::proxy::CacheProperties::No)
        .build()
        .await
        .unwrap();
    let alias = zbus::Proxy::new(&conn, SERVICE_NAME, alias_path.clone(), COLLECTION_IFACE)
        .await
        .unwrap();
    let other = zbus::Proxy::new(&conn, SERVICE_NAME, b_path.clone(), COLLECTION_IFACE)
        .await
        .unwrap();
    let canonical_properties =
        zbus::Proxy::new(&conn, SERVICE_NAME, a_path.clone(), PROPERTIES_IFACE)
            .await
            .unwrap();
    let alias_properties =
        zbus::Proxy::new(&conn, SERVICE_NAME, alias_path.clone(), PROPERTIES_IFACE)
            .await
            .unwrap();
    let service_properties = zbus::Proxy::new(&conn, SERVICE_NAME, SERVICE_PATH, PROPERTIES_IFACE)
        .await
        .unwrap();

    // Canonical Label setter fans out Label and Modified exactly once to every
    // served path, then reports the canonical CollectionChanged path.
    let initial_modified: u64 = canonical.get_property("Modified").await.unwrap();
    let _: String = alias.get_property("Label").await.unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let mut canonical_changes = std::pin::pin!(
        canonical_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let mut alias_changes = std::pin::pin!(
        alias_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let mut collection_changed =
        std::pin::pin!(service.receive_signal("CollectionChanged").await.unwrap());
    canonical
        .set_property("Label", "s14-canonical-label")
        .await
        .unwrap();

    let (name, value) = next_property_change(canonical_changes.as_mut(), COLLECTION_IFACE).await;
    assert_eq!(name, "Label");
    assert_eq!(String::try_from(value).unwrap(), "s14-canonical-label");
    let (name, value) = next_property_change(canonical_changes.as_mut(), COLLECTION_IFACE).await;
    assert_eq!(name, "Modified");
    let modified_after: u64 = canonical.get_property("Modified").await.unwrap();
    assert_eq!(u64::try_from(value).unwrap(), modified_after);
    assert!(modified_after > initial_modified);
    assert_no_signal(canonical_changes.as_mut(), "duplicate canonical Label").await;

    let (name, value) = next_property_change(alias_changes.as_mut(), COLLECTION_IFACE).await;
    assert_eq!(name, "Label");
    assert_eq!(String::try_from(value).unwrap(), "s14-canonical-label");
    let (name, _) = next_property_change(alias_changes.as_mut(), COLLECTION_IFACE).await;
    assert_eq!(name, "Modified");
    assert_no_signal(alias_changes.as_mut(), "duplicate alias Label").await;
    assert_eq!(
        alias.get_property::<String>("Label").await.unwrap(),
        "s14-canonical-label"
    );

    let message = tokio::time::timeout(
        Duration::from_secs(10),
        next_event(collection_changed.as_mut()),
    )
    .await
    .expect("timed out waiting for canonical CollectionChanged")
    .expect("canonical CollectionChanged stream ended");
    let (changed_path,): (OwnedObjectPath,) = message.body().deserialize().unwrap();
    assert_eq!(changed_path, a_path);

    // Label setter through alias has identical canonical fanout and signal
    // path semantics.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let mut canonical_changes = std::pin::pin!(
        canonical_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let mut alias_changes = std::pin::pin!(
        alias_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let mut collection_changed =
        std::pin::pin!(service.receive_signal("CollectionChanged").await.unwrap());
    alias
        .set_property("Label", "s14-alias-label")
        .await
        .unwrap();
    for changes in [&mut canonical_changes, &mut alias_changes] {
        let (name, value) = next_property_change(changes.as_mut(), COLLECTION_IFACE).await;
        assert_eq!(name, "Label");
        assert_eq!(String::try_from(value).unwrap(), "s14-alias-label");
        let (name, _) = next_property_change(changes.as_mut(), COLLECTION_IFACE).await;
        assert_eq!(name, "Modified");
        assert_no_signal(changes.as_mut(), "duplicate alias-set Label").await;
    }
    assert_eq!(
        canonical.get_property::<String>("Label").await.unwrap(),
        "s14-alias-label"
    );
    let message = tokio::time::timeout(
        Duration::from_secs(10),
        next_event(collection_changed.as_mut()),
    )
    .await
    .expect("timed out waiting for alias-set CollectionChanged")
    .expect("alias-set CollectionChanged stream ended");
    let (changed_path,): (OwnedObjectPath,) = message.body().deserialize().unwrap();
    assert_eq!(changed_path, a_path);

    // Existing-alias CreateCollection label update reuses same fanout without
    // changing collection membership.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let mut canonical_changes = std::pin::pin!(
        canonical_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let mut alias_changes = std::pin::pin!(
        alias_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let mut collection_changed =
        std::pin::pin!(service.receive_signal("CollectionChanged").await.unwrap());
    let mut collection_created =
        std::pin::pin!(service.receive_signal("CollectionCreated").await.unwrap());
    let mut service_properties_changed = std::pin::pin!(
        service_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let (returned, prompt): (OwnedObjectPath, OwnedObjectPath) = service
        .call(
            "CreateCollection",
            &(
                collection_properties(Some("s14-existing-alias")),
                "s14_alias",
            ),
        )
        .await
        .unwrap();
    assert_eq!(returned, a_path);
    assert_eq!(prompt.as_str(), "/");
    for changes in [&mut canonical_changes, &mut alias_changes] {
        let (name, value) = next_property_change(changes.as_mut(), COLLECTION_IFACE).await;
        assert_eq!(name, "Label");
        assert_eq!(String::try_from(value).unwrap(), "s14-existing-alias");
        let (name, _) = next_property_change(changes.as_mut(), COLLECTION_IFACE).await;
        assert_eq!(name, "Modified");
        assert_no_signal(changes.as_mut(), "duplicate existing-alias Label").await;
    }
    let message = tokio::time::timeout(
        Duration::from_secs(10),
        next_event(collection_changed.as_mut()),
    )
    .await
    .expect("timed out waiting for existing-alias CollectionChanged")
    .expect("existing-alias CollectionChanged stream ended");
    let (changed_path,): (OwnedObjectPath,) = message.body().deserialize().unwrap();
    assert_eq!(changed_path, a_path);
    assert_no_signal(
        collection_created.as_mut(),
        "CollectionCreated for existing alias",
    )
    .await;
    assert_no_signal(
        service_properties_changed.as_mut(),
        "Collections change for existing alias",
    )
    .await;

    // Item membership changes fan out to canonical and alias paths. Replace
    // keeps membership unchanged and therefore emits no Items change.
    let (_, session): (OwnedValue, OwnedObjectPath) = service
        .call("OpenSession", &("plain", Value::from("")))
        .await
        .unwrap();
    let mut initial_items: Vec<OwnedObjectPath> = canonical.get_property("Items").await.unwrap();
    assert_eq!(initial_items.len(), 0);
    initial_items = alias.get_property("Items").await.unwrap();
    assert_eq!(initial_items.len(), 0);

    let first_properties = item_properties("s14-first", "s14-first");
    let first_secret = noirpass::service::session::Secret {
        session: session.clone(),
        parameters: Vec::new(),
        value: zeroize::Zeroizing::new(b"s14-first-secret".to_vec()),
        content_type: "text/plain".to_string(),
    };
    let mut canonical_items_changed = std::pin::pin!(
        canonical_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let mut alias_items_changed = std::pin::pin!(
        alias_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let (first_path, _): (OwnedObjectPath, OwnedObjectPath) = canonical
        .call("CreateItem", &(&first_properties, &first_secret, false))
        .await
        .unwrap();
    for changes in [&mut canonical_items_changed, &mut alias_items_changed] {
        let (name, value) = next_property_change(changes.as_mut(), COLLECTION_IFACE).await;
        assert_eq!(name, "Items");
        assert_eq!(
            Vec::<OwnedObjectPath>::try_from(value).unwrap(),
            vec![first_path.clone()]
        );
        let (name, value) = next_property_change(changes.as_mut(), COLLECTION_IFACE).await;
        assert_eq!(name, "Modified");
        assert!(u64::try_from(value).unwrap() > 0);
        assert_no_signal(changes.as_mut(), "duplicate create Items").await;
    }

    let second_properties = item_properties("s14-second", "s14-second");
    let second_secret = noirpass::service::session::Secret {
        session: session.clone(),
        parameters: Vec::new(),
        value: zeroize::Zeroizing::new(b"s14-second-secret".to_vec()),
        content_type: "text/plain".to_string(),
    };
    let mut canonical_items_changed = std::pin::pin!(
        canonical_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let mut alias_items_changed = std::pin::pin!(
        alias_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let (second_path, _): (OwnedObjectPath, OwnedObjectPath) = alias
        .call("CreateItem", &(&second_properties, &second_secret, false))
        .await
        .unwrap();
    let mut expected_items = vec![first_path.clone(), second_path.clone()];
    expected_items.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    for changes in [&mut canonical_items_changed, &mut alias_items_changed] {
        let (name, value) = next_property_change(changes.as_mut(), COLLECTION_IFACE).await;
        assert_eq!(name, "Items");
        let mut actual = Vec::<OwnedObjectPath>::try_from(value).unwrap();
        actual.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        assert_eq!(actual, expected_items);
        let (name, value) = next_property_change(changes.as_mut(), COLLECTION_IFACE).await;
        assert_eq!(name, "Modified");
        assert!(u64::try_from(value).unwrap() > 0);
        assert_no_signal(changes.as_mut(), "duplicate alias-create Items").await;
    }

    let first_item = zbus::Proxy::new(
        &conn,
        SERVICE_NAME,
        first_path.clone(),
        "org.freedesktop.Secret.Item",
    )
    .await
    .unwrap();
    let mut canonical_items_changed = std::pin::pin!(
        canonical_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let mut alias_items_changed = std::pin::pin!(
        alias_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    first_item
        .call::<_, _, OwnedObjectPath>("Delete", &())
        .await
        .unwrap();
    for changes in [&mut canonical_items_changed, &mut alias_items_changed] {
        let (name, value) = next_property_change(changes.as_mut(), COLLECTION_IFACE).await;
        assert_eq!(name, "Items");
        assert_eq!(
            Vec::<OwnedObjectPath>::try_from(value).unwrap(),
            vec![second_path.clone()]
        );
        let (name, value) = next_property_change(changes.as_mut(), COLLECTION_IFACE).await;
        assert_eq!(name, "Modified");
        assert!(u64::try_from(value).unwrap() > 0);
        assert_no_signal(changes.as_mut(), "duplicate delete Items").await;
    }

    {
        let second_item_properties =
            zbus::Proxy::new(&conn, SERVICE_NAME, second_path.clone(), PROPERTIES_IFACE)
                .await
                .unwrap();
        let mut item_changed =
            std::pin::pin!(canonical.receive_signal("ItemChanged").await.unwrap());
        let mut item_properties_changed = std::pin::pin!(
            second_item_properties
                .receive_signal("PropertiesChanged")
                .await
                .unwrap()
        );
        let mut canonical_items_changed = std::pin::pin!(
            canonical_properties
                .receive_signal("PropertiesChanged")
                .await
                .unwrap()
        );
        let mut alias_items_changed = std::pin::pin!(
            alias_properties
                .receive_signal("PropertiesChanged")
                .await
                .unwrap()
        );
        let replacement_properties = item_properties("s14-replaced", "s14-second");
        let replacement_secret = noirpass::service::session::Secret {
            session: session.clone(),
            parameters: Vec::new(),
            value: zeroize::Zeroizing::new(b"s14-replaced-secret".to_vec()),
            content_type: "text/plain".to_string(),
        };
        let (replacement_path, _): (OwnedObjectPath, OwnedObjectPath) = alias
            .call(
                "CreateItem",
                &(&replacement_properties, &replacement_secret, true),
            )
            .await
            .unwrap();
        assert_eq!(replacement_path, second_path);
        assert_eq!(
            super::super::super::helpers::next_property_name(item_properties_changed.as_mut())
                .await,
            "Label"
        );
        assert_eq!(
            super::super::super::helpers::next_property_name(item_properties_changed.as_mut())
                .await,
            "Modified"
        );
        super::super::super::helpers::next_item_changed(item_changed.as_mut(), &second_path).await;
        for changes in [&mut canonical_items_changed, &mut alias_items_changed] {
            let (name, value) = next_property_change(changes.as_mut(), COLLECTION_IFACE).await;
            assert_eq!(name, "Modified");
            assert!(u64::try_from(value).unwrap() > 0);
        }
        assert_no_signal(canonical_items_changed.as_mut(), "Items for replacement").await;
        assert_no_signal(alias_items_changed.as_mut(), "alias Items for replacement").await;
        let items: Vec<OwnedObjectPath> = canonical.get_property("Items").await.unwrap();
        assert_eq!(items, vec![second_path.clone()]);
    }

    // Repoint A -> B: same alias object stays registered, but only its four
    // target-dependent properties are invalidated. No collection signal fires.
    let _: Vec<OwnedObjectPath> = alias.get_property("Items").await.unwrap();
    let _: String = alias.get_property("Label").await.unwrap();
    let _: u64 = alias.get_property("Created").await.unwrap();
    let _: u64 = alias.get_property("Modified").await.unwrap();
    let other_items: Vec<OwnedObjectPath> = other.get_property("Items").await.unwrap();
    assert_eq!(other_items.len(), 0);
    {
        let mut alias_changes = std::pin::pin!(
            alias_properties
                .receive_signal("PropertiesChanged")
                .await
                .unwrap()
        );
        let mut collection_changed =
            std::pin::pin!(service.receive_signal("CollectionChanged").await.unwrap());
        let mut service_properties_changed = std::pin::pin!(
            service_properties
                .receive_signal("PropertiesChanged")
                .await
                .unwrap()
        );
        service
            .call::<_, _, ()>("SetAlias", &("s14_alias", &b_path))
            .await
            .unwrap();
        let mut invalidated =
            next_invalidated_properties(alias_changes.as_mut(), COLLECTION_IFACE).await;
        invalidated.sort();
        assert_eq!(invalidated, ["Created", "Items", "Label", "Modified"]);
        assert_no_signal(
            alias_changes.as_mut(),
            "duplicate alias repoint invalidation",
        )
        .await;
        assert_eq!(
            alias.get_property::<String>("Label").await.unwrap(),
            "s14-b"
        );
        assert_eq!(
            alias
                .get_property::<Vec<OwnedObjectPath>>("Items")
                .await
                .unwrap(),
            other_items
        );
        assert_eq!(
            alias.get_property::<u64>("Created").await.unwrap(),
            other.get_property::<u64>("Created").await.unwrap()
        );
        assert_eq!(
            alias.get_property::<u64>("Modified").await.unwrap(),
            other.get_property::<u64>("Modified").await.unwrap()
        );
        assert_no_signal(
            collection_changed.as_mut(),
            "CollectionChanged for alias repoint",
        )
        .await;
        assert_no_signal(
            service_properties_changed.as_mut(),
            "Collections change for alias repoint",
        )
        .await;
    }

    // B -> B is idempotent and emits no alias invalidation.
    {
        let mut alias_changes = std::pin::pin!(
            alias_properties
                .receive_signal("PropertiesChanged")
                .await
                .unwrap()
        );
        service
            .call::<_, _, ()>("SetAlias", &("s14_alias", &b_path))
            .await
            .unwrap();
        assert_no_signal(
            alias_changes.as_mut(),
            "alias invalidation for idempotent SetAlias",
        )
        .await;
    }

    // Clearing alias removes object and preserves ReadAlias's root convention.
    let root = OwnedObjectPath::try_from("/").unwrap();
    service
        .call::<_, _, ()>("SetAlias", &("s14_alias", &root))
        .await
        .unwrap();
    let resolved: OwnedObjectPath = service.call("ReadAlias", &("s14_alias",)).await.unwrap();
    assert_eq!(resolved.as_str(), "/");
    assert!(alias.get_property::<String>("Label").await.is_err());

    canonical
        .call::<_, _, OwnedObjectPath>("Delete", &())
        .await
        .unwrap();
    other
        .call::<_, _, OwnedObjectPath>("Delete", &())
        .await
        .unwrap();
}
