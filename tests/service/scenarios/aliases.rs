use std::collections::HashMap;
use std::time::Duration;

use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

use super::super::helpers::{
    COLLECTION_IFACE, PROPERTIES_IFACE, SERVICE_IFACE, SERVICE_NAME, SERVICE_PATH,
    assert_no_signal, collection_properties, item_properties, next_event,
    next_invalidated_properties, next_property_change, service_proxy,
};

/// Scenario 4: alias handling, including the raw `/` conventions.
pub(super) async fn s4_aliases() {
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

/// Scenario 13: reusing an existing alias applies an optional collection label
/// without changing collection membership or the alias target.
#[allow(
    clippy::too_many_lines,
    reason = "one private-bus scenario covers every CreateCollection alias/property case"
)]
pub(super) async fn s13_existing_alias_collection() {
    let conn = zbus::Connection::session().await.unwrap();
    let service = service_proxy(&conn).await;
    let initial_count: Vec<OwnedObjectPath> = service.get_property("Collections").await.unwrap();

    let (initial_path, prompt): (OwnedObjectPath, OwnedObjectPath) = service
        .call(
            "CreateCollection",
            &(
                collection_properties(Some("s13-initial")),
                "s13-existing-alias",
            ),
        )
        .await
        .unwrap();
    assert_eq!(prompt.as_str(), "/");
    assert_eq!(
        service
            .call::<_, _, OwnedObjectPath>("ReadAlias", &("s13-existing-alias",))
            .await
            .unwrap(),
        initial_path
    );

    let collection = zbus::Proxy::new(&conn, SERVICE_NAME, initial_path.clone(), COLLECTION_IFACE)
        .await
        .unwrap();
    let collection_properties_proxy =
        zbus::Proxy::new(&conn, SERVICE_NAME, initial_path.clone(), PROPERTIES_IFACE)
            .await
            .unwrap();
    let service_properties = zbus::Proxy::new(&conn, SERVICE_NAME, SERVICE_PATH, PROPERTIES_IFACE)
        .await
        .unwrap();
    let initial_label: String = collection.get_property("Label").await.unwrap();
    assert_eq!(initial_label, "s13-initial");
    let initial_modified: u64 = collection.get_property("Modified").await.unwrap();

    // Existing alias + supplied Label updates the existing collection in place.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let mut collection_properties_changed = std::pin::pin!(
        collection_properties_proxy
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
    let (returned_path, prompt): (OwnedObjectPath, OwnedObjectPath) = service
        .call(
            "CreateCollection",
            &(
                collection_properties(Some("s13-updated")),
                "s13-existing-alias",
            ),
        )
        .await
        .unwrap();
    assert_eq!(returned_path, initial_path);
    assert_eq!(prompt.as_str(), "/");
    assert_eq!(
        service
            .call::<_, _, OwnedObjectPath>("ReadAlias", &("s13-existing-alias",))
            .await
            .unwrap(),
        initial_path
    );
    let (label_name, label_value) =
        next_property_change(collection_properties_changed.as_mut(), COLLECTION_IFACE).await;
    assert_eq!(label_name, "Label");
    assert_eq!(String::try_from(label_value).unwrap(), "s13-updated");
    let (modified_name, modified_value) =
        next_property_change(collection_properties_changed.as_mut(), COLLECTION_IFACE).await;
    assert_eq!(modified_name, "Modified");
    let modified_after: u64 = collection.get_property("Modified").await.unwrap();
    assert_eq!(u64::try_from(modified_value).unwrap(), modified_after);
    assert!(modified_after > initial_modified);
    assert_eq!(
        collection.get_property::<String>("Label").await.unwrap(),
        "s13-updated"
    );
    let changed_message = tokio::time::timeout(
        Duration::from_secs(10),
        next_event(collection_changed.as_mut()),
    )
    .await
    .expect("timed out waiting for CollectionChanged")
    .expect("CollectionChanged stream ended");
    let (changed_path,): (OwnedObjectPath,) = changed_message.body().deserialize().unwrap();
    assert_eq!(changed_path, initial_path);
    assert_no_signal(
        collection_created.as_mut(),
        "CollectionCreated for existing alias",
    )
    .await;
    assert_no_signal(
        service_properties_changed.as_mut(),
        "Service.Collections change for existing alias",
    )
    .await;
    let after_update_count: Vec<OwnedObjectPath> =
        service.get_property("Collections").await.unwrap();
    assert_eq!(after_update_count.len(), initial_count.len() + 1);
    assert!(after_update_count.contains(&initial_path));

    // Existing alias + no Label is a no-op, including timestamps and signals.
    let unchanged_label: String = collection.get_property("Label").await.unwrap();
    let unchanged_modified: u64 = collection.get_property("Modified").await.unwrap();
    let mut collection_properties_changed = std::pin::pin!(
        collection_properties_proxy
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
    let (returned_path, prompt): (OwnedObjectPath, OwnedObjectPath) = service
        .call::<_, _, (OwnedObjectPath, OwnedObjectPath)>(
            "CreateCollection",
            &(HashMap::<String, OwnedValue>::new(), "s13-existing-alias"),
        )
        .await
        .unwrap();
    assert_eq!(returned_path, initial_path);
    assert_eq!(prompt.as_str(), "/");
    assert_eq!(
        collection.get_property::<String>("Label").await.unwrap(),
        unchanged_label
    );
    assert_eq!(
        collection.get_property::<u64>("Modified").await.unwrap(),
        unchanged_modified
    );
    assert_no_signal(
        collection_properties_changed.as_mut(),
        "PropertiesChanged for absent Label",
    )
    .await;
    assert_no_signal(
        collection_changed.as_mut(),
        "CollectionChanged for absent Label",
    )
    .await;
    assert_no_signal(
        collection_created.as_mut(),
        "CollectionCreated for absent Label",
    )
    .await;
    assert_no_signal(
        service_properties_changed.as_mut(),
        "Service.Collections change for absent Label",
    )
    .await;

    // Existing alias + explicit empty Label must mutate the label.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let modified_before_empty: u64 = collection.get_property("Modified").await.unwrap();
    let mut collection_properties_changed = std::pin::pin!(
        collection_properties_proxy
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
    let (returned_path, prompt): (OwnedObjectPath, OwnedObjectPath) = service
        .call(
            "CreateCollection",
            &(collection_properties(Some("")), "s13-existing-alias"),
        )
        .await
        .unwrap();
    assert_eq!(returned_path, initial_path);
    assert_eq!(prompt.as_str(), "/");
    let (label_name, label_value) =
        next_property_change(collection_properties_changed.as_mut(), COLLECTION_IFACE).await;
    assert_eq!(label_name, "Label");
    assert_eq!(String::try_from(label_value).unwrap(), "");
    let (modified_name, _) =
        next_property_change(collection_properties_changed.as_mut(), COLLECTION_IFACE).await;
    assert_eq!(modified_name, "Modified");
    assert_eq!(
        collection.get_property::<String>("Label").await.unwrap(),
        ""
    );
    assert!(collection.get_property::<u64>("Modified").await.unwrap() > modified_before_empty);
    let changed_message = tokio::time::timeout(
        Duration::from_secs(10),
        next_event(collection_changed.as_mut()),
    )
    .await
    .expect("timed out waiting for empty-label CollectionChanged")
    .expect("empty-label CollectionChanged stream ended");
    let (changed_path,): (OwnedObjectPath,) = changed_message.body().deserialize().unwrap();
    assert_eq!(changed_path, initial_path);
    assert_no_signal(
        collection_created.as_mut(),
        "CollectionCreated for empty Label",
    )
    .await;
    assert_no_signal(
        service_properties_changed.as_mut(),
        "Service.Collections change for empty Label",
    )
    .await;

    // Alias absent keeps normal creation behavior and grows Collections.
    let before_new_count: Vec<OwnedObjectPath> = service.get_property("Collections").await.unwrap();
    let mut collection_created =
        std::pin::pin!(service.receive_signal("CollectionCreated").await.unwrap());
    let mut service_properties_changed = std::pin::pin!(
        service_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let (new_path, prompt): (OwnedObjectPath, OwnedObjectPath) = service
        .call(
            "CreateCollection",
            &(collection_properties(Some("s13-no-alias")), ""),
        )
        .await
        .unwrap();
    assert_ne!(new_path, initial_path);
    assert_eq!(prompt.as_str(), "/");
    let new_collection = zbus::Proxy::new(&conn, SERVICE_NAME, new_path.clone(), COLLECTION_IFACE)
        .await
        .unwrap();
    assert_eq!(
        new_collection
            .get_property::<String>("Label")
            .await
            .unwrap(),
        "s13-no-alias"
    );
    let created_message = tokio::time::timeout(
        Duration::from_secs(10),
        next_event(collection_created.as_mut()),
    )
    .await
    .expect("timed out waiting for alias-absent CollectionCreated")
    .expect("alias-absent CollectionCreated stream ended");
    let (created_path,): (OwnedObjectPath,) = created_message.body().deserialize().unwrap();
    assert_eq!(created_path, new_path);
    let (interface, changed, invalidated): (String, HashMap<String, OwnedValue>, Vec<String>) =
        tokio::time::timeout(
            Duration::from_secs(10),
            next_event(service_properties_changed.as_mut()),
        )
        .await
        .expect("timed out waiting for alias-absent Collections change")
        .expect("alias-absent Collections stream ended")
        .body()
        .deserialize()
        .unwrap();
    assert_eq!(interface, SERVICE_IFACE);
    assert!(invalidated.is_empty());
    assert_eq!(changed.len(), 1);
    assert!(changed.contains_key("Collections"));
    let after_new_count: Vec<OwnedObjectPath> = service.get_property("Collections").await.unwrap();
    assert_eq!(after_new_count.len(), before_new_count.len() + 1);
    assert!(after_new_count.contains(&new_path));

    for path in [initial_path, new_path] {
        let collection = zbus::Proxy::new(&conn, SERVICE_NAME, path, COLLECTION_IFACE)
            .await
            .unwrap();
        collection
            .call::<_, _, OwnedObjectPath>("Delete", &())
            .await
            .unwrap();
    }
}

/// Scenario 14: collection properties and membership stay coherent across
/// canonical and alias object paths, including alias target changes.
#[allow(
    clippy::too_many_lines,
    reason = "one private-bus scenario covers collection and alias notification semantics"
)]
pub(super) async fn s14_collection_alias_notifications() {
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
    let canonical = zbus::Proxy::new(&conn, SERVICE_NAME, a_path.clone(), COLLECTION_IFACE)
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
    assert!(initial_items.is_empty());
    initial_items = alias.get_property("Items").await.unwrap();
    assert!(initial_items.is_empty());

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
            super::super::helpers::next_property_name(item_properties_changed.as_mut()).await,
            "Label"
        );
        assert_eq!(
            super::super::helpers::next_property_name(item_properties_changed.as_mut()).await,
            "Modified"
        );
        super::super::helpers::next_item_changed(item_changed.as_mut(), &second_path).await;
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
    assert!(other_items.is_empty());
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
