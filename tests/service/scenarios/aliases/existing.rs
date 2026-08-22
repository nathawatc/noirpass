use std::collections::HashMap;
use std::time::Duration;

use zbus::zvariant::{OwnedObjectPath, OwnedValue};

use super::super::super::helpers::{
    COLLECTION_IFACE, PROPERTIES_IFACE, SERVICE_IFACE, SERVICE_NAME, SERVICE_PATH,
    assert_no_signal, collection_properties, next_event, next_property_change, service_proxy,
};

/// Scenario 13: reusing an existing alias applies an optional collection label
/// without changing collection membership or the alias target.
#[allow(
    clippy::too_many_lines,
    reason = "one private-bus scenario covers every CreateCollection alias/property case"
)]
pub(in super::super) async fn s13_existing_alias_collection() {
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
