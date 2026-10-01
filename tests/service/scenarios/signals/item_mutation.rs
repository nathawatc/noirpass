use std::collections::HashMap;
use std::time::Duration;

use noirpass::service::session::Secret as WireSecret;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zeroize::Zeroizing;

use super::super::super::harness::harness;
use super::super::super::helpers::{
    COLLECTION_IFACE, ITEM_IFACE, PROPERTIES_IFACE, SERVICE_NAME, assert_method_error,
    assert_no_signal, attrs, next_event, next_item_changed, next_property_name, service_proxy,
};

/// Scenario 12: item mutations emit required property and collection signals.
#[allow(
    clippy::too_many_lines,
    reason = "one private-bus scenario covers every item mutation notification path"
)]
pub(in super::super) async fn s12_item_mutation_signals() {
    let h = harness();
    let service = oo7::dbus::Service::plain().await.unwrap();
    let collection = service
        .create_collection("s12-mutations", None, None)
        .await
        .unwrap();
    let attributes = attrs("s12");
    let item = collection
        .create_item(
            "s12-initial",
            &attributes,
            oo7::Secret::text("initial secret"),
            true,
            None,
        )
        .await
        .unwrap();
    let collection_path = OwnedObjectPath::from(collection.path().to_owned());
    let item_path = OwnedObjectPath::from(item.path().to_owned());

    let conn = zbus::Connection::session().await.unwrap();
    let service_proxy = service_proxy(&conn).await;
    let item_proxy = zbus::Proxy::new(&conn, SERVICE_NAME, item_path.clone(), ITEM_IFACE)
        .await
        .unwrap();
    let item_properties =
        zbus::Proxy::new(&conn, SERVICE_NAME, item_path.clone(), PROPERTIES_IFACE)
            .await
            .unwrap();
    let collection_proxy = zbus::Proxy::new(
        &conn,
        SERVICE_NAME,
        collection_path.clone(),
        COLLECTION_IFACE,
    )
    .await
    .unwrap();
    let (_, session): (OwnedValue, OwnedObjectPath) = service_proxy
        .call("OpenSession", &("plain", Value::from("")))
        .await
        .unwrap();

    // SetSecret emits ItemChanged and Modified.
    let mut item_changed = std::pin::pin!(
        collection_proxy
            .receive_signal("ItemChanged")
            .await
            .unwrap()
    );
    let mut properties_changed = std::pin::pin!(
        item_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let secret = WireSecret {
        session: session.clone(),
        parameters: Vec::new(),
        value: Zeroizing::new(b"changed secret".to_vec()),
        content_type: "text/plain".to_string(),
    };
    item_proxy
        .call::<_, _, ()>("SetSecret", &(&secret,))
        .await
        .unwrap();
    assert_eq!(
        next_property_name(properties_changed.as_mut()).await,
        "Modified"
    );
    assert_no_signal(
        properties_changed.as_mut(),
        "duplicate SetSecret property signal",
    )
    .await;
    next_item_changed(item_changed.as_mut(), &item_path).await;
    assert_no_signal(item_changed.as_mut(), "duplicate SetSecret ItemChanged").await;

    // Label setter emits one explicit Label signal plus Modified and ItemChanged.
    let mut item_changed = std::pin::pin!(
        collection_proxy
            .receive_signal("ItemChanged")
            .await
            .unwrap()
    );
    let mut properties_changed = std::pin::pin!(
        item_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    item_proxy.set_property("Label", "s12-label").await.unwrap();
    let label_names = vec![
        next_property_name(properties_changed.as_mut()).await,
        next_property_name(properties_changed.as_mut()).await,
    ];
    assert_eq!(label_names, ["Label", "Modified"]);
    assert_no_signal(
        properties_changed.as_mut(),
        "duplicate Label property signal",
    )
    .await;
    next_item_changed(item_changed.as_mut(), &item_path).await;
    assert_no_signal(item_changed.as_mut(), "duplicate Label ItemChanged").await;

    // Attributes setter emits one explicit Attributes signal plus Modified and ItemChanged.
    let mut item_changed = std::pin::pin!(
        collection_proxy
            .receive_signal("ItemChanged")
            .await
            .unwrap()
    );
    let mut properties_changed = std::pin::pin!(
        item_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let replacement_attributes = HashMap::from([
        ("app".to_string(), "noirpass-e2e".to_string()),
        ("case".to_string(), "s12-updated".to_string()),
    ]);
    item_proxy
        .set_property("Attributes", replacement_attributes.clone())
        .await
        .unwrap();
    let attribute_names = vec![
        next_property_name(properties_changed.as_mut()).await,
        next_property_name(properties_changed.as_mut()).await,
    ];
    assert_eq!(attribute_names, ["Attributes", "Modified"]);
    assert_no_signal(
        properties_changed.as_mut(),
        "duplicate Attributes property signal",
    )
    .await;
    next_item_changed(item_changed.as_mut(), &item_path).await;
    assert_no_signal(item_changed.as_mut(), "duplicate Attributes ItemChanged").await;

    // Replacement emits one Label, one Modified, ItemChanged, but not ItemCreated.
    let mut item_changed = std::pin::pin!(
        collection_proxy
            .receive_signal("ItemChanged")
            .await
            .unwrap()
    );
    let mut item_created = std::pin::pin!(
        collection_proxy
            .receive_signal("ItemCreated")
            .await
            .unwrap()
    );
    let mut properties_changed = std::pin::pin!(
        item_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let replacement = collection
        .create_item(
            "s12-replaced",
            &replacement_attributes,
            oo7::Secret::text("replaced secret"),
            true,
            None,
        )
        .await
        .unwrap();
    assert_eq!(replacement.path(), item.path());
    let replacement_names = vec![
        next_property_name(properties_changed.as_mut()).await,
        next_property_name(properties_changed.as_mut()).await,
    ];
    assert_eq!(replacement_names, ["Label", "Modified"]);
    assert_no_signal(
        properties_changed.as_mut(),
        "duplicate replacement property signal",
    )
    .await;
    next_item_changed(item_changed.as_mut(), &item_path).await;
    assert_no_signal(item_changed.as_mut(), "duplicate replacement ItemChanged").await;
    assert!(
        tokio::time::timeout(
            Duration::from_millis(250),
            next_event(item_created.as_mut())
        )
        .await
        .is_err(),
        "replacement must not emit ItemCreated"
    );

    // A failed persistence mutation emits no property or ItemChanged signals.
    let mut item_changed = std::pin::pin!(
        collection_proxy
            .receive_signal("ItemChanged")
            .await
            .unwrap()
    );
    let mut properties_changed = std::pin::pin!(
        item_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    // The daemon pins its directory fd, so replacing the directory pathname no longer fails writes.
    // Replace the final ciphertext entry with a directory to inject a real validation failure.
    let item_id = item_path.as_str().rsplit('/').next().unwrap();
    let ciphertext = h.store_dir.join("secrets").join(format!("{item_id}.gpg"));
    let hidden_ciphertext = h.store_dir.join("s12-ciphertext-hidden");
    std::fs::rename(&ciphertext, &hidden_ciphertext).unwrap();
    std::fs::create_dir(&ciphertext).unwrap();
    let failed_secret = WireSecret {
        session,
        parameters: Vec::new(),
        value: Zeroizing::new(b"must not persist".to_vec()),
        content_type: "text/plain".to_string(),
    };
    let failure = item_proxy
        .call::<_, _, ()>("SetSecret", &(&failed_secret,))
        .await;
    std::fs::remove_dir(&ciphertext).unwrap();
    std::fs::rename(&hidden_ciphertext, &ciphertext).unwrap();
    assert_method_error(&failure.unwrap_err(), "org.freedesktop.DBus.Error.Failed");
    assert!(
        tokio::time::timeout(
            Duration::from_millis(250),
            next_event(properties_changed.as_mut())
        )
        .await
        .is_err(),
        "failed persistence must not emit PropertiesChanged"
    );
    assert!(
        tokio::time::timeout(
            Duration::from_millis(250),
            next_event(item_changed.as_mut())
        )
        .await
        .is_err(),
        "failed persistence must not emit ItemChanged"
    );

    collection.delete(None).await.unwrap();
}
