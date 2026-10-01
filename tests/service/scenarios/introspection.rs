//! Wire contracts from the freedesktop Secret Service specification.
//!
//! Check live introspection on the existing private-bus fixture, independent of
//! XML whitespace, argument names, annotations, and member ordering.

use std::collections::{BTreeMap, HashMap};

use noirpass::service::session::Secret;
use roxmltree::{Document, ParsingOptions};
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zeroize::Zeroizing;

use super::super::helpers::{
    COLLECTION_IFACE, ITEM_IFACE, PROPERTIES_IFACE, SERVICE_IFACE, SERVICE_NAME, SERVICE_PATH,
    service_proxy,
};

// Methods: input/output signatures. Signals: empty input/output signature.
// Properties: type/access. Secret's wire signature is (oayays).
const SERVICE: &[(&str, &str, &str, &str)] = &[
    ("method", "OpenSession", "sv", "vo"),
    ("method", "CreateCollection", "a{sv}s", "oo"),
    ("method", "SearchItems", "a{ss}", "aoao"),
    ("method", "Unlock", "ao", "aoo"),
    ("method", "Lock", "ao", "aoo"),
    ("method", "GetSecrets", "aoo", "a{o(oayays)}"),
    ("method", "ReadAlias", "s", "o"),
    ("method", "SetAlias", "so", ""),
    ("property", "Collections", "ao", "read"),
    ("signal", "CollectionCreated", "", "o"),
    ("signal", "CollectionDeleted", "", "o"),
    ("signal", "CollectionChanged", "", "o"),
];
const COLLECTION: &[(&str, &str, &str, &str)] = &[
    ("method", "Delete", "", "o"),
    ("method", "SearchItems", "a{ss}", "ao"),
    ("method", "CreateItem", "a{sv}(oayays)b", "oo"),
    ("property", "Items", "ao", "read"),
    ("property", "Label", "s", "readwrite"),
    ("property", "Locked", "b", "read"),
    ("property", "Created", "t", "read"),
    ("property", "Modified", "t", "read"),
    ("signal", "ItemCreated", "", "o"),
    ("signal", "ItemDeleted", "", "o"),
    ("signal", "ItemChanged", "", "o"),
];
const ITEM: &[(&str, &str, &str, &str)] = &[
    ("method", "Delete", "", "o"),
    ("method", "GetSecret", "o", "(oayays)"),
    ("method", "SetSecret", "(oayays)", ""),
    ("property", "Locked", "b", "read"),
    ("property", "Attributes", "a{ss}", "readwrite"),
    ("property", "Label", "s", "readwrite"),
    ("property", "Created", "t", "read"),
    ("property", "Modified", "t", "read"),
];

fn assert_interface(xml: &str, interface: &str, expected: &[(&str, &str, &str, &str)]) {
    let document = Document::parse_with_options(
        xml,
        ParsingOptions {
            allow_dtd: true, // zbus emits the standard introspection DOCTYPE.
            ..ParsingOptions::default()
        },
    )
    .expect("valid introspection XML");
    let node = document
        .root_element()
        .children()
        .find(|node| node.has_tag_name("interface") && node.attribute("name") == Some(interface))
        .unwrap_or_else(|| panic!("missing {interface}"));
    let mut actual = BTreeMap::new();
    for member in node.children().filter(roxmltree::Node::is_element) {
        let kind = member.tag_name().name();
        let signatures = match kind {
            "property" => (
                member.attribute("type").unwrap().to_owned(),
                member.attribute("access").unwrap().to_owned(),
            ),
            "method" | "signal" => {
                let mut input = String::new();
                let mut output = String::new();
                for arg in member.children().filter(|arg| arg.has_tag_name("arg")) {
                    let direction = arg.attribute("direction").unwrap_or(if kind == "method" {
                        "in"
                    } else {
                        "out"
                    });
                    let signature = match direction {
                        "in" => &mut input,
                        "out" => &mut output,
                        other => panic!("invalid argument direction {other}"),
                    };
                    signature.push_str(arg.attribute("type").unwrap());
                }
                (input, output)
            }
            _ => continue, // Interface annotations are not API members.
        };
        let key = (kind, member.attribute("name").unwrap());
        assert!(
            actual.insert(key, signatures).is_none(),
            "duplicate {key:?}"
        );
    }
    let expected: BTreeMap<_, _> = expected
        .iter()
        .map(|&(kind, name, first, second)| ((kind, name), (first.to_owned(), second.to_owned())))
        .collect();
    assert_eq!(actual, expected, "{interface} wire contract");
}

async fn introspect(connection: &zbus::Connection, path: &str) -> String {
    let proxy = zbus::fdo::IntrospectableProxy::builder(connection)
        .destination(SERVICE_NAME)
        .unwrap()
        .path(path)
        .unwrap()
        .build()
        .await
        .unwrap();
    let xml = proxy.introspect().await.unwrap();
    assert_interface(
        &xml,
        PROPERTIES_IFACE,
        &[
            ("method", "Get", "ss", "v"),
            ("method", "Set", "ssv", ""),
            ("method", "GetAll", "s", "a{sv}"),
            ("signal", "PropertiesChanged", "", "sa{sv}as"),
        ],
    );
    assert_interface(
        &xml,
        "org.freedesktop.DBus.Introspectable",
        &[("method", "Introspect", "", "s")],
    );
    assert_interface(
        &xml,
        "org.freedesktop.DBus.Peer",
        &[
            ("method", "Ping", "", ""),
            ("method", "GetMachineId", "", "s"),
        ],
    );
    xml
}

pub(super) async fn introspection_contract() {
    let connection = zbus::Connection::session().await.unwrap();
    let service = service_proxy(&connection).await;
    assert_interface(
        &introspect(&connection, SERVICE_PATH).await,
        SERVICE_IFACE,
        SERVICE,
    );
    for path in [
        "/org/freedesktop/secrets/collection/default",
        "/org/freedesktop/secrets/aliases/default",
        "/org/freedesktop/secrets/collection/session",
        "/org/freedesktop/secrets/aliases/session",
    ] {
        assert_interface(
            &introspect(&connection, path).await,
            COLLECTION_IFACE,
            COLLECTION,
        );
    }
    let (_, session): (OwnedValue, OwnedObjectPath) = service
        .call("OpenSession", &("plain", Value::from("")))
        .await
        .unwrap();
    assert_interface(
        &introspect(&connection, session.as_str()).await,
        "org.freedesktop.Secret.Session",
        &[("method", "Close", "", "")],
    );
    let secret = Secret {
        session: session.clone(),
        parameters: Vec::new(),
        value: Zeroizing::new(b"introspection fixture".to_vec()),
        content_type: "text/plain".into(),
    };
    for collection_id in ["default", "session"] {
        let collection_path = format!("/org/freedesktop/secrets/collection/{collection_id}");
        let collection =
            zbus::Proxy::new(&connection, SERVICE_NAME, collection_path, COLLECTION_IFACE)
                .await
                .unwrap();
        let properties: HashMap<String, OwnedValue> = HashMap::new();
        let (item_path, _): (OwnedObjectPath, OwnedObjectPath) = collection
            .call("CreateItem", &(&properties, &secret, false))
            .await
            .unwrap();
        assert_interface(
            &introspect(&connection, item_path.as_str()).await,
            ITEM_IFACE,
            ITEM,
        );
        let item = zbus::Proxy::new(&connection, SERVICE_NAME, item_path, ITEM_IFACE)
            .await
            .unwrap();
        let _: OwnedObjectPath = item.call("Delete", &()).await.unwrap();
    }
    let session = zbus::Proxy::new(
        &connection,
        SERVICE_NAME,
        session,
        "org.freedesktop.Secret.Session",
    )
    .await
    .unwrap();
    session.call::<_, _, ()>("Close", &()).await.unwrap();
}
