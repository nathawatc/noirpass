use super::super::{
    SecretError, collection_path, item_path, parse_collection_path, parse_item_path, session_path,
};
use zbus::fdo;

#[test]
fn standard_dbus_error_names_survive_both_conversion_paths() {
    for (error, expected) in [
        (fdo::Error::InvalidArgs("bad input".into()), "InvalidArgs"),
        (
            fdo::Error::NotSupported("unsupported".into()),
            "NotSupported",
        ),
        (fdo::Error::Failed("operation failed".into()), "Failed"),
        (
            fdo::Error::AccessDenied("missing identity".into()),
            "AccessDenied",
        ),
    ] {
        let expected = format!("org.freedesktop.DBus.Error.{expected}");
        let direct: SecretError = error.clone().into();
        let wrapped: SecretError = zbus::Error::FDO(Box::new(error)).into();
        for converted in [direct, wrapped] {
            assert_eq!(zbus::DBusError::name(&converted).as_str(), expected);
            assert!(zbus::DBusError::description(&converted).is_some());
        }
    }
}

#[test]
fn path_helpers_roundtrip() {
    let col = collection_path("default");
    assert_eq!(col.as_str(), "/org/freedesktop/secrets/collection/default");
    assert_eq!(
        parse_collection_path(col.as_str()).as_deref(),
        Some("default")
    );

    let item = item_path("abc123", "def456");
    assert_eq!(
        item.as_str(),
        "/org/freedesktop/secrets/collection/abc123/def456"
    );
    assert_eq!(
        parse_item_path(item.as_str()),
        Some(("abc123".to_string(), "def456".to_string()))
    );

    assert_eq!(
        session_path(7).as_str(),
        "/org/freedesktop/secrets/session/s7"
    );

    // Non-matching shapes parse to None.
    assert_eq!(parse_collection_path("/org/freedesktop/secrets"), None);
    assert_eq!(parse_collection_path(item.as_str()), None);
    assert_eq!(parse_item_path(col.as_str()), None);
    assert_eq!(parse_item_path("/somewhere/else"), None);
}
