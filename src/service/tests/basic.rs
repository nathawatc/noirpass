use super::super::{
    SecretError, collection_path, item_path, parse_collection_path, parse_item_path, session_path,
};
use zbus::fdo;

#[test]
fn invalid_args_preserve_standard_dbus_error_name() {
    let error: SecretError = fdo::Error::InvalidArgs("bad input".into()).into();
    assert_eq!(
        zbus::DBusError::name(&error).as_str(),
        "org.freedesktop.DBus.Error.InvalidArgs"
    );
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
