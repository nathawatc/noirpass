//! Public Secret Service D-Bus error mapping.

use zbus::fdo;

/// Secret Service and standard D-Bus method errors.
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.freedesktop")]
pub enum SecretError {
    /// Transparent wrapper for errors without a dedicated public variant.
    #[zbus(error)]
    ZBus(zbus::Error),
    /// Invalid client arguments.
    #[zbus(name = "DBus.Error.InvalidArgs")]
    InvalidArgs(String),
    /// The requested operation is unsupported.
    #[zbus(name = "DBus.Error.NotSupported")]
    NotSupported(String),
    /// An internal operation failed.
    #[zbus(name = "DBus.Error.Failed")]
    Failed(String),
    /// The caller lacks the required identity or authorization.
    #[zbus(name = "DBus.Error.AccessDenied")]
    AccessDenied(String),
    /// The daemon's bounded request capacity is exhausted.
    #[zbus(name = "DBus.Error.LimitsExceeded")]
    LimitsExceeded(String),
    /// The session named in a `Secret` does not exist.
    #[zbus(name = "Secret.Error.NoSession")]
    NoSession(String),
    /// The referenced object does not exist.
    #[zbus(name = "Secret.Error.NoSuchObject")]
    NoSuchObject(String),
}

impl From<fdo::Error> for SecretError {
    fn from(err: fdo::Error) -> Self {
        match err {
            fdo::Error::InvalidArgs(message) => Self::InvalidArgs(message),
            fdo::Error::NotSupported(message) => Self::NotSupported(message),
            fdo::Error::Failed(message) => Self::Failed(message),
            fdo::Error::AccessDenied(message) => Self::AccessDenied(message),
            fdo::Error::LimitsExceeded(message) => Self::LimitsExceeded(message),
            other => Self::ZBus(zbus::Error::FDO(Box::new(other))),
        }
    }
}

impl From<crate::Error> for SecretError {
    fn from(err: crate::Error) -> Self {
        match err {
            crate::Error::NotFound(msg) => Self::NoSuchObject(msg),
            other => fdo::Error::Failed(other.to_string()).into(),
        }
    }
}
