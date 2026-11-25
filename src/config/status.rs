//! Recipient loading and read-only status reporting.

use std::io;
use std::path::Path;

use sequoia_openpgp::Cert;

use crate::error::{Error, Result};
use crate::filesystem::{Directory, validate_no_symlink_components};
use crate::gpg::{has_usable_encryption_key, parse_recipient_cert};
use crate::store::Store;

use super::{CONFIG_FILE, CONFIG_VERSION, Config, INIT_HINT, Recipient, Status};

fn read_and_parse_recipient_cert(
    data_dir: &Path,
    root: &Directory,
    rel_path: &Path,
) -> Result<Cert> {
    super::format::validate_recipient_cert_path(rel_path)?;
    root.validate_regular_or_absent(rel_path)?;
    let path = data_dir.join(rel_path);
    let bytes = root.read_regular(rel_path).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            Error::Config(format!(
                "recipient certificate missing at {}; {INIT_HINT}",
                path.display()
            ))
        } else {
            Error::Io(e)
        }
    })?;
    parse_recipient_cert(&bytes)
}

pub(super) fn load_configured_recipient_in(
    data_dir: &Path,
    root: &Directory,
) -> Result<(Config, Cert, String)> {
    let config = Config::load_in(root)?;
    if config.version != CONFIG_VERSION {
        return Err(Error::Config(format!(
            "unsupported config version {}; expected {CONFIG_VERSION}",
            config.version
        )));
    }

    let cert = read_and_parse_recipient_cert(data_dir, root, &config.recipient_cert)?;
    let actual = cert.fingerprint().to_hex();
    if actual != config.recipient_fingerprint {
        return Err(Error::Config(format!(
            "recipient fingerprint mismatch: config has {}, cert has {}",
            config.recipient_fingerprint, actual
        )));
    }
    Ok((config, cert, actual))
}

/// Load config and recipient certificate, validating consistency and key usability.
pub fn load_recipient(data_dir: &Path) -> Result<Recipient> {
    validate_no_symlink_components(data_dir)?;
    let root = Directory::open(data_dir).map_err(super::format::uninitialized_or_io)?;
    Ok(load_recipient_in(data_dir, &root)?.1)
}

pub(super) fn load_recipient_in(data_dir: &Path, root: &Directory) -> Result<(Config, Recipient)> {
    let (config, cert, fingerprint) = load_configured_recipient_in(data_dir, root)?;
    if !has_usable_encryption_key(&cert) {
        return Err(Error::Config(
            "recipient certificate has no usable encryption-capable key".into(),
        ));
    }
    Ok((config, Recipient { cert, fingerprint }))
}

/// Compute status without mutating store.
#[must_use]
pub fn status(data_dir: &Path) -> Status {
    status_with_cert(data_dir).0
}

/// Compute status and return the already-validated certificate when usable,
/// avoiding a second path resolution and certificate parse in `noirpass status`.
#[must_use]
pub fn status_with_cert(data_dir: &Path) -> (Status, Option<Cert>) {
    let mut out = Status {
        data_dir: data_dir.to_path_buf(),
        config_present: false,
        config_valid: false,
        recipient_cert_present: false,
        configured_fingerprint: None,
        actual_fingerprint: None,
        fingerprint_matches: None,
        cert_has_encryption_key: None,
        errors: Vec::new(),
    };

    if let Err(err) = validate_no_symlink_components(data_dir) {
        out.errors.push(format!("store path is unsafe: {err}"));
        return (out, None);
    }
    let root = match Directory::open(data_dir).map_err(super::format::uninitialized_or_io) {
        Ok(root) => root,
        Err(err) => {
            out.errors.push(err.to_string());
            return (out, None);
        }
    };
    out.config_present = root.entry_exists(Path::new(CONFIG_FILE)).unwrap_or(false);

    let config = match Config::load_in(&root) {
        Ok(config) => {
            out.config_valid = true;
            out.configured_fingerprint = Some(config.recipient_fingerprint.clone());
            if config.version != CONFIG_VERSION {
                out.errors.push(format!(
                    "unsupported config version {}; expected {CONFIG_VERSION}",
                    config.version
                ));
            }
            Some(config)
        }
        Err(err) => {
            out.errors.push(err.to_string());
            None
        }
    };

    let mut validated_cert = None;
    if let Some(config) = config {
        if root
            .validate_regular_or_absent(&config.recipient_cert)
            .is_ok()
        {
            out.recipient_cert_present = root.entry_exists(&config.recipient_cert).unwrap_or(false);
        }
        match read_and_parse_recipient_cert(data_dir, &root, &config.recipient_cert) {
            Ok(cert) => {
                let actual = cert.fingerprint().to_hex();
                let has_key = has_usable_encryption_key(&cert);
                out.actual_fingerprint = Some(actual.clone());
                out.fingerprint_matches = Some(actual == config.recipient_fingerprint);
                out.cert_has_encryption_key = Some(has_key);
                if out.fingerprint_matches != Some(true) {
                    out.errors.push(format!(
                        "recipient fingerprint mismatch: config has {}, cert has {}",
                        config.recipient_fingerprint, actual
                    ));
                }
                if !has_key {
                    out.errors
                        .push("recipient certificate has no usable encryption-capable key".into());
                }
                if out.fingerprint_matches == Some(true) && has_key {
                    validated_cert = Some(cert);
                }
            }
            Err(err) => out.errors.push(err.to_string()),
        }
    }

    if out.config_valid
        && out.recipient_cert_present
        && out.fingerprint_matches == Some(true)
        && out.cert_has_encryption_key == Some(true)
    {
        match Store::probe_integrity_in(data_dir, &root) {
            Ok(report) if report.is_healthy() => {}
            Ok(_) => out.errors.push(
                "store integrity check failed; run `noirpass check` before starting daemon".into(),
            ),
            Err(err) => out
                .errors
                .push(format!("store integrity check failed: {err}")),
        }
    }

    let cert = if out.usable() { validated_cert } else { None };
    (out, cert)
}
