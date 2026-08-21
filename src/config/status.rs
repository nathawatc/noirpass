//! Recipient loading and read-only status reporting.

use std::fs;
use std::io;
use std::path::Path;

use sequoia_openpgp::Cert;

use crate::error::{Error, Result};
use crate::gpg::{has_usable_encryption_key, parse_recipient_cert};
use crate::store::Store;

use super::format::{config_path, recipient_cert_path_from_config};
use super::{CONFIG_VERSION, Config, INIT_HINT, Recipient, Status};

pub(super) fn load_configured_recipient(data_dir: &Path) -> Result<(Config, Cert, String)> {
    let config = Config::load(data_dir)?;
    if config.version != CONFIG_VERSION {
        return Err(Error::Config(format!(
            "unsupported config version {}; expected {CONFIG_VERSION}",
            config.version
        )));
    }

    let path = recipient_cert_path_from_config(data_dir, &config.recipient_cert)?;
    let bytes = fs::read(&path).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            Error::Config(format!(
                "recipient certificate missing at {}; {INIT_HINT}",
                path.display()
            ))
        } else {
            Error::Io(e)
        }
    })?;
    let cert = parse_recipient_cert(&bytes)?;
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
    let (_, cert, fingerprint) = load_configured_recipient(data_dir)?;
    if !has_usable_encryption_key(&cert) {
        return Err(Error::Config(
            "recipient certificate has no usable encryption-capable key".into(),
        ));
    }
    Ok(Recipient { cert, fingerprint })
}

/// Compute status without mutating store.
#[must_use]
pub fn status(data_dir: &Path) -> Status {
    let mut out = Status {
        data_dir: data_dir.to_path_buf(),
        config_present: config_path(data_dir).exists(),
        config_valid: false,
        recipient_cert_present: false,
        configured_fingerprint: None,
        actual_fingerprint: None,
        fingerprint_matches: None,
        cert_has_encryption_key: None,
        errors: Vec::new(),
    };

    let config = match Config::load(data_dir) {
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

    if let Some(config) = config {
        match recipient_cert_path_from_config(data_dir, &config.recipient_cert) {
            Ok(cert_path) => {
                out.recipient_cert_present = cert_path.exists();
                match fs::read(&cert_path) {
                    Ok(bytes) => match parse_recipient_cert(&bytes) {
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
                                out.errors.push(
                                    "recipient certificate has no usable encryption-capable key"
                                        .into(),
                                );
                            }
                        }
                        Err(err) => out.errors.push(err.to_string()),
                    },
                    Err(err) if err.kind() == io::ErrorKind::NotFound => out.errors.push(format!(
                        "recipient certificate missing at {}",
                        cert_path.display()
                    )),
                    Err(err) => out.errors.push(err.to_string()),
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
        match Store::probe_integrity(data_dir) {
            Ok(report) if report.is_healthy() => {}
            Ok(_) => out.errors.push(
                "store integrity check failed; run `noirpass check` before starting daemon".into(),
            ),
            Err(err) => out
                .errors
                .push(format!("store integrity check failed: {err}")),
        }
    }

    out
}
