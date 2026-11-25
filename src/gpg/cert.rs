//! `OpenPGP` recipient certificate parsing, serialization, and key selection.

use sequoia_openpgp as openpgp;

use openpgp::cert::Cert;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::Serialize;
use openpgp::types::KeyFlags;

use crate::error::{Error, Result};

/// Flatten a Sequoia (`anyhow`) error into [`Error::OpenPgp`] without taking a
/// direct dependency on `anyhow`.
pub(super) fn pgp_err<E: std::fmt::Display>(e: E) -> Error {
    Error::OpenPgp(e.to_string())
}

pub(super) fn encryption_key_flags() -> KeyFlags {
    KeyFlags::empty()
        .set_storage_encryption()
        .set_transport_encryption()
}

pub(super) fn usable_encryption_keys<'a>(
    cert: &'a Cert,
    policy: &'a StandardPolicy,
) -> impl Iterator<
    Item = openpgp::cert::amalgamation::key::ValidErasedKeyAmalgamation<
        'a,
        openpgp::packet::key::PublicParts,
    >,
> {
    cert.keys()
        .with_policy(policy, None)
        .supported()
        .alive()
        .revoked(false)
        .key_flags(encryption_key_flags())
}

/// Parse an armored or binary `OpenPGP` recipient certificate.
pub fn parse_recipient(bytes: &[u8]) -> Result<Cert> {
    Cert::from_bytes(bytes).map_err(pgp_err)
}

/// Serialize a certificate as binary `OpenPGP` packets.
pub fn cert_to_binary(cert: &Cert) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    cert.serialize(&mut out).map_err(pgp_err)?;
    Ok(out)
}

/// True when cert has at least one valid encryption-capable key.
#[must_use]
pub fn has_usable_encryption_key(cert: &Cert) -> bool {
    let policy = StandardPolicy::new();
    usable_encryption_keys(cert, &policy).next().is_some()
}
