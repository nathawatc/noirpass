//! In-process `OpenPGP` encryption.

use std::io;

use sequoia_openpgp as openpgp;

use openpgp::cert::Cert;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Encryptor, LiteralWriter, Message};

use crate::error::{Error, Result};

use super::cert::{encryption_key_flags, pgp_err};

pub(super) fn encrypt(cert: &Cert, fingerprint: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    let policy = StandardPolicy::new();

    let recipients: Vec<_> = cert
        .keys()
        .with_policy(&policy, None)
        .supported()
        .alive()
        .revoked(false)
        .key_flags(encryption_key_flags())
        .collect();

    if recipients.is_empty() {
        return Err(Error::OpenPgp(format!(
            "certificate {fingerprint} has no usable encryption subkey"
        )));
    }

    let mut sink = Vec::new();
    {
        let message = Message::new(&mut sink);
        let message = Encryptor::for_recipients(message, recipients)
            .build()
            .map_err(pgp_err)?;
        let mut writer = LiteralWriter::new(message).build().map_err(pgp_err)?;
        io::Write::write_all(&mut writer, plaintext)?;
        writer.finalize().map_err(pgp_err)?;
    }
    Ok(sink)
}
