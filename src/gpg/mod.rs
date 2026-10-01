//! `OpenPGP` at-rest encryption of secrets.
//!
//! Each secret is encrypted to the user's own `OpenPGP` certificate, so the
//! ciphertext on disk can only be recovered with the user's secret key. The
//! public recipient certificate is imported by `noirpass init` and loaded from
//! noirpass' own store at daemon startup. Every secret is encrypted in-process
//! with Sequoia. Decryption is delegated to the running `gpg-agent` over its
//! Assuan socket via `sequoia-gpg-agent`, so noirpass never holds private key
//! material itself and honours the user's passphrase/pinentry policy.

mod agent;
mod cert;
mod crypto;
mod socket;

#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
mod tests;

use std::path::PathBuf;

use sequoia_openpgp::cert::Cert;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub use cert::{cert_to_binary, has_usable_encryption_key, parse_recipient_cert};

/// A recipient certificate plus enough context to decrypt via `gpg-agent`.
pub struct Gpg {
    /// The user's public certificate; secrets are encrypted to this.
    cert: Cert,
    /// The certificate's primary fingerprint (hex).
    fingerprint: String,
    /// The `GnuPG` home directory, if not the process default. Used to
    /// reconnect to the correct `gpg-agent` at decryption time.
    homedir: Option<PathBuf>,
}

impl Gpg {
    /// Construct a `Gpg` from the configured recipient certificate.
    pub fn from_cert(cert: Cert) -> Result<Self> {
        Self::from_cert_with_homedir(cert, None)
    }

    /// Construct a `Gpg` from a cert and explicit `GNUPGHOME` for tests.
    pub fn from_cert_with_homedir(cert: Cert, homedir: Option<PathBuf>) -> Result<Self> {
        let fingerprint = cert.fingerprint().to_hex();
        Ok(Self {
            cert,
            fingerprint,
            homedir,
        })
    }

    /// The primary fingerprint (hex) of the recipient certificate.
    #[must_use]
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Verify that `gpg-agent` has a secret key for at least one current
    /// encryption-capable recipient key.
    pub async fn ensure_recipient_secret_available(&self) -> Result<()> {
        let cert = self.cert.clone();
        let homedir = self.homedir.clone();
        let fingerprint = self.fingerprint.clone();
        agent::ensure_recipient_secret_available(homedir.as_deref(), &cert)
            .await
            .map_err(|err| {
                Error::Config(format!(
                    "no available GnuPG secret key for configured recipient {fingerprint}: {err}"
                ))
            })
    }

    /// Encrypt `plaintext` to the recipient certificate, returning binary
    /// (non-armored) `OpenPGP` ciphertext.
    ///
    /// The message is encrypted to every valid, live, non-revoked encryption
    /// subkey (storage and transport). This is a purely local operation and
    /// requires no agent interaction.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        crypto::encrypt(&self.cert, &self.fingerprint, plaintext)
    }

    /// Run agent decryption inside the caller's bounded blocking worker.
    pub(crate) fn decrypt_blocking(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        agent::decrypt_blocking(self.homedir.as_deref(), &self.cert, ciphertext)
    }

    /// Decrypt `ciphertext` produced by `encrypt` via the
    /// running `gpg-agent`.
    ///
    /// The blocking Sequoia/agent pipeline is run on a blocking thread so this
    /// is safe to call from an async context. The agent must be running for the
    /// configured `GnuPG` home; unlocking the key follows the user's pinentry
    /// policy (an empty-passphrase key needs no interaction).
    pub async fn decrypt(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let cert = self.cert.clone();
        let homedir = self.homedir.clone();
        let ct = ciphertext.to_vec();

        tokio::task::spawn_blocking(move || agent::decrypt_blocking(homedir.as_deref(), &cert, &ct))
            .await
            .map_err(|e| Error::OpenPgp(format!("decrypt task failed: {e}")))?
    }
}
