//! `OpenPGP` at-rest encryption of secrets.
//!
//! Each secret is encrypted to the user's own `OpenPGP` certificate, so the
//! ciphertext on disk can only be recovered with the user's secret key. The
//! public recipient certificate is loaded once at startup by shelling out to
//! `gpg --export` (documented below); every secret is then encrypted in-process
//! with Sequoia. Decryption is delegated to the running `gpg-agent` over its
//! Assuan socket via `sequoia-gpg-agent`, so noirpass never holds the secret
//! key material itself and honours whatever passphrase/pinentry policy the user
//! has configured.
//!
//! # Why shell out at startup
//!
//! Reading `GnuPG`'s keybox/keyring formats directly is fiddly and version
//! dependent. Running `gpg --export <fpr>` exactly once at construction time to
//! obtain the binary certificate — which is then parsed with
//! [`Cert::from_bytes`] — is simple and robust. This happens a single time per
//! [`Gpg`] instance, never per encrypt/decrypt operation.

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use sequoia_gpg_agent as gpg_agent;
use sequoia_openpgp as openpgp;

use gpg_agent::KeyPair;
use gpg_agent::gnupg;
use openpgp::KeyID;
use openpgp::cert::Cert;
use openpgp::crypto::SessionKey;
use openpgp::packet::{PKESK, SKESK};
use openpgp::parse::Parse;
use openpgp::parse::stream::{
    DecryptionHelper, DecryptorBuilder, MessageStructure, VerificationHelper,
};
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Encryptor, LiteralWriter, Message};
use openpgp::types::SymmetricAlgorithm;
use std::collections::HashMap;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Flatten a Sequoia (`anyhow`) error into [`Error::OpenPgp`] without taking a
/// direct dependency on `anyhow`.
fn pgp_err<E: std::fmt::Display>(e: E) -> Error {
    Error::OpenPgp(e.to_string())
}

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
    /// Construct a [`Gpg`] using the default `GnuPG` home (honouring `GNUPGHOME`).
    ///
    /// If `key_fpr` is `None`, the first available secret key is used as the
    /// recipient.
    pub fn new(key_fpr: Option<&str>) -> Result<Self> {
        let ctx = gnupg::Context::new().map_err(pgp_err)?;
        Self::from_context(&ctx, key_fpr)
    }

    /// Construct a [`Gpg`] rooted at an explicit `GnuPG` home directory.
    ///
    /// This keeps operations hermetic (tests, sandboxed daemons) by never
    /// touching the ambient `~/.gnupg`.
    pub fn with_homedir(homedir: &Path, key_fpr: Option<&str>) -> Result<Self> {
        let ctx = gnupg::Context::with_homedir(homedir).map_err(pgp_err)?;
        Self::from_context(&ctx, key_fpr)
    }

    /// Shared construction path: resolve the fingerprint, export and parse the
    /// public certificate.
    fn from_context(ctx: &gnupg::Context, key_fpr: Option<&str>) -> Result<Self> {
        let homedir = ctx.homedir().map(Path::to_path_buf);

        let fingerprint = match key_fpr {
            Some(fpr) => fpr.to_string(),
            None => default_secret_fingerprint(homedir.as_deref())?,
        };

        let cert = export_cert(homedir.as_deref(), &fingerprint)?;
        // Normalise to the certificate's actual primary fingerprint.
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

    /// Encrypt `plaintext` to the recipient certificate, returning binary
    /// (non-armored) `OpenPGP` ciphertext.
    ///
    /// The message is encrypted to every valid, live, non-revoked encryption
    /// subkey (storage and transport). This is a purely local operation and
    /// requires no agent interaction.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let policy = StandardPolicy::new();

        let recipients: Vec<_> = self
            .cert
            .keys()
            .with_policy(&policy, None)
            .supported()
            .alive()
            .revoked(false)
            .for_storage_encryption()
            .for_transport_encryption()
            .collect();

        if recipients.is_empty() {
            return Err(Error::OpenPgp(format!(
                "certificate {} has no usable encryption subkey",
                self.fingerprint
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

    /// Decrypt `ciphertext` produced by [`encrypt`](Self::encrypt) via the
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

        tokio::task::spawn_blocking(move || decrypt_blocking(homedir.as_deref(), &cert, &ct))
            .await
            .map_err(|e| Error::OpenPgp(format!("decrypt task failed: {e}")))?
    }
}

/// Run the synchronous Sequoia decryption pipeline against `gpg-agent`.
fn decrypt_blocking(
    homedir: Option<&Path>,
    cert: &Cert,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let ctx = match homedir {
        Some(h) => gnupg::Context::with_homedir(h),
        None => gnupg::Context::new(),
    }
    .map_err(pgp_err)?;

    let policy = StandardPolicy::new();
    let helper = AgentHelper::new(&ctx, &policy, cert)?;

    let mut decryptor = DecryptorBuilder::from_bytes(ciphertext)
        .map_err(pgp_err)?
        .with_policy(&policy, None, helper)
        .map_err(pgp_err)?;

    let mut out = Vec::new();
    io::copy(&mut decryptor, &mut out)?;
    Ok(Zeroizing::new(out))
}

/// A [`DecryptionHelper`] that unlocks PKESKs through `gpg-agent` keypairs.
struct AgentHelper {
    keys: HashMap<KeyID, KeyPair>,
}

impl AgentHelper {
    /// Build agent-backed keypairs for the certificate's encryption subkeys.
    fn new(ctx: &gnupg::Context, policy: &StandardPolicy, cert: &Cert) -> Result<Self> {
        let mut keys = HashMap::new();
        for ka in cert
            .keys()
            .with_policy(policy, None)
            .for_storage_encryption()
            .for_transport_encryption()
        {
            let pair = KeyPair::new_for_gnupg_context(ctx, ka.key()).map_err(pgp_err)?;
            keys.insert(ka.key().keyid(), pair);
        }
        if keys.is_empty() {
            return Err(Error::OpenPgp(
                "certificate has no encryption subkey to decrypt with".into(),
            ));
        }
        Ok(Self { keys })
    }
}

impl DecryptionHelper for AgentHelper {
    fn decrypt(
        &mut self,
        pkesks: &[PKESK],
        _skesks: &[SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> openpgp::Result<Option<Cert>> {
        for pkesk in pkesks {
            let keyid = pkesk.recipient().map_or_else(KeyID::wildcard, KeyID::from);
            if let Some(pair) = self.keys.get_mut(&keyid)
                && pkesk
                    .decrypt(pair, sym_algo)
                    .is_some_and(|(algo, session_key)| decrypt(algo, &session_key))
            {
                break;
            }
        }
        Ok(None)
    }
}

impl VerificationHelper for AgentHelper {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        Ok(Vec::new())
    }

    fn check(&mut self, _structure: MessageStructure) -> openpgp::Result<()> {
        // Secrets are encrypted to ourselves, not signed; nothing to verify.
        Ok(())
    }
}

/// Build a `gpg` command scoped to `homedir` (if any) and non-interactive.
fn gpg_command(homedir: Option<&Path>) -> Command {
    let mut cmd = Command::new("gpg");
    cmd.arg("--batch").arg("--no-tty");
    if let Some(h) = homedir {
        cmd.arg("--homedir").arg(h);
    }
    cmd
}

/// Export the binary public certificate for `fingerprint` via `gpg --export`.
fn export_cert(homedir: Option<&Path>, fingerprint: &str) -> Result<Cert> {
    let output = gpg_command(homedir)
        .arg("--export")
        .arg(fingerprint)
        .output()?;
    if !output.status.success() {
        return Err(Error::OpenPgp(format!(
            "`gpg --export {fingerprint}` failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    if output.stdout.is_empty() {
        return Err(Error::NotFound(format!("gpg certificate {fingerprint}")));
    }
    Cert::from_bytes(&output.stdout).map_err(pgp_err)
}

/// Resolve the fingerprint of the first available secret key.
///
/// Parses `gpg --list-secret-keys --with-colons`, taking the `fpr` line that
/// follows the first `sec` record (field index 9 in the colon format).
fn default_secret_fingerprint(homedir: Option<&Path>) -> Result<String> {
    let output = gpg_command(homedir)
        .arg("--list-secret-keys")
        .arg("--with-colons")
        .output()?;
    if !output.status.success() {
        return Err(Error::OpenPgp(format!(
            "`gpg --list-secret-keys` failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let mut seen_sec = false;
    for line in text.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        match fields.first().copied() {
            Some("sec") => seen_sec = true,
            Some("fpr") if seen_sec => {
                if let Some(fpr) = fields.get(9)
                    && !fpr.is_empty()
                {
                    return Ok((*fpr).to_string());
                }
            }
            _ => {}
        }
    }
    Err(Error::NotFound("no gpg secret key available".into()))
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Shared test fixture: an ephemeral, hermetic `GnuPG` home.

    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::process::Command;

    /// An ephemeral `GnuPG` home with a freshly generated, empty-passphrase key.
    ///
    /// Never touches the user's real `~/.gnupg`: every `gpg`/`gpgconf` call and
    /// every Sequoia context is scoped to this temporary directory. The agent
    /// is killed on drop.
    pub(crate) struct TestGnupg {
        dir: tempfile::TempDir,
    }

    impl TestGnupg {
        pub(crate) fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();

            // Allow loopback pinentry so key generation with an empty
            // passphrase works headlessly.
            fs::write(
                dir.path().join("gpg-agent.conf"),
                "allow-loopback-pinentry\n",
            )
            .unwrap();

            let status = Command::new("gpg")
                .args(["--batch", "--no-tty", "--homedir"])
                .arg(dir.path())
                .args([
                    "--pinentry-mode",
                    "loopback",
                    "--passphrase",
                    "",
                    "--quick-gen-key",
                    "noirpass test <t@t>",
                    "default",
                    "default",
                    "never",
                ])
                .status()
                .expect("spawn gpg");
            assert!(status.success(), "gpg --quick-gen-key failed");

            Self { dir }
        }

        pub(crate) fn path(&self) -> &Path {
            self.dir.path()
        }
    }

    impl Drop for TestGnupg {
        fn drop(&mut self) {
            let _ = Command::new("gpgconf")
                .arg("--homedir")
                .arg(self.dir.path())
                .args(["--kill", "gpg-agent"])
                .status();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::TestGnupg;
    use super::*;

    #[tokio::test]
    async fn encrypt_decrypt_roundtrip_via_agent() {
        let gnupg = TestGnupg::new();
        let gpg = Gpg::with_homedir(gnupg.path(), None).unwrap();
        assert!(!gpg.fingerprint().is_empty());

        let plaintext = b"a very secret value";
        let ciphertext = gpg.encrypt(plaintext).unwrap();
        // Binary OpenPGP, not ASCII armor.
        assert_ne!(&ciphertext[..], &plaintext[..]);
        assert!(!ciphertext.starts_with(b"-----BEGIN"));

        let recovered = gpg.decrypt(&ciphertext).await.unwrap();
        assert_eq!(&recovered[..], &plaintext[..]);
    }

    #[tokio::test]
    async fn decrypt_rejects_garbage() {
        let gnupg = TestGnupg::new();
        let gpg = Gpg::with_homedir(gnupg.path(), None).unwrap();
        assert!(gpg.decrypt(b"not a pgp message at all").await.is_err());
    }

    #[test]
    fn missing_key_errors() {
        let dir = tempfile::tempdir().unwrap();
        // An empty GnuPG home has no secret keys.
        let result = Gpg::with_homedir(dir.path(), None);
        assert!(matches!(result, Err(Error::NotFound(_))));
    }
}
