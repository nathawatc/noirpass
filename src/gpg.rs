//! `OpenPGP` at-rest encryption of secrets.
//!
//! Each secret is encrypted to the user's own `OpenPGP` certificate, so the
//! ciphertext on disk can only be recovered with the user's secret key. The
//! public recipient certificate is imported by `noirpass init` and loaded from
//! noirpass' own store at daemon startup. Every secret is encrypted in-process
//! with Sequoia. Decryption is delegated to the running `gpg-agent` over its
//! Assuan socket via `sequoia-gpg-agent`, so noirpass never holds private key
//! material itself and honours the user's passphrase/pinentry policy.

use std::io;
use std::path::{Path, PathBuf};

use sequoia_gpg_agent as gpg_agent;
use sequoia_openpgp as openpgp;

use gpg_agent::gnupg;
use gpg_agent::{Agent, KeyPair};
use openpgp::KeyID;
use openpgp::cert::Cert;
use openpgp::crypto::SessionKey;
use openpgp::packet::{PKESK, SKESK};
use openpgp::parse::Parse;
use openpgp::parse::stream::{
    DecryptionHelper, DecryptorBuilder, MessageStructure, VerificationHelper,
};
use openpgp::policy::StandardPolicy;
use openpgp::serialize::Serialize;
use openpgp::serialize::stream::{Encryptor, LiteralWriter, Message};
use openpgp::types::{KeyFlags, SymmetricAlgorithm};
use std::collections::HashMap;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Flatten a Sequoia (`anyhow`) error into [`Error::OpenPgp`] without taking a
/// direct dependency on `anyhow`.
fn pgp_err<E: std::fmt::Display>(e: E) -> Error {
    Error::OpenPgp(e.to_string())
}

fn encryption_key_flags() -> KeyFlags {
    KeyFlags::empty()
        .set_storage_encryption()
        .set_transport_encryption()
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
    /// Construct a [`Gpg`] from the configured recipient certificate.
    pub fn from_cert(cert: Cert) -> Result<Self> {
        Self::from_cert_with_homedir(cert, None)
    }

    /// Construct a [`Gpg`] from a cert and explicit `GNUPGHOME` for tests.
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
        ensure_recipient_secret_available(homedir.as_deref(), &cert)
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
        let policy = StandardPolicy::new();

        let recipients: Vec<_> = self
            .cert
            .keys()
            .with_policy(&policy, None)
            .supported()
            .alive()
            .revoked(false)
            .key_flags(encryption_key_flags())
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

/// Parse an armored or binary `OpenPGP` recipient certificate.
pub fn parse_recipient_cert(bytes: &[u8]) -> Result<Cert> {
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
    cert.keys()
        .with_policy(&policy, None)
        .supported()
        .alive()
        .revoked(false)
        .key_flags(encryption_key_flags())
        .next()
        .is_some()
}

async fn ensure_recipient_secret_available(homedir: Option<&Path>, cert: &Cert) -> Result<()> {
    let ctx = match homedir {
        Some(h) => gnupg::Context::with_homedir(h),
        None => gnupg::Context::new(),
    }
    .map_err(pgp_err)?;

    let mut agent = Agent::connect(&ctx).await.map_err(pgp_err)?;
    let policy = StandardPolicy::new();
    let mut checked = 0usize;
    for ka in cert
        .keys()
        .with_policy(&policy, None)
        .supported()
        .alive()
        .revoked(false)
        .key_flags(encryption_key_flags())
    {
        checked += 1;
        if agent
            .has_key(ka.key().role_as_unspecified())
            .await
            .map_err(pgp_err)?
        {
            return Ok(());
        }
    }

    if checked == 0 {
        return Err(Error::OpenPgp(
            "certificate has no usable encryption-capable key".into(),
        ));
    }
    Err(Error::OpenPgp(
        "gpg-agent has none of the configured recipient secret keys".into(),
    ))
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
            .key_flags(encryption_key_flags())
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

#[cfg(test)]
pub(crate) mod test_support {
    //! Shared test fixture: an ephemeral, hermetic `GnuPG` home.

    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::process::Command;

    use sequoia_openpgp::Cert;
    use sequoia_openpgp::serialize::Serialize;

    /// An ephemeral `GnuPG` home with a freshly generated, empty-passphrase key.
    ///
    /// Never touches the user's real `~/.gnupg`: every `gpg`/`gpgconf` call and
    /// every Sequoia context is scoped to this temporary directory. The agent
    /// is killed on drop.
    pub struct TestGnupg {
        dir: tempfile::TempDir,
        fingerprint: String,
    }

    impl TestGnupg {
        pub fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();

            // Allow loopback pinentry so key generation with an empty
            // passphrase works headlessly.
            fs::write(
                dir.path().join("gpg-agent.conf"),
                "allow-loopback-pinentry\n",
            )
            .unwrap();

            Self::from_dir_with(dir, |path| {
                let status = Command::new("gpg")
                    .args(["--batch", "--no-tty", "--homedir"])
                    .arg(path)
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
            })
        }

        pub fn import(cert: &Cert) -> Self {
            let dir = tempfile::tempdir().unwrap();
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();

            fs::write(
                dir.path().join("gpg-agent.conf"),
                "allow-loopback-pinentry\n",
            )
            .unwrap();

            Self::from_dir_with(dir, |path| {
                let mut tsk = Vec::new();
                cert.as_tsk().serialize(&mut tsk).unwrap();
                let mut child = Command::new("gpg")
                    .args(["--batch", "--no-tty", "--homedir"])
                    .arg(path)
                    .arg("--import")
                    .stdin(std::process::Stdio::piped())
                    .spawn()
                    .expect("spawn gpg --import");
                child.stdin.as_mut().unwrap().write_all(&tsk).unwrap();
                let status = child.wait().expect("wait gpg --import");
                assert!(status.success(), "gpg --import failed");
            })
        }

        fn from_dir_with(dir: tempfile::TempDir, init: impl FnOnce(&Path)) -> Self {
            init(dir.path());
            let status = Command::new("gpg")
                .args(["--batch", "--no-tty", "--homedir"])
                .arg(dir.path())
                .arg("--list-secret-keys")
                .status()
                .expect("spawn gpg --list-secret-keys");
            assert!(status.success(), "gpg --list-secret-keys failed");

            let fingerprint = secret_fingerprint(dir.path());
            Self { dir, fingerprint }
        }

        pub fn path(&self) -> &Path {
            self.dir.path()
        }

        pub fn fingerprint(&self) -> &str {
            &self.fingerprint
        }

        pub fn export_public_binary(&self) -> Vec<u8> {
            export_public(self.dir.path(), &self.fingerprint, false)
        }

        pub fn export_public_armored(&self) -> Vec<u8> {
            export_public(self.dir.path(), &self.fingerprint, true)
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

    fn export_public(homedir: &Path, fingerprint: &str, armor: bool) -> Vec<u8> {
        let mut cmd = Command::new("gpg");
        cmd.args(["--batch", "--no-tty", "--homedir"]).arg(homedir);
        if armor {
            cmd.arg("--armor");
        }
        let output = cmd
            .arg("--export")
            .arg(fingerprint)
            .output()
            .expect("gpg export");
        assert!(output.status.success(), "gpg --export failed");
        output.stdout
    }

    fn secret_fingerprint(homedir: &Path) -> String {
        let output = Command::new("gpg")
            .args(["--batch", "--no-tty", "--homedir"])
            .arg(homedir)
            .args(["--list-secret-keys", "--with-colons"])
            .output()
            .expect("gpg list secret keys");
        assert!(output.status.success(), "gpg --list-secret-keys failed");

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
                        return (*fpr).to_string();
                    }
                }
                _ => {}
            }
        }
        panic!("test gpg key has no fingerprint")
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::TestGnupg;
    use super::*;
    use sequoia_openpgp::cert::CertBuilder;

    #[tokio::test]
    async fn encrypt_decrypt_roundtrip_via_agent() {
        let gnupg = TestGnupg::new();
        let cert = parse_recipient_cert(&gnupg.export_public_binary()).unwrap();
        let gpg = Gpg::from_cert_with_homedir(cert, Some(gnupg.path().to_path_buf())).unwrap();
        assert_eq!(gpg.fingerprint(), gnupg.fingerprint());
        gpg.ensure_recipient_secret_available().await.unwrap();

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
        let cert = parse_recipient_cert(&gnupg.export_public_binary()).unwrap();
        let gpg = Gpg::from_cert_with_homedir(cert, Some(gnupg.path().to_path_buf())).unwrap();
        assert!(gpg.decrypt(b"not a pgp message at all").await.is_err());
    }

    #[test]
    fn encrypt_uses_configured_recipient_cert() {
        let one = TestGnupg::new();
        let two = TestGnupg::new();
        let cert = parse_recipient_cert(&two.export_public_binary()).unwrap();
        let gpg = Gpg::from_cert(cert).unwrap();

        assert_eq!(gpg.fingerprint(), two.fingerprint());
        assert_ne!(gpg.fingerprint(), one.fingerprint());
    }

    #[tokio::test]
    async fn recipient_secret_check_rejects_wrong_gnupg_home() {
        let one = TestGnupg::new();
        let two = TestGnupg::new();
        let cert = parse_recipient_cert(&two.export_public_binary()).unwrap();
        let gpg = Gpg::from_cert_with_homedir(cert, Some(one.path().to_path_buf())).unwrap();

        let err = gpg.ensure_recipient_secret_available().await.unwrap_err();

        assert!(err.to_string().contains("no available GnuPG secret key"));
    }

    fn storage_only_cert() -> Cert {
        CertBuilder::new()
            .add_userid("storage-only <storage@test>")
            .add_storage_encryption_subkey()
            .generate()
            .unwrap()
            .0
    }

    fn transport_only_cert() -> Cert {
        CertBuilder::new()
            .add_userid("transport-only <transport@test>")
            .add_transport_encryption_subkey()
            .generate()
            .unwrap()
            .0
    }

    #[test]
    fn has_usable_encryption_key_accepts_storage_only_subkey() {
        assert!(has_usable_encryption_key(&storage_only_cert()));
    }

    #[test]
    fn has_usable_encryption_key_accepts_transport_only_subkey() {
        assert!(has_usable_encryption_key(&transport_only_cert()));
    }

    #[tokio::test]
    async fn encrypt_decrypt_roundtrip_via_agent_with_storage_only_subkey() {
        let cert = storage_only_cert();
        let gnupg = TestGnupg::import(&cert);
        let gpg = Gpg::from_cert_with_homedir(cert, Some(gnupg.path().to_path_buf())).unwrap();

        let plaintext = b"storage-only secret";
        let ciphertext = gpg.encrypt(plaintext).unwrap();
        let recovered = gpg.decrypt(&ciphertext).await.unwrap();

        assert_eq!(&recovered[..], &plaintext[..]);
    }

    #[tokio::test]
    async fn encrypt_decrypt_roundtrip_via_agent_with_transport_only_subkey() {
        let cert = transport_only_cert();
        let gnupg = TestGnupg::import(&cert);
        let gpg = Gpg::from_cert_with_homedir(cert, Some(gnupg.path().to_path_buf())).unwrap();

        let plaintext = b"transport-only secret";
        let ciphertext = gpg.encrypt(plaintext).unwrap();
        let recovered = gpg.decrypt(&ciphertext).await.unwrap();

        assert_eq!(&recovered[..], &plaintext[..]);
    }
}
