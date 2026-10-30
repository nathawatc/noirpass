//! GPG-agent-backed recipient secret lookup and decryption.

use std::collections::HashMap;
use std::io;
use std::path::Path;

use sequoia_gpg_agent as gpg_agent;
use sequoia_openpgp as openpgp;

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
use openpgp::types::SymmetricAlgorithm;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

use super::cert::{encryption_key_flags, pgp_err, usable_encryption_keys};

pub(super) async fn ensure_recipient_secret_available(
    homedir: Option<&Path>,
    cert: &Cert,
) -> Result<()> {
    let socket = super::socket::agent_socket(homedir)?;

    let mut agent = Agent::connect_to_agent(&socket).await.map_err(pgp_err)?;
    let policy = StandardPolicy::new();
    let mut checked = 0usize;
    for ka in usable_encryption_keys(cert, &policy) {
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
pub(super) fn decrypt_blocking(
    homedir: Option<&Path>,
    cert: &Cert,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let socket = super::socket::agent_socket(homedir)?;

    let policy = StandardPolicy::new();
    let helper = AgentHelper::new(&socket, &policy, cert)?;

    let mut decryptor = DecryptorBuilder::from_bytes(ciphertext)
        .map_err(pgp_err)?
        .with_policy(&policy, None, helper)
        .map_err(pgp_err)?;

    let mut out = Zeroizing::new(Vec::new());
    io::copy(&mut decryptor, &mut *out)?;
    Ok(out)
}

/// A [`DecryptionHelper`] that unlocks PKESKs through `gpg-agent` keypairs.
struct AgentHelper {
    keys: HashMap<KeyID, KeyPair>,
}

impl AgentHelper {
    /// Build agent-backed keypairs for the certificate's encryption subkeys.
    fn new(socket: &Path, policy: &StandardPolicy, cert: &Cert) -> Result<Self> {
        let mut keys = HashMap::new();
        for ka in cert
            .keys()
            .with_policy(policy, None)
            .key_flags(encryption_key_flags())
        {
            let pair = KeyPair::new_for_socket(socket, ka.key()).map_err(pgp_err)?;
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
