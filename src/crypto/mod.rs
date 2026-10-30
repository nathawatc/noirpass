//! Secret Service session encryption algorithms.
//!
//! A Secret Service session negotiates how secrets are transported between the
//! client and the daemon. noirpass supports the two algorithms mandated by the
//! specification and implemented by every real client (libsecret, oo7,
//! gnome-keyring):
//!
//! * `plain` — no transport encryption; the secret bytes are passed through
//!   unchanged (used over the private per-connection D-Bus socket).
//! * `dh-ietf1024-sha256-aes128-cbc-pkcs7` — an unauthenticated Diffie-Hellman
//!   key agreement over the 1024-bit MODP group (RFC 2409, Second Oakley
//!   Group), the shared secret run through HKDF-SHA256 (no salt, empty info) to
//!   yield a 128-bit key, and payloads encrypted with AES-128-CBC/PKCS7.
//!
//! The handshake is:
//! ```text
//!   let hs = DhHandshake::generate();
//!   // send hs.public_bytes() to the client, receive the client's public key
//!   let cipher = hs.derive(&client_public)?;   // -> SessionCipher::Dh
//! ```

use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
use hkdf::Hkdf;
use num_bigint_dig::BigUint;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

/// The 1024-bit MODP group prime `p` from RFC 2409 (Second Oakley Group).
const MODP_1024_PRIME_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1",
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD",
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245",
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381",
    "FFFFFFFFFFFFFFFF",
);

/// Byte length of a group element (1024 bits = 128 bytes).
const GROUP_BYTES: usize = 128;

/// The prime modulus of the MODP group.
fn prime() -> BigUint {
    BigUint::parse_bytes(MODP_1024_PRIME_HEX.as_bytes(), 16).expect("MODP prime is valid hex")
}

/// Left-pad a big-endian integer's bytes to exactly `GROUP_BYTES`.
///
/// The shared secret passed to HKDF must retain the group's full width;
/// incoming public integers may use variable-width unsigned encoding.
fn pad_be(value: &BigUint) -> Vec<u8> {
    let raw = Zeroizing::new(value.to_bytes_be());
    debug_assert!(raw.len() <= GROUP_BYTES);
    let mut out = vec![0u8; GROUP_BYTES - raw.len()];
    out.extend_from_slice(raw.as_slice());
    out
}

/// A negotiated session cipher.
pub enum SessionCipher {
    /// No transport encryption; payloads pass through unchanged.
    Plain,
    /// Diffie-Hellman derived AES-128-CBC transport encryption.
    Dh(DhKey),
}

/// The derived symmetric key of a `dh-ietf1024-sha256-aes128-cbc-pkcs7` session.
pub struct DhKey {
    key: Zeroizing<[u8; 16]>,
}

/// An in-progress server-side Diffie-Hellman handshake.
///
/// Holds the server's private exponent and matching public key until the
/// client's public key arrives and the shared key is derived.
pub struct DhHandshake {
    private: Zeroizing<BigUint>,
    public: BigUint,
}

impl DhHandshake {
    /// Start a handshake with a fresh random 128-byte (1024-bit) private
    /// exponent and compute the matching public key `g^priv mod p`.
    #[must_use]
    pub fn generate() -> Self {
        let private_bytes = {
            // 128 random bytes; the group order is ~2^1024 so this is a valid
            // exponent with overwhelming probability.
            let mut buf = Zeroizing::new([0u8; GROUP_BYTES]);
            rand::fill(&mut *buf);
            buf
        };
        Self::from_private_bytes(&private_bytes[..])
    }

    /// Build a handshake from an explicit private exponent (used for
    /// deterministic tests and known-answer vectors).
    fn from_private_bytes(private_bytes: &[u8]) -> Self {
        let p = prime();
        let g = BigUint::from(2u32);
        let private = Zeroizing::new(BigUint::from_bytes_be(private_bytes));
        let public = g.modpow(&private, &p);
        Self { private, public }
    }

    /// The server's public key as a fixed 128-byte big-endian value, ready to
    /// send to the client.
    #[must_use]
    pub fn public_bytes(&self) -> Vec<u8> {
        pad_be(&self.public)
    }

    /// Complete the handshake with the client's public key, producing the
    /// session cipher.
    ///
    /// The client public key is rejected if it is not a proper group element
    /// (`<= 1` or `>= p - 1`), which rules out the small-subgroup values that
    /// would collapse the shared secret.
    pub fn derive(self, client_public: &[u8]) -> Result<SessionCipher> {
        let p = prime();
        let one = BigUint::from(1u32);
        let p_minus_one = &p - &one;
        let significant = match client_public.iter().position(|byte| *byte != 0) {
            Some(offset) => &client_public[offset..],
            None => &[],
        };
        if significant.len() > GROUP_BYTES {
            return Err(Error::Crypto(
                "client public key exceeds the 1024-bit group size".into(),
            ));
        }
        let client = BigUint::from_bytes_be(significant);

        if client <= one || client >= p_minus_one {
            return Err(Error::Crypto(
                "client public key is outside the valid group range".into(),
            ));
        }

        let shared = Zeroizing::new(client.modpow(&self.private, &p));
        let ikm = Zeroizing::new(pad_be(&shared));

        // HKDF-SHA256 with no salt and empty info, per the spec / libsecret.
        let hk = Hkdf::<Sha256>::new(None, ikm.as_slice());
        let mut key = Zeroizing::new([0u8; 16]);
        hk.expand(&[], key.as_mut())
            .map_err(|e| Error::Crypto(format!("HKDF expand failed: {e}")))?;

        Ok(SessionCipher::Dh(DhKey { key }))
    }
}

impl SessionCipher {
    /// Encrypt `plaintext`, returning `(iv, ciphertext)`.
    ///
    /// For [`SessionCipher::Plain`] the IV is empty and the plaintext is
    /// returned unchanged. For a DH session a fresh random 16-byte IV is used
    /// with AES-128-CBC/PKCS7.
    #[must_use]
    pub fn encrypt(&self, plaintext: &[u8]) -> (Vec<u8>, Zeroizing<Vec<u8>>) {
        match self {
            SessionCipher::Plain => (Vec::new(), Zeroizing::new(plaintext.to_vec())),
            SessionCipher::Dh(dh) => {
                let iv: [u8; 16] = rand::random();
                // Exact padded length: always at least one full padding block.
                let padded_len = (plaintext.len() / 16 + 1) * 16;
                let mut buf = Zeroizing::new(vec![0u8; padded_len]);
                buf[..plaintext.len()].copy_from_slice(plaintext);
                let ct = Zeroizing::new(
                    Aes128CbcEnc::new_from_slices(&dh.key[..], &iv)
                        .expect("fixed-size AES key and IV")
                        .encrypt_padded::<Pkcs7>(&mut buf[..], plaintext.len())
                        .expect("buffer sized for PKCS7 padding")
                        .to_vec(),
                );
                (iv.to_vec(), ct)
            }
        }
    }

    /// Decrypt `(iv, ciphertext)` back to plaintext.
    ///
    /// For [`SessionCipher::Plain`] the ciphertext is returned unchanged. For a
    /// DH session, a bad IV length or corrupted padding yields
    /// [`Error::Crypto`].
    pub fn decrypt(&self, iv: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        match self {
            SessionCipher::Plain => Ok(Zeroizing::new(ciphertext.to_vec())),
            SessionCipher::Dh(dh) => {
                let iv: [u8; 16] = iv
                    .try_into()
                    .map_err(|_| Error::Crypto("IV must be 16 bytes".into()))?;
                let mut buf = Zeroizing::new(ciphertext.to_vec());
                let plaintext_len = Aes128CbcDec::new_from_slices(&dh.key[..], &iv)
                    .expect("fixed-size AES key and IV")
                    .decrypt_padded::<Pkcs7>(&mut buf[..])
                    .map_err(|e| Error::Crypto(format!("AES-CBC decrypt failed: {e}")))?
                    .len();
                buf.truncate(plaintext_len);
                Ok(buf)
            }
        }
    }
}

#[cfg(test)]
mod tests;
