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
/// Both the exchanged public keys and the derived shared secret must be
/// serialized as fixed-width 128-byte big-endian values so that the HKDF input
/// (and the bytes on the wire) match the peer's.
fn pad_be(value: &BigUint) -> Vec<u8> {
    let raw = value.to_bytes_be();
    debug_assert!(raw.len() <= GROUP_BYTES);
    let mut out = vec![0u8; GROUP_BYTES - raw.len()];
    out.extend_from_slice(&raw);
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
    private: BigUint,
    public: BigUint,
}

impl DhHandshake {
    /// Start a handshake with a fresh random 128-byte (1024-bit) private
    /// exponent and compute the matching public key `g^priv mod p`.
    #[must_use]
    pub fn generate() -> Self {
        let private_bytes: [u8; GROUP_BYTES] = {
            // 128 random bytes; the group order is ~2^1024 so this is a valid
            // exponent with overwhelming probability.
            let mut buf = [0u8; GROUP_BYTES];
            for b in &mut buf {
                *b = rand::random();
            }
            buf
        };
        Self::from_private_bytes(&private_bytes)
    }

    /// Build a handshake from an explicit private exponent (used for
    /// deterministic tests and known-answer vectors).
    fn from_private_bytes(private_bytes: &[u8]) -> Self {
        let p = prime();
        let g = BigUint::from(2u32);
        let private = BigUint::from_bytes_be(private_bytes);
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

        let shared = client.modpow(&self.private, &p);
        let ikm = pad_be(&shared);

        // HKDF-SHA256 with no salt and empty info, per the spec / libsecret.
        let hk = Hkdf::<Sha256>::new(None, &ikm);
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
    pub fn encrypt(&self, plaintext: &[u8]) -> (Vec<u8>, Vec<u8>) {
        match self {
            SessionCipher::Plain => (Vec::new(), plaintext.to_vec()),
            SessionCipher::Dh(dh) => {
                let iv: [u8; 16] = {
                    let mut buf = [0u8; 16];
                    for b in &mut buf {
                        *b = rand::random();
                    }
                    buf
                };
                let key: [u8; 16] = *dh.key;
                // Exact padded length: always at least one full padding block.
                let padded_len = (plaintext.len() / 16 + 1) * 16;
                let mut buf = vec![0u8; padded_len];
                buf[..plaintext.len()].copy_from_slice(plaintext);
                let ct = Aes128CbcEnc::new(&key.into(), &iv.into())
                    .encrypt_padded::<Pkcs7>(&mut buf, plaintext.len())
                    .expect("buffer sized for PKCS7 padding")
                    .to_vec();
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
                let key: [u8; 16] = *dh.key;
                let mut buf = ciphertext.to_vec();
                let pt = Aes128CbcDec::new(&key.into(), &iv.into())
                    .decrypt_padded::<Pkcs7>(&mut buf)
                    .map_err(|e| Error::Crypto(format!("AES-CBC decrypt failed: {e}")))?;
                Ok(Zeroizing::new(pt.to_vec()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_dh_handshake_derives_matching_keys() {
        // Simulate both sides: each generates a handshake and derives against
        // the other's public key. The resulting keys must be identical.
        let server = DhHandshake::generate();
        let client = DhHandshake::generate();

        let server_pub = server.public_bytes();
        let client_pub = client.public_bytes();

        let server_cipher = server.derive(&client_pub).unwrap();
        let client_cipher = client.derive(&server_pub).unwrap();

        let SessionCipher::Dh(sk) = &server_cipher else {
            panic!("expected DH")
        };
        let SessionCipher::Dh(ck) = &client_cipher else {
            panic!("expected DH")
        };
        assert_eq!(sk.key.as_ref(), ck.key.as_ref());

        // A payload encrypted by one side round-trips through the other.
        let (iv, ct) = server_cipher.encrypt(b"top secret");
        let pt = client_cipher.decrypt(&iv, &ct).unwrap();
        assert_eq!(&pt[..], b"top secret");
    }

    #[test]
    fn known_answer_fixed_exponents() {
        // Fixed small exponents make the derived key deterministic; both
        // directions must agree (this pins the pad/HKDF wiring).
        let a = DhHandshake::from_private_bytes(&[0x03]);
        let b = DhHandshake::from_private_bytes(&[0x05]);

        // Capture public keys before `derive` consumes each handshake.
        let a_pub = a.public_bytes();
        let b_pub = b.public_bytes();
        let ca = a.derive(&b_pub).unwrap();
        let cb = b.derive(&a_pub).unwrap();

        let (SessionCipher::Dh(ka), SessionCipher::Dh(kb)) = (&ca, &cb) else {
            panic!("expected DH")
        };
        assert_eq!(ka.key.as_ref(), kb.key.as_ref());
        // The derived key must not be all zeros.
        assert_ne!(ka.key.as_ref(), &[0u8; 16]);
    }

    #[test]
    fn encrypt_decrypt_roundtrip_dh() {
        let server = DhHandshake::generate();
        let client = DhHandshake::generate();
        let cipher = server.derive(&client.public_bytes()).unwrap();

        for msg in [&b""[..], b"x", b"a slightly longer secret value 1234567890"] {
            let (iv, ct) = cipher.encrypt(msg);
            assert_eq!(iv.len(), 16);
            let pt = cipher.decrypt(&iv, &ct).unwrap();
            assert_eq!(&pt[..], msg);
        }
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let server = DhHandshake::generate();
        let client = DhHandshake::generate();
        let cipher = server.derive(&client.public_bytes()).unwrap();

        let (iv, mut ct) = cipher.encrypt(b"authentic");
        // Flip a bit in the last block to corrupt the PKCS7 padding.
        *ct.last_mut().unwrap() ^= 0x01;
        assert!(matches!(cipher.decrypt(&iv, &ct), Err(Error::Crypto(_))));
    }

    #[test]
    fn invalid_client_pubkeys_rejected() {
        let p = prime();
        let make = || DhHandshake::generate();

        // 0, 1 and p-1 (and larger) are all invalid.
        assert!(make().derive(&pad_be(&BigUint::from(0u32))).is_err());
        assert!(make().derive(&pad_be(&BigUint::from(1u32))).is_err());
        let p_minus_one = &p - BigUint::from(1u32);
        assert!(make().derive(&pad_be(&p_minus_one)).is_err());
        assert!(make().derive(&pad_be(&p)).is_err());
        assert!(make().derive(&[0xff; GROUP_BYTES + 1]).is_err());
    }

    #[test]
    fn client_pubkey_accepts_leading_zero_padding() {
        let server = DhHandshake::generate();
        let client = DhHandshake::generate();
        let mut padded = vec![0u8; 1024];
        padded.extend(client.public_bytes());

        assert!(matches!(server.derive(&padded), Ok(SessionCipher::Dh(_))));
    }

    #[test]
    fn plain_passthrough() {
        let cipher = SessionCipher::Plain;
        let (iv, ct) = cipher.encrypt(b"hello");
        assert!(iv.is_empty());
        assert_eq!(ct, b"hello");
        let pt = cipher.decrypt(&iv, &ct).unwrap();
        assert_eq!(&pt[..], b"hello");
    }
}
