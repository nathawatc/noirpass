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

    let a_pub = a.public_bytes();
    let b_pub = b.public_bytes();
    let ca = a.derive(&b_pub).unwrap();
    let cb = b.derive(&a_pub).unwrap();

    let (SessionCipher::Dh(ka), SessionCipher::Dh(kb)) = (&ca, &cb) else {
        panic!("expected DH")
    };
    assert_eq!(ka.key.as_ref(), kb.key.as_ref());
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
    let p_minus_one = p - BigUint::from(1u32);
    assert!(make().derive(&pad_be(&p_minus_one)).is_err());
    assert!(make().derive(&pad_be(p)).is_err());
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
fn malformed_ciphertext_fails() {
    let server = DhHandshake::generate();
    let client = DhHandshake::generate();
    let cipher = server.derive(&client.public_bytes()).unwrap();
    let (iv, _) = cipher.encrypt(b"");

    assert!(cipher.decrypt(&iv, &[]).is_err());
    assert!(cipher.decrypt(&iv, &[0u8; 15]).is_err());
    assert!(cipher.decrypt(&iv, &[0u8; 17]).is_err());
    assert!(cipher.decrypt(&iv[..15], &[]).is_err());
}

#[test]
fn plain_passthrough() {
    let cipher = SessionCipher::Plain;
    let (iv, ct) = cipher.encrypt(b"hello");
    assert_eq!(iv.len(), 0);
    assert_eq!(ct.as_slice(), b"hello");
    let pt = cipher.decrypt(&iv, &ct).unwrap();
    assert_eq!(&pt[..], b"hello");
}

#[test]
fn respond_validates_client_public_and_derives_matching_key() {
    let p = prime();
    for bad in [
        pad_be(&BigUint::from(0u32)),
        pad_be(&BigUint::from(1u32)),
        pad_be(&(p - BigUint::from(1u32))),
        pad_be(p),
        vec![0xff; GROUP_BYTES + 1],
    ] {
        assert!(matches!(DhHandshake::respond(&bad), Err(Error::Crypto(_))));
    }

    let client = DhHandshake::generate();
    let (server_pub, server_cipher) = DhHandshake::respond(&client.public_bytes()).unwrap();
    let client_cipher = client.derive(&server_pub).unwrap();
    let (iv, ct) = server_cipher.encrypt(b"respond secret");
    assert_eq!(
        &client_cipher.decrypt(&iv, &ct).unwrap()[..],
        b"respond secret"
    );
}
