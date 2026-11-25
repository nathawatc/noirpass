use super::test_support::TestGnupg;
use super::*;
use sequoia_openpgp::cert::CertBuilder;

#[tokio::test]
async fn encrypt_decrypt_roundtrip_via_agent() {
    let gnupg = TestGnupg::new();
    let cert = parse_recipient_cert(&gnupg.export_public_binary()).unwrap();
    let gpg = Gpg::from_cert_with_homedir(cert, Some(gnupg.path().to_path_buf()));
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
    let gpg = Gpg::from_cert_with_homedir(cert, Some(gnupg.path().to_path_buf()));
    assert!(gpg.decrypt(b"not a pgp message at all").await.is_err());
}

#[test]
fn encrypt_uses_configured_recipient_cert() {
    let one = TestGnupg::new();
    let two = TestGnupg::new();
    let cert = parse_recipient_cert(&two.export_public_binary()).unwrap();
    let gpg = Gpg::from_cert(cert);

    assert_eq!(gpg.fingerprint(), two.fingerprint());
    assert_ne!(gpg.fingerprint(), one.fingerprint());
}

#[tokio::test]
async fn recipient_secret_check_rejects_wrong_gnupg_home() {
    let one = TestGnupg::new();
    let two = TestGnupg::new();
    let cert = parse_recipient_cert(&two.export_public_binary()).unwrap();
    let gpg = Gpg::from_cert_with_homedir(cert, Some(one.path().to_path_buf()));

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
    let gpg = Gpg::from_cert_with_homedir(cert, Some(gnupg.path().to_path_buf()));

    let plaintext = b"storage-only secret";
    let ciphertext = gpg.encrypt(plaintext).unwrap();
    let recovered = gpg.decrypt(&ciphertext).await.unwrap();

    assert_eq!(&recovered[..], &plaintext[..]);
}

#[tokio::test]
async fn encrypt_decrypt_roundtrip_via_agent_with_transport_only_subkey() {
    let cert = transport_only_cert();
    let gnupg = TestGnupg::import(&cert);
    let gpg = Gpg::from_cert_with_homedir(cert, Some(gnupg.path().to_path_buf()));

    let plaintext = b"transport-only secret";
    let ciphertext = gpg.encrypt(plaintext).unwrap();
    let recovered = gpg.decrypt(&ciphertext).await.unwrap();

    assert_eq!(&recovered[..], &plaintext[..]);
}

#[tokio::test]
async fn agent_socket_matches_gnupg_and_does_not_restart_stopped_agent() {
    let gnupg = TestGnupg::new();
    let output = std::process::Command::new("gpgconf")
        .arg("--homedir")
        .arg(gnupg.path())
        .args(["--list-dirs", "agent-socket"])
        .output()
        .unwrap();
    assert!(output.status.success());
    // Fixture paths contain no percent-encoded characters.
    let expected = String::from_utf8(output.stdout).unwrap();
    let socket = super::socket::agent_socket(Some(gnupg.path())).unwrap();
    assert_eq!(socket, std::path::Path::new(expected.trim()));
    let cert = parse_recipient_cert(&gnupg.export_public_binary()).unwrap();
    let gpg = Gpg::from_cert_with_homedir(cert, Some(gnupg.path().to_path_buf()));
    gpg.ensure_recipient_secret_available().await.unwrap();
    let status = std::process::Command::new("gpgconf")
        .arg("--homedir")
        .arg(gnupg.path())
        .args(["--kill", "gpg-agent"])
        .status()
        .unwrap();
    assert!(status.success());
    assert!(gpg.ensure_recipient_secret_available().await.is_err());
    assert!(
        !socket.exists(),
        "Noirpass must not launch a replacement agent"
    );
}
