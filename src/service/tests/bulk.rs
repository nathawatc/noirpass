use std::collections::HashMap;

use zbus::zvariant::{LE, OwnedObjectPath, serialized::Context, to_bytes};
use zeroize::Zeroizing;

use super::super::{MAX_BULK_SECRET_BYTES, SecretError, insert_bulk_secret, secret_entry_bytes};
use crate::service::session::Secret;

#[tokio::test]
async fn persistent_bulk_rejects_large_item_but_individual_retrieval_remains_available() {
    use crate::crypto::SessionCipher;
    use crate::gpg::test_support::TestGnupg;

    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = super::test_state(&gnupg, tmp.path());
    let plaintext = Zeroizing::new(vec![11; MAX_BULK_SECRET_BYTES + 1]);
    let ciphertext = state.gpg().encrypt(&plaintext).unwrap();
    let meta = state
        .store()
        .create_item(
            "default",
            "large",
            HashMap::new(),
            "application/octet-stream",
            &ciphertext,
        )
        .unwrap();
    let session = state
        .register_session(SessionCipher::Plain, ":1.7".into())
        .unwrap();
    let path = super::super::item_path("default", &meta.id);
    assert!(matches!(
        state.secret_for_item_path(&path, &session, ":1.7").await,
        Err(SecretError::LimitsExceeded(_))
    ));
    let secret = state
        .persistent_secret("default", &meta.id, &session, ":1.7", None)
        .await
        .unwrap();
    assert_eq!(secret.value, plaintext);
    assert_eq!(secret.content_type, "application/octet-stream");
    assert!(matches!(
        state
            .persistent_secret("other", &meta.id, &session, ":1.7", None)
            .await,
        Err(SecretError::NoSuchObject(_))
    ));
}

#[test]
fn bulk_response_bounds_wire_size_and_refunds_replaced_paths() {
    let path = OwnedObjectPath::try_from("/item").unwrap();
    let mut secret = Secret {
        session: OwnedObjectPath::try_from("/session").unwrap(),
        parameters: vec![1; 16],
        value: Zeroizing::new(vec![7; MAX_BULK_SECRET_BYTES - 128]),
        content_type: "text/plain".into(),
    };
    let mut out = HashMap::new();
    let mut bytes = 8;
    insert_bulk_secret(&mut out, &mut bytes, path.clone(), secret.clone()).unwrap();
    insert_bulk_secret(&mut out, &mut bytes, path.clone(), secret.clone()).unwrap();
    assert_eq!(out.len(), 1);
    let serialized = to_bytes(Context::new_dbus(LE, 0), &out).unwrap();
    assert!(serialized.len() <= bytes);
    assert!(bytes <= MAX_BULK_SECRET_BYTES);
    drop(serialized);

    let before = bytes;
    let other = OwnedObjectPath::try_from("/other").unwrap();
    assert!(matches!(
        insert_bulk_secret(&mut out, &mut bytes, other, secret.clone()),
        Err(SecretError::LimitsExceeded(_))
    ));
    assert_eq!(bytes, before);
    assert_eq!(out.len(), 1);

    secret.value = Zeroizing::new(vec![8; 3]);
    insert_bulk_secret(&mut out, &mut bytes, path.clone(), secret.clone()).unwrap();
    assert_eq!(bytes, 8 + secret_entry_bytes(&path, &secret).unwrap());
    assert_eq!(out[&path].value.as_slice(), &[8; 3]);
    for length in 0..16 {
        let path = OwnedObjectPath::try_from(format!("/item{length}")).unwrap();
        secret.value = Zeroizing::new(vec![9; length]);
        insert_bulk_secret(&mut out, &mut bytes, path, secret.clone()).unwrap();
    }
    assert!(to_bytes(Context::new_dbus(LE, 0), &out).unwrap().len() <= bytes);
}
