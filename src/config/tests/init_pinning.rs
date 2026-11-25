use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

use sequoia_openpgp::serialize::Serialize;

use super::super::format::{atomic_write_in, atomic_write_in_with_sync};
use super::super::init::{init_from_cert_in_with_hooks, init_store_with_hook};
use super::super::{CONFIG_FILE, Config, INDEX_FILE, KEYS_DIR, RECIPIENT_REL, init_from_bytes};
use super::support::generated_recipient;
use crate::filesystem::Directory;
use crate::gpg::parse_recipient_cert;
use crate::store::Store;

#[test]
fn complete_initialization_stays_on_selected_root_after_replacement() {
    let (bytes, _) = generated_recipient();
    let cert = parse_recipient_cert(&bytes).unwrap();
    let (other, _) = generated_recipient();
    for existing in [false, true] {
        for link in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            let selected = tmp.path().join("selected");
            let moved = tmp.path().join("moved");
            let outside = tmp.path().join("outside");
            if existing {
                init_from_bytes(&selected, &bytes).unwrap();
                drop(Store::open(&selected).unwrap());
            } else {
                fs::create_dir(&selected).unwrap();
            }
            init_from_bytes(&outside, &other).unwrap();
            drop(Store::open(&outside).unwrap());
            let outside_config = fs::read(outside.join(CONFIG_FILE)).unwrap();
            let outside_cert = fs::read(outside.join(RECIPIENT_REL)).unwrap();
            let outside_index = fs::read(outside.join(INDEX_FILE)).unwrap();
            let config = init_store_with_hook(&selected, &cert, || {
                fs::rename(&selected, &moved).unwrap();
                if link {
                    symlink(&outside, &selected).unwrap();
                } else {
                    fs::rename(&outside, &selected).unwrap();
                }
            })
            .unwrap();
            assert_eq!(config.recipient_fingerprint, cert.fingerprint().to_hex());
            assert_eq!(Config::load(&moved).unwrap(), config);
            let store = Store::open_existing(&moved).unwrap();
            assert_eq!(store.get_collection("default").unwrap().id, "default");
            drop(store);
            let replacement = if link { &outside } else { &selected };
            assert_eq!(
                fs::read(replacement.join(CONFIG_FILE)).unwrap(),
                outside_config
            );
            assert_eq!(
                fs::read(replacement.join(RECIPIENT_REL)).unwrap(),
                outside_cert
            );
            assert_eq!(
                fs::read(replacement.join(INDEX_FILE)).unwrap(),
                outside_index
            );
            assert!(!replacement.join(".noirpass-lifecycle.lock").exists());
        }
    }
}

#[test]
fn refresh_rolls_back_on_pinned_keys_after_directory_replacement() {
    let (bytes, _) = generated_recipient();
    let cert = parse_recipient_cert(&bytes).unwrap();
    let (other, _) = generated_recipient();
    let mut previous = Vec::new();
    cert.armored().serialize(&mut previous).unwrap();
    for after_write in [false, true] {
        for link in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            let selected = tmp.path().join("selected");
            let outside = tmp.path().join("outside");
            let moved_keys = tmp.path().join("moved-keys");
            init_from_bytes(&selected, &bytes).unwrap();
            drop(Store::open(&selected).unwrap());
            fs::write(selected.join(RECIPIENT_REL), &previous).unwrap();
            let old_config = fs::read(selected.join(CONFIG_FILE)).unwrap();
            init_from_bytes(&outside, &other).unwrap();
            let outside_cert = fs::read(outside.join(RECIPIENT_REL)).unwrap();
            let root = Directory::open(&selected).unwrap();
            let replace = || {
                fs::rename(selected.join(KEYS_DIR), &moved_keys).unwrap();
                if link {
                    symlink(outside.join(KEYS_DIR), selected.join(KEYS_DIR)).unwrap();
                } else {
                    fs::rename(outside.join(KEYS_DIR), selected.join(KEYS_DIR)).unwrap();
                }
            };
            let err = init_from_cert_in_with_hooks(
                &selected,
                &root,
                &cert,
                |keys, bytes| {
                    if !after_write {
                        replace();
                    }
                    atomic_write_in(keys, Path::new("recipient.pgp"), bytes, 0o600)
                },
                || {
                    if after_write {
                        replace();
                    }
                },
            )
            .unwrap_err();
            assert!(err.to_string().contains("recipient directory changed"));
            assert_eq!(
                fs::read(moved_keys.join("recipient.pgp")).unwrap(),
                previous
            );
            assert_eq!(fs::read(selected.join(CONFIG_FILE)).unwrap(), old_config);
            let replacement = if link {
                outside.join(KEYS_DIR)
            } else {
                selected.join(KEYS_DIR)
            };
            assert_eq!(
                fs::read(replacement.join("recipient.pgp")).unwrap(),
                outside_cert
            );
            assert_eq!(fs::read_dir(&moved_keys).unwrap().count(), 1);
        }
    }
}

#[test]
fn config_failure_after_certificate_publication_restores_previous_bytes() {
    let tmp = tempfile::tempdir().unwrap();
    let (bytes, _) = generated_recipient();
    let cert = parse_recipient_cert(&bytes).unwrap();
    init_from_bytes(tmp.path(), &bytes).unwrap();
    drop(Store::open(tmp.path()).unwrap());
    let mut previous = Vec::new();
    cert.armored().serialize(&mut previous).unwrap();
    fs::write(tmp.path().join(RECIPIENT_REL), &previous).unwrap();
    let root = Directory::open(tmp.path()).unwrap();
    let err = init_from_cert_in_with_hooks(
        tmp.path(),
        &root,
        &cert,
        |keys, bytes| atomic_write_in(keys, Path::new("recipient.pgp"), bytes, 0o600),
        || {
            assert_ne!(
                root.read_regular(Path::new(RECIPIENT_REL)).unwrap(),
                previous
            );
            fs::remove_file(tmp.path().join(CONFIG_FILE)).unwrap();
            fs::create_dir(tmp.path().join(CONFIG_FILE)).unwrap();
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("not a regular file"));
    assert_eq!(fs::read(tmp.path().join(RECIPIENT_REL)).unwrap(), previous);
    assert!(tmp.path().join(CONFIG_FILE).is_dir());
}

#[test]
fn certificate_sync_failure_rolls_back_fresh_and_existing_initialization() {
    let (bytes, _) = generated_recipient();
    let cert = parse_recipient_cert(&bytes).unwrap();
    for existing in [false, true] {
        let tmp = tempfile::tempdir().unwrap();
        let previous = if existing {
            init_from_bytes(tmp.path(), &bytes).unwrap();
            drop(Store::open(tmp.path()).unwrap());
            let mut armored = Vec::new();
            cert.armored().serialize(&mut armored).unwrap();
            fs::write(tmp.path().join(RECIPIENT_REL), &armored).unwrap();
            Some(armored)
        } else {
            None
        };
        let previous_config = fs::read(tmp.path().join(CONFIG_FILE)).ok();
        let root = Directory::open(tmp.path()).unwrap();
        let err = init_from_cert_in_with_hooks(
            tmp.path(),
            &root,
            &cert,
            |keys, bytes| {
                atomic_write_in_with_sync(keys, Path::new("recipient.pgp"), bytes, 0o600, || {
                    assert_eq!(
                        keys.read_regular(Path::new("recipient.pgp")).unwrap(),
                        bytes
                    );
                    Err(std::io::Error::from_raw_os_error(libc::EIO))
                })
            },
            || panic!("certificate sync failure must stop config publication"),
        )
        .unwrap_err();
        assert!(
            matches!(err, crate::error::Error::Io(ref err) if err.raw_os_error() == Some(libc::EIO))
        );
        assert_eq!(fs::read(tmp.path().join(RECIPIENT_REL)).ok(), previous);
        assert_eq!(fs::read(tmp.path().join(CONFIG_FILE)).ok(), previous_config);
        assert_eq!(
            fs::read_dir(tmp.path().join(KEYS_DIR)).unwrap().count(),
            usize::from(existing)
        );
        // A failed fresh initialization must remain retryable.
        init_store_with_hook(tmp.path(), &cert, || {}).unwrap();
    }
}
