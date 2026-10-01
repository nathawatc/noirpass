use super::super::deinit::{deinit_with_hooks, remove_empty_directory};
use super::super::{CONFIG_FILE, INDEX_FILE, KEYS_DIR, RECIPIENT_REL, SECRETS_DIR};
use super::support::generated_recipient;
use crate::config::init_from_bytes;
use crate::store::Store;
use std::fs;
use std::os::unix::fs::symlink;

#[test]
fn deinit_refuses_busy_index_when_secrets_directory_is_missing() {
    let tmp = tempfile::tempdir().unwrap();
    let (certificate, _) = generated_recipient();
    init_from_bytes(tmp.path(), &certificate).unwrap();
    let store = Store::open(tmp.path()).unwrap();
    fs::rename(
        tmp.path().join(SECRETS_DIR),
        tmp.path().join("saved-secrets"),
    )
    .unwrap();
    let config = fs::read(tmp.path().join(CONFIG_FILE)).unwrap();
    let index = fs::read(tmp.path().join(INDEX_FILE)).unwrap();

    let err = crate::config::deinit(tmp.path()).unwrap_err();
    assert!(err.to_string().contains("store is in use"));
    assert_eq!(fs::read(tmp.path().join(CONFIG_FILE)).unwrap(), config);
    assert_eq!(fs::read(tmp.path().join(INDEX_FILE)).unwrap(), index);
    assert!(!tmp.path().join(".noirpass-lifecycle.lock").exists());
    drop(store);
    crate::config::deinit(tmp.path()).unwrap();
    assert!(!tmp.path().join(INDEX_FILE).exists());
    assert!(tmp.path().join("saved-secrets").is_dir());
}

#[test]
fn incomplete_index_ownership_does_not_initialize_or_rewrite_data() {
    let (certificate, _) = generated_recipient();
    for bytes in [b"".as_slice(), b"corrupt index".as_slice()] {
        let tmp = tempfile::tempdir().unwrap();
        init_from_bytes(tmp.path(), &certificate).unwrap();
        fs::write(tmp.path().join(INDEX_FILE), bytes).unwrap();
        deinit_with_hooks(
            tmp.path(),
            || {},
            || {
                assert_eq!(fs::read(tmp.path().join(INDEX_FILE)).unwrap(), bytes);
            },
        )
        .unwrap();
        assert!(!tmp.path().join(INDEX_FILE).exists());
        assert!(!tmp.path().join(CONFIG_FILE).exists());
    }
}

#[test]
fn emptied_child_replacement_is_preserved() {
    let tmp = tempfile::tempdir().unwrap();
    let root = crate::filesystem::Directory::open(tmp.path()).unwrap();
    fs::create_dir(tmp.path().join(KEYS_DIR)).unwrap();
    let keys = root.child(std::path::Path::new(KEYS_DIR)).unwrap();
    fs::rename(tmp.path().join(KEYS_DIR), tmp.path().join("moved")).unwrap();
    fs::create_dir(tmp.path().join(KEYS_DIR)).unwrap();

    remove_empty_directory(&root, &keys, std::path::Path::new(KEYS_DIR)).unwrap();

    assert!(tmp.path().join(KEYS_DIR).is_dir());
    assert!(tmp.path().join("moved").is_dir());
}

#[test]
fn deinit_stays_on_pinned_root_and_children_after_replacement() {
    let (certificate, _) = generated_recipient();
    for replace_root in [true, false] {
        for replacement_is_symlink in [true, false] {
            let tmp = tempfile::tempdir().unwrap();
            let selected = tmp.path().join("selected");
            let moved = tmp.path().join("moved");
            let outside = tmp.path().join("outside");
            init_from_bytes(&selected, &certificate).unwrap();
            drop(Store::open(&selected).unwrap());
            init_from_bytes(&outside, &certificate).unwrap();
            drop(Store::open(&outside).unwrap());
            let secret = "0123456789abcdef0123456789abcdef.gpg";
            let temporary = ".noirpass-tmp-0123456789abcdef";
            fs::write(selected.join(SECRETS_DIR).join(secret), b"owned").unwrap();
            fs::write(outside.join(SECRETS_DIR).join(secret), b"untouched").unwrap();
            fs::write(selected.join(KEYS_DIR).join(temporary), b"owned").unwrap();
            fs::write(outside.join(KEYS_DIR).join(temporary), b"untouched").unwrap();
            let outside_config = fs::read(outside.join(CONFIG_FILE)).unwrap();
            let outside_index = fs::read(outside.join(INDEX_FILE)).unwrap();
            let outside_certificate = fs::read(outside.join(RECIPIENT_REL)).unwrap();
            let replace = || {
                if replace_root {
                    fs::rename(&selected, &moved).unwrap();
                    if replacement_is_symlink {
                        symlink(&outside, &selected).unwrap();
                    } else {
                        fs::rename(&outside, &selected).unwrap();
                    }
                } else {
                    fs::create_dir(&moved).unwrap();
                    for name in [SECRETS_DIR, KEYS_DIR] {
                        fs::rename(selected.join(name), moved.join(name)).unwrap();
                        if replacement_is_symlink {
                            symlink(outside.join(name), selected.join(name)).unwrap();
                        } else {
                            fs::rename(outside.join(name), selected.join(name)).unwrap();
                        }
                    }
                }
            };
            deinit_with_hooks(
                &selected,
                || {
                    if replace_root {
                        replace();
                    }
                },
                || {
                    if !replace_root {
                        replace();
                    }
                },
            )
            .unwrap();

            assert!(!moved.join(SECRETS_DIR).join(secret).exists());
            assert!(!moved.join(KEYS_DIR).join(temporary).exists());
            assert!(!moved.join(RECIPIENT_REL).exists());
            let replacement_children = if replacement_is_symlink {
                &outside
            } else {
                &selected
            };
            assert_eq!(
                fs::read(replacement_children.join(SECRETS_DIR).join(secret)).unwrap(),
                b"untouched"
            );
            assert_eq!(
                fs::read(replacement_children.join(KEYS_DIR).join(temporary)).unwrap(),
                b"untouched"
            );
            assert_eq!(
                fs::read(replacement_children.join(RECIPIENT_REL)).unwrap(),
                outside_certificate
            );
            let replacement_root = if replace_root && !replacement_is_symlink {
                &selected
            } else {
                &outside
            };
            assert_eq!(
                fs::read(replacement_root.join(CONFIG_FILE)).unwrap(),
                outside_config
            );
            assert_eq!(
                fs::read(replacement_root.join(INDEX_FILE)).unwrap(),
                outside_index
            );
            let owned_root = if replace_root { &moved } else { &selected };
            assert!(!owned_root.join(CONFIG_FILE).exists());
            assert!(!owned_root.join(INDEX_FILE).exists());
        }
    }
}
