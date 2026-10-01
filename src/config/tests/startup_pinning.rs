use std::fs;
use std::os::unix::fs::symlink;

use super::super::startup::open_startup_after_preflight;
use super::super::{CONFIG_FILE, Config, INDEX_FILE, RECIPIENT_REL, init_from_bytes};
use super::support::generated_recipient;
use crate::store::Store;

#[test]
fn startup_revalidates_after_preflight_without_recreating_missing_index() {
    let directory = tempfile::tempdir().unwrap();
    let (bytes, _) = generated_recipient();
    init_from_bytes(directory.path(), &bytes).unwrap();
    drop(Store::open(directory.path()).unwrap());
    let (store, _, config) = open_startup_after_preflight(directory.path(), || {
        let mut config = Config::load(directory.path()).unwrap();
        config.idle_exit = 123;
        config.write(directory.path()).unwrap();
    })
    .unwrap();
    assert_eq!(config.idle_exit, 123);
    drop(store);

    let err = open_startup_after_preflight(directory.path(), || {
        fs::write(directory.path().join(RECIPIENT_REL), b"invalid certificate").unwrap();
    })
    .unwrap_err();
    assert!(matches!(err, crate::Error::OpenPgp(_)));
    fs::write(directory.path().join(RECIPIENT_REL), &bytes).unwrap();
    assert!(
        open_startup_after_preflight(directory.path(), || {
            fs::remove_file(directory.path().join(INDEX_FILE)).unwrap();
        })
        .is_err()
    );
    assert!(!directory.path().join(INDEX_FILE).exists());
}

#[test]
fn startup_keeps_recipient_config_and_database_on_same_root_after_replacement() {
    let (bytes, fingerprint) = generated_recipient();
    let (other, _) = generated_recipient();
    for link in [false, true] {
        let tmp = tempfile::tempdir().unwrap();
        let selected = tmp.path().join("selected");
        let moved = tmp.path().join("moved");
        let outside = tmp.path().join("outside");
        init_from_bytes(&selected, &bytes).unwrap();
        let store = Store::open(&selected).unwrap();
        store.ensure_default().unwrap();
        store.create_collection("selected-marker", None).unwrap();
        drop(store);
        let mut config = Config::load(&selected).unwrap();
        config.idle_exit = 123;
        config.write(&selected).unwrap();
        init_from_bytes(&outside, &other).unwrap();
        drop(Store::open(&outside).unwrap());
        let outside_config = fs::read(outside.join(CONFIG_FILE)).unwrap();
        let outside_index = fs::read(outside.join(INDEX_FILE)).unwrap();
        let (store, recipient, loaded) = open_startup_after_preflight(&selected, || {
            fs::rename(&selected, &moved).unwrap();
            if link {
                symlink(&outside, &selected).unwrap();
            } else {
                fs::rename(&outside, &selected).unwrap();
            }
        })
        .unwrap();
        assert_eq!(loaded, config);
        assert_eq!(recipient.fingerprint, fingerprint);
        assert!(
            store
                .list_collections()
                .unwrap()
                .iter()
                .any(|collection| collection.label == "selected-marker")
        );
        drop(store);
        let replacement = if link { &outside } else { &selected };
        assert_eq!(
            fs::read(replacement.join(CONFIG_FILE)).unwrap(),
            outside_config
        );
        assert_eq!(
            fs::read(replacement.join(INDEX_FILE)).unwrap(),
            outside_index
        );
    }
}
