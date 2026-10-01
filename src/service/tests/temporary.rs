use super::super::state::{
    MAX_SESSION_ALIAS_BYTES, MAX_SESSION_ALIASES, MAX_SESSION_ATTRIBUTES, MAX_SESSION_BYTES,
    MAX_SESSION_ITEMS, MAX_SESSION_METADATA_BYTES, MAX_SESSION_SECRET_BYTES,
    MAX_SESSION_STRING_BYTES, session_item_bytes,
};
use super::test_state;
use crate::gpg::test_support::TestGnupg;
use std::collections::HashMap;
use zeroize::Zeroizing;

#[test]
fn temporary_session_items_stay_out_of_persistent_store() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    let attributes = HashMap::from([("type".to_string(), "luks".to_string())]);

    let (created, replaced) = state
        .create_or_replace_session_item(
            "temporary",
            attributes.clone(),
            "text/plain",
            Zeroizing::new(b"secret one".to_vec()),
            false,
        )
        .unwrap();
    assert!(!replaced);
    assert_eq!(state.session_secret_count(), 1);
    assert!(state.store().get_item(&created.id).is_err());

    let (metadata, secret) = state.read_session_item_secret(&created.id).unwrap();
    assert_eq!(metadata.attributes, attributes);
    assert_eq!(secret.as_slice(), b"secret one");

    let (replacement, replaced) = state
        .create_or_replace_session_item(
            "replacement",
            attributes,
            "application/octet-stream",
            Zeroizing::new(b"secret two".to_vec()),
            true,
        )
        .unwrap();
    assert!(replaced);
    assert_eq!(replacement.id, created.id);
    assert_eq!(state.session_secret_count(), 1);
    let (metadata, secret) = state.read_session_item_secret(&created.id).unwrap();
    assert_eq!(metadata.label, "replacement");
    assert_eq!(metadata.content_type, "application/octet-stream");
    assert_eq!(secret.as_slice(), b"secret two");

    state.delete_session_item(&created.id).unwrap();
    assert_eq!(state.session_secret_count(), 0);
    assert!(state.read_session_item_secret(&created.id).is_err());
}

#[test]
fn temporary_session_item_blocks_idle_shutdown_until_deleted() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    drop(state.activity().unwrap());

    let (item, _) = state
        .create_or_replace_session_item(
            "temporary",
            HashMap::new(),
            "text/plain",
            Zeroizing::new(b"secret".to_vec()),
            false,
        )
        .unwrap();
    assert!(!state.try_begin_idle_shutdown(0));

    state.delete_session_item(&item.id).unwrap();
    assert!(state.try_begin_idle_shutdown(0));
}

#[test]
fn temporary_item_size_limits_cover_secret_and_metadata() {
    let empty = HashMap::new();
    assert!(session_item_bytes("", &empty, "", MAX_SESSION_SECRET_BYTES).is_ok());
    assert!(session_item_bytes("", &empty, "", MAX_SESSION_SECRET_BYTES + 1).is_err());
    let long = "x".repeat(MAX_SESSION_STRING_BYTES + 1);
    assert!(session_item_bytes(&long, &empty, "", 0).is_err());
    assert!(session_item_bytes("", &empty, &long, 0).is_err());
    for attributes in [
        HashMap::from([(long.clone(), String::new())]),
        HashMap::from([(String::new(), long)]),
        (0..=MAX_SESSION_ATTRIBUTES)
            .map(|i| (i.to_string(), String::new()))
            .collect(),
        (0..=MAX_SESSION_METADATA_BYTES / MAX_SESSION_STRING_BYTES)
            .map(|i| (i.to_string(), "x".repeat(MAX_SESSION_STRING_BYTES)))
            .collect(),
    ] {
        assert!(session_item_bytes("", &attributes, "", 0).is_err());
    }
}

#[test]
fn temporary_collection_limits_preserve_items_on_failure_and_release_capacity() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    let mut ids = Vec::new();
    for _ in 0..MAX_SESSION_BYTES / MAX_SESSION_SECRET_BYTES {
        let (item, _) = state
            .create_or_replace_session_item(
                "",
                HashMap::new(),
                "",
                Zeroizing::new(vec![7; MAX_SESSION_SECRET_BYTES]),
                false,
            )
            .unwrap();
        ids.push(item.id);
    }
    assert!(
        state
            .create_or_replace_session_item("", HashMap::new(), "", Zeroizing::new(vec![1]), false,)
            .is_err()
    );
    assert!(
        state
            .update_session_item(&ids[0], Some("larger"), None, None, None)
            .is_err()
    );
    assert_eq!(state.get_session_item(&ids[0]).unwrap().label, "");
    assert!(
        state
            .create_or_replace_session_item(
                "larger",
                HashMap::new(),
                "",
                Zeroizing::new(vec![9; MAX_SESSION_SECRET_BYTES]),
                true,
            )
            .is_err()
    );
    assert!(
        state
            .list_session_items()
            .iter()
            .all(|item| item.label.is_empty())
    );
    let (_, replaced) = state
        .create_or_replace_session_item(
            "",
            HashMap::new(),
            "",
            Zeroizing::new(vec![9; MAX_SESSION_SECRET_BYTES]),
            true,
        )
        .unwrap();
    assert!(replaced, "same-sized replacement must work at capacity");
    state.delete_session_item(&ids[0]).unwrap();
    state
        .update_session_item(&ids[1], Some("larger"), None, None, None)
        .unwrap();
    assert!(
        state
            .update_session_item(
                &ids[1],
                None,
                None,
                None,
                Some(Zeroizing::new(vec![0; MAX_SESSION_SECRET_BYTES + 1])),
            )
            .is_err()
    );
    assert_eq!(
        state.read_session_item_secret(&ids[1]).unwrap().1.len(),
        MAX_SESSION_SECRET_BYTES
    );
    assert!(
        state
            .set_session_collection_label(&"x".repeat(MAX_SESSION_STRING_BYTES + 1))
            .is_err()
    );
    assert_eq!(state.session_collection_meta().label, "Session");
}

#[test]
fn temporary_item_count_limit_allows_replace_and_delete() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    let mut last = String::new();
    for _ in 0..MAX_SESSION_ITEMS {
        last = state
            .create_or_replace_session_item(
                "",
                HashMap::new(),
                "",
                Zeroizing::new(Vec::new()),
                false,
            )
            .unwrap()
            .0
            .id;
    }
    assert!(
        state
            .create_or_replace_session_item(
                "",
                HashMap::new(),
                "",
                Zeroizing::new(Vec::new()),
                false,
            )
            .is_err()
    );
    assert!(
        state
            .create_or_replace_session_item(
                "",
                HashMap::new(),
                "",
                Zeroizing::new(Vec::new()),
                true,
            )
            .unwrap()
            .1
    );
    state.delete_session_item(&last).unwrap();
    assert!(
        state
            .create_or_replace_session_item(
                "",
                HashMap::new(),
                "",
                Zeroizing::new(Vec::new()),
                false,
            )
            .is_ok()
    );
    assert_eq!(state.session_secret_count(), MAX_SESSION_ITEMS);
}

#[test]
fn temporary_alias_limits_preserve_persisted_targets_and_release_capacity() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    let persisted = state
        .store()
        .create_collection("persisted", Some("overflow"))
        .unwrap();
    assert!(
        state
            .set_session_alias(&"x".repeat(MAX_SESSION_ALIAS_BYTES + 1))
            .is_err()
    );
    for i in 0..MAX_SESSION_ALIASES {
        state.set_session_alias(&format!("alias_{i}")).unwrap();
    }
    assert!(state.set_session_alias("overflow").is_err());
    assert_eq!(
        state.store().read_alias("overflow").unwrap(),
        Some(persisted.id)
    );
    state.set_session_alias("alias_0").unwrap();
    state.remove_session_alias("alias_0");
    state.set_session_alias("overflow").unwrap();
    assert!(state.store().read_alias("overflow").unwrap().is_none());
    assert_eq!(
        state.read_alias("overflow").unwrap().as_deref(),
        Some("session")
    );
    assert_eq!(
        state.session_collection_aliases().len(),
        MAX_SESSION_ALIASES + 1
    );
}
