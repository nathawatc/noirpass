use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use crate::gpg::test_support::TestGnupg;
use zeroize::Zeroizing;

use super::super::SecretError;
use super::super::state::SESSION_ALLOCATION_ATTEMPTS;
use super::super::{DhHandshake, SessionCipher, session_path};
use super::test_state;

#[tokio::test]
async fn session_registry_adds_looks_up_and_removes() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());

    assert_eq!(state.session_count(), 0);

    let p1 = state
        .register_session(SessionCipher::Plain, ":1.7".into())
        .unwrap();
    assert_eq!(state.session_count(), 1);
    assert!(state.session_cipher(&p1, ":1.7").is_some());
    assert!(state.session_cipher(&p1, ":1.8").is_none());

    assert!(!state.remove_session(&p1, ":1.8"));
    assert!(state.remove_session(&p1, ":1.7"));
    assert!(!state.remove_session(&p1, ":1.7"));
    assert_eq!(state.session_count(), 0);
}

#[test]
fn active_handler_blocks_positive_idle_exit_and_starts_fresh_period() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    let activity = state.activity().unwrap();

    std::thread::sleep(Duration::from_millis(1_100));
    assert!(!state.try_begin_idle_shutdown(1));

    drop(activity);
    assert!(!state.try_begin_idle_shutdown(1));
    std::thread::sleep(Duration::from_millis(1_100));
    assert!(state.try_begin_idle_shutdown(1));
}

#[test]
fn completed_handler_invalidates_stale_elapsed_time() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());

    std::thread::sleep(Duration::from_millis(1_100));
    let activity = state.activity().unwrap();
    drop(activity);

    assert!(!state.try_begin_idle_shutdown(1));
}

#[test]
fn shutdown_rejects_new_handler_admission() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    drop(state.activity().unwrap());

    assert!(state.try_begin_idle_shutdown(0));
    assert!(state.activity().is_err());
}

#[tokio::test]
async fn explicit_shutdown_closes_admission_and_drains_active_handlers() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    let activity = state.activity().unwrap();

    state.begin_shutdown();
    assert!(state.activity().is_err());

    let mut drain = Box::pin(state.wait_for_active_calls());
    let pending = std::future::poll_fn(|cx| {
        if drain.as_mut().poll(cx).is_pending() {
            std::task::Poll::Ready(true)
        } else {
            std::task::Poll::Ready(false)
        }
    })
    .await;
    assert!(pending, "active-call drain completed before guard drop");

    drop(activity);
    tokio::time::timeout(Duration::from_secs(1), &mut drain)
        .await
        .expect("active-call drain did not complete after guard drop");
}

#[tokio::test]
async fn shutdown_drain_completes_with_no_active_handlers() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());

    state.begin_shutdown();
    tokio::time::timeout(Duration::from_secs(1), state.wait_for_active_calls())
        .await
        .expect("zero-active shutdown drain did not complete");
}

#[test]
fn zero_idle_exit_waits_for_first_completed_handler() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());

    assert!(!state.try_begin_idle_shutdown(-1));
    assert!(!state.try_begin_idle_shutdown(0));
    let activity = state.activity().unwrap();
    assert!(!state.try_begin_idle_shutdown(0));
    drop(activity);
    assert!(state.try_begin_idle_shutdown(0));
}

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

#[tokio::test]
async fn persistent_decryption_rejects_foreign_and_closed_sessions_before_gpg() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    let session = state
        .register_session(SessionCipher::Plain, ":1.7".into())
        .unwrap();
    // Invalid OpenPGP bytes would return a GPG error if decryption were attempted.
    let foreign = state
        .ciphertext_to_secret(&session, b"invalid ciphertext", "", ":1.8")
        .await;
    assert!(matches!(foreign, Err(SecretError::NoSession(_))));
    assert!(state.remove_session(&session, ":1.7"));
    let closed = state
        .ciphertext_to_secret(&session, b"invalid ciphertext", "", ":1.7")
        .await;
    assert!(matches!(closed, Err(SecretError::NoSession(_))));
}

#[test]
fn open_session_blocks_idle_shutdown() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    drop(state.activity().unwrap());
    let session = state
        .register_session(SessionCipher::Plain, ":1.7".into())
        .unwrap();

    assert!(!state.try_begin_idle_shutdown(0));
    assert!(state.remove_session(&session, ":1.7"));
    assert!(state.try_begin_idle_shutdown(0));
}

#[test]
fn sessions_of_vanished_owner_are_reaped() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    let p1 = state
        .register_session(SessionCipher::Plain, ":1.7".into())
        .unwrap();
    let _p2 = state
        .register_session(SessionCipher::Plain, ":1.8".into())
        .unwrap();
    let _p3 = state
        .register_session(SessionCipher::Plain, ":1.9".into())
        .unwrap();
    assert_eq!(state.session_count(), 3);

    let reaped = state.remove_sessions_owned_by(":1.7");
    assert_eq!(reaped, vec![p1.clone()]);
    assert_eq!(state.session_count(), 2);
    assert!(state.session_cipher(&p1, ":1.7").is_none());

    // Unknown owners and other owners' sessions are untouched.
    assert!(state.remove_sessions_owned_by(":9.9").is_empty());
    assert_eq!(state.session_count(), 2);
}

#[test]
fn session_registration_retries_path_collision_without_overwrite() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    let occupied_id = 41;
    let replacement_id = 42;
    let occupied = state
        .register_session_with(SessionCipher::Plain, ":1.7".into(), || occupied_id)
        .unwrap();
    let mut ids = [occupied_id, replacement_id].into_iter();
    let client_dh = DhHandshake::generate();
    let replacement_cipher = DhHandshake::generate()
        .derive(&client_dh.public_bytes())
        .unwrap();

    let replacement = state
        .register_session_with(replacement_cipher, ":1.8".into(), || ids.next().unwrap())
        .unwrap();

    assert_eq!(occupied, session_path(occupied_id));
    assert_eq!(replacement, session_path(replacement_id));
    assert_eq!(state.session_count(), 2);
    let occupied_cipher = state.session_cipher(&occupied, ":1.7").unwrap();
    let (parameters, value) = occupied_cipher.encrypt(b"collision probe");
    assert!(parameters.is_empty());
    assert_eq!(value.as_slice(), b"collision probe");
    assert!(state.session_cipher(&occupied, ":1.8").is_none());
    let replacement_cipher = state.session_cipher(&replacement, ":1.8").unwrap();
    let (parameters, _) = replacement_cipher.encrypt(b"collision probe");
    assert_eq!(parameters.len(), 16);
}

#[test]
fn concurrent_session_registration_allocates_distinct_paths() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let mut workers = Vec::new();

    for (owner, fallback_id) in [(":1.7", 52), (":1.8", 53)] {
        let state = state.clone();
        let barrier = barrier.clone();
        workers.push(std::thread::spawn(move || {
            let mut ids = [51, fallback_id].into_iter();
            barrier.wait();
            let path = state
                .register_session_with(SessionCipher::Plain, owner.into(), || ids.next().unwrap())
                .unwrap();
            (owner, path)
        }));
    }
    barrier.wait();

    let registrations: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    assert_ne!(registrations[0].1, registrations[1].1);
    assert_eq!(state.session_count(), 2);
    for (owner, path) in registrations {
        assert!(state.session_cipher(&path, owner).is_some());
    }
}

#[test]
fn session_registration_stops_after_bounded_collisions() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    let occupied = state
        .register_session_with(SessionCipher::Plain, ":1.7".into(), || 54)
        .unwrap();
    let attempts = std::sync::atomic::AtomicUsize::new(0);

    let err = state
        .register_session_with(SessionCipher::Plain, ":1.8".into(), || {
            attempts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            54
        })
        .unwrap_err();

    assert!(err.to_string().contains("128 attempts"));
    assert_eq!(
        attempts.load(std::sync::atomic::Ordering::Relaxed),
        SESSION_ALLOCATION_ATTEMPTS
    );
    assert_eq!(state.session_count(), 1);
    assert!(state.session_cipher(&occupied, ":1.7").is_some());
}
