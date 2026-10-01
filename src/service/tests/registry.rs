use super::super::SecretError;
use super::super::state::{
    MAX_TRANSPORT_SESSIONS, MAX_TRANSPORT_SESSIONS_PER_OWNER, SESSION_ALLOCATION_ATTEMPTS,
};
use super::super::{DhHandshake, SessionCipher, session_path};
use super::test_state;
use crate::gpg::test_support::TestGnupg;
use std::sync::Arc;

#[test]
fn transport_session_limits_release_capacity_on_close_and_disconnect() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    let owner = ":1.7";
    let mut paths = Vec::new();
    for _ in 0..MAX_TRANSPORT_SESSIONS_PER_OWNER {
        paths.push(
            state
                .register_session(SessionCipher::Plain, owner.into())
                .unwrap(),
        );
    }
    let err = state
        .register_session_with(SessionCipher::Plain, owner.into(), || {
            panic!("rejected session must not allocate a path")
        })
        .unwrap_err();
    assert!(matches!(err, zbus::fdo::Error::LimitsExceeded(_)));
    assert_eq!(state.session_count(), MAX_TRANSPORT_SESSIONS_PER_OWNER);
    assert!(!state.remove_session(&paths[0], ":1.8"));
    assert!(state.remove_session(&paths[0], owner));
    state
        .register_session(SessionCipher::Plain, owner.into())
        .unwrap();
    for i in MAX_TRANSPORT_SESSIONS_PER_OWNER..MAX_TRANSPORT_SESSIONS {
        state
            .register_session(SessionCipher::Plain, format!(":2.{i}"))
            .unwrap();
    }
    let err = state
        .register_session(SessionCipher::Plain, ":1.8".into())
        .unwrap_err();
    assert!(matches!(err, zbus::fdo::Error::LimitsExceeded(_)));
    assert_eq!(state.session_count(), MAX_TRANSPORT_SESSIONS);
    assert_eq!(
        state.remove_sessions_owned_by(owner).len(),
        MAX_TRANSPORT_SESSIONS_PER_OWNER
    );
    state
        .register_session(SessionCipher::Plain, ":1.8".into())
        .unwrap();
    assert_eq!(
        state.session_count(),
        MAX_TRANSPORT_SESSIONS - MAX_TRANSPORT_SESSIONS_PER_OWNER + 1
    );
}

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

#[tokio::test]
async fn persistent_decryption_rejects_foreign_and_closed_sessions_before_gpg() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    let session = state
        .register_session(SessionCipher::Plain, ":1.7".into())
        .unwrap();
    // Missing metadata would return NoSuchObject if storage were accessed first.
    let foreign = state
        .persistent_secret("default", "missing", &session, ":1.8", None)
        .await;
    assert!(matches!(foreign, Err(SecretError::NoSession(_))));
    assert!(state.remove_session(&session, ":1.7"));
    let closed = state
        .persistent_secret("default", "missing", &session, ":1.7", None)
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
