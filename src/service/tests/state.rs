use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use crate::gpg::test_support::TestGnupg;
use zeroize::Zeroizing;

use super::super::SecretError;
use super::super::state::{
    MAX_BLOCKING_WORKERS, MAX_SESSION_ALIAS_BYTES, MAX_SESSION_ALIASES, MAX_SESSION_ATTRIBUTES,
    MAX_SESSION_BYTES, MAX_SESSION_ITEMS, MAX_SESSION_METADATA_BYTES, MAX_SESSION_SECRET_BYTES,
    MAX_SESSION_STRING_BYTES, SESSION_ALLOCATION_ATTEMPTS, session_item_bytes,
};
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

#[tokio::test]
async fn blocking_work_bounds_decryption_and_rechecks_queued_session() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    let mut tasks = Vec::new();
    let mut releases = Vec::new();
    for _ in 0..MAX_BLOCKING_WORKERS {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let worker_state = state.clone();
        tasks.push(tokio::spawn(async move {
            worker_state
                .blocking(None, move |_| {
                    started_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    Ok(())
                })
                .await
                .unwrap();
        }));
        started_rx.await.unwrap();
        releases.push(release_tx);
    }
    let worker_state = state.clone();
    let session = state
        .register_session(SessionCipher::Plain, ":1.7".into())
        .unwrap();
    let worker_session = session.clone();
    let (started_tx, mut started_rx) = tokio::sync::oneshot::channel();
    let (queued_tx, queued_rx) = tokio::sync::oneshot::channel();
    let fifth = tokio::spawn(async move {
        queued_tx.send(()).unwrap();
        let result = worker_state
            .ciphertext_to_secret(&worker_session, b"invalid ciphertext", "", ":1.7")
            .await;
        // Garbage ciphertext would fail as OpenPGP if the closed session reached the agent.
        assert!(matches!(result, Err(SecretError::NoSession(_))));
        started_tx.send(()).unwrap();
    });
    queued_rx.await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut started_rx)
            .await
            .is_err()
    );
    let lifecycle = tokio::time::timeout(Duration::from_secs(2), state.lock_object_lifecycle())
        .await
        .unwrap();
    drop(lifecycle);
    // A real object-server call remains responsive on this single-thread executor.
    let (_server, client) = super::p2p_pair(state.clone()).await;
    let proxy = zbus::Proxy::new(
        &client,
        ":1.0",
        super::super::SERVICE_PATH,
        "org.freedesktop.Secret.Service",
    )
    .await
    .unwrap();
    let _: Vec<zbus::zvariant::OwnedObjectPath> =
        tokio::time::timeout(Duration::from_secs(2), proxy.get_property("Collections"))
            .await
            .unwrap()
            .unwrap();
    assert!(state.remove_session(&session, ":1.7"));
    for release in releases {
        release.send(()).unwrap();
    }
    started_rx.await.unwrap();
    for task in tasks {
        task.await.unwrap();
    }
    fifth.await.unwrap();
}

#[tokio::test]
async fn cancelled_blocking_waiter_retains_mutation_lock_and_activity() {
    let gnupg = TestGnupg::new();
    for namespace in [false, true] {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(&gnupg, tmp.path());
        let lifecycle = if namespace {
            state.lock_owned_namespace_lifecycle().await
        } else {
            state.lock_owned_collection_lifecycle("default").await
        };
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let worker_state = state.clone();
        let waiter = tokio::spawn(async move {
            worker_state
                .blocking(Some(lifecycle), move |_| {
                    started_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    Ok(())
                })
                .await
        });
        started_rx.await.unwrap();
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        assert!(
            tokio::time::timeout(Duration::from_millis(50), state.lock_object_lifecycle())
                .await
                .is_err()
        );
        state.begin_shutdown();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), state.wait_for_active_calls())
                .await
                .is_err()
        );
        release_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), state.wait_for_active_calls())
            .await
            .unwrap();
        drop(state.lock_object_lifecycle().await);
    }
}
