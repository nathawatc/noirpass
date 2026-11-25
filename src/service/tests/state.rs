use super::super::SecretError;
use super::super::SessionCipher;
use super::super::state::{MAX_BLOCKING_WORKERS, MAX_PENDING_REQUEST_BYTES, MAX_PENDING_REQUESTS};
use super::test_state;
use crate::gpg::test_support::TestGnupg;
use std::collections::HashMap;
use std::future::Future;
use std::time::Duration;

#[test]
fn request_count_and_payload_limits_release_capacity() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    let mut requests: Vec<_> = (0..MAX_PENDING_REQUESTS)
        .map(|_| state.request(&0u8).unwrap())
        .collect();
    assert!(matches!(
        state.request(&0u8),
        Err(zbus::fdo::Error::LimitsExceeded(_))
    ));
    // Internal activity must remain available for workers and publication.
    drop(state.activity().unwrap());
    drop(requests.pop());
    drop(state.request(&0u8).unwrap());
    drop(requests);

    // D-Bus strings encode a four-byte length and one trailing NUL.
    let payload = "x".repeat(MAX_PENDING_REQUEST_BYTES as usize - 5);
    let request = state.request(payload.as_str()).unwrap();
    assert!(matches!(
        state.request(""),
        Err(zbus::fdo::Error::LimitsExceeded(_))
    ));
    drop(request);
    let oversized = "x".repeat(MAX_PENDING_REQUEST_BYTES as usize);
    for _ in 0..=MAX_PENDING_REQUESTS {
        assert!(matches!(
            state.request(oversized.as_str()),
            Err(zbus::fdo::Error::LimitsExceeded(_))
        ));
    }
    // Failed byte admission releases its request slot and activity guard.
    drop(state.request("").unwrap());
    assert!(state.try_begin_idle_shutdown(0));
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

#[tokio::test]
async fn notify_activity_completion_wakes_wait_for_activity_completion() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());

    let waiting = state.wait_for_activity_completion();
    tokio::pin!(waiting);
    std::future::poll_fn(|context| {
        assert!(waiting.as_mut().poll(context).is_pending());
        std::task::Poll::Ready(())
    })
    .await;

    state.notify_activity_completion();
    tokio::time::timeout(Duration::from_secs(1), waiting)
        .await
        .expect("notify_activity_completion must wake activity completion waiter");
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
            .persistent_secret("default", "missing", &worker_session, ":1.7", None)
            .await;
        // Missing metadata would fail as NoSuchObject if the closed session reached storage.
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
    let _: Vec<zbus::OwnedObjectPath> =
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
        let payload = "x".repeat(MAX_PENDING_REQUEST_BYTES as usize - 5);
        let request = state.request(payload.as_str()).unwrap();
        let worker_state = state.clone();
        let waiter = tokio::spawn(request.run(async move {
            worker_state
                .blocking(Some(lifecycle), move |_| {
                    started_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    Ok(())
                })
                .await
        }));
        started_rx.await.unwrap();
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        assert!(
            tokio::time::timeout(Duration::from_millis(50), state.lock_object_lifecycle())
                .await
                .is_err()
        );
        assert!(matches!(
            state.request(&0u8),
            Err(zbus::fdo::Error::LimitsExceeded(_))
        ));
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

#[tokio::test]
async fn cancelled_search_retains_request_capacity_until_worker_completion() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    let mut workers = Vec::new();
    for i in 0..MAX_BLOCKING_WORKERS {
        workers.push(
            state
                .lock_owned_collection_lifecycle(&format!("busy{i}"))
                .await,
        );
    }
    let requests: Vec<_> = (0..MAX_PENDING_REQUESTS - 1)
        .map(|_| state.request(&0u8).unwrap())
        .collect();
    let object = super::super::Service::new(state.clone());
    super::support::admit_then_cancel(
        object.search_items(HashMap::from([("attribute".into(), "value".into())])),
    )
    .await;
    assert!(matches!(
        state.request(&0u8),
        Err(zbus::fdo::Error::LimitsExceeded(_))
    ));
    drop(workers);
    drop(requests);
    tokio::time::timeout(Duration::from_secs(2), state.wait_for_active_calls())
        .await
        .unwrap();
    drop(state.request(&0u8).unwrap());
}

#[tokio::test]
async fn property_worker_admission_drains_after_shutdown_and_rejects_foreign_state() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    let other_tmp = tempfile::tempdir().unwrap();
    let state = test_state(&gnupg, tmp.path());
    let other = test_state(&gnupg, other_tmp.path());
    let activity = std::sync::Arc::new(state.activity().unwrap());
    state.begin_shutdown();
    // Existing property admission remains valid; a new handler still fails.
    assert!(state.activity().is_err());
    assert_eq!(
        state
            .blocking_admitted(activity.clone(), None, |_| Ok(42))
            .await
            .unwrap(),
        42
    );
    assert!(
        other
            .blocking_admitted(activity.clone(), None, |_| Ok(()))
            .await
            .is_err()
    );
    let drained = state.wait_for_active_calls();
    tokio::pin!(drained);
    std::future::poll_fn(|context| {
        assert!(drained.as_mut().poll(context).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    drop(activity);
    tokio::time::timeout(Duration::from_secs(2), drained)
        .await
        .unwrap();
}
