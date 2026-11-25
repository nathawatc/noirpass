//! Daemon startup, vanished-client session reaping, and shutdown lifecycle.

use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, info};
use zbus::export::futures_core::Stream;

use noirpass::config::open_startup_store;
use noirpass::gpg::Gpg;
use noirpass::service::session::Session;
use noirpass::service::{SERVICE_NAME, SERVICE_PATH, Service, ServiceState, register_existing};

pub(super) async fn run(
    store_dir: &Path,
    idle_exit_override: Option<i64>,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    info!(store = %store_dir.display(), "opening store");

    let (store, recipient, config) = open_startup_store(store_dir)?;
    let idle_exit = idle_exit_override.unwrap_or(config.idle_exit);
    store.recover_interrupted_operations()?;
    store.ensure_safe_to_serve()?;
    store.ensure_default()?;
    let gpg = Gpg::from_cert(recipient.cert);
    gpg.ensure_recipient_secret_available().await?;
    info!(key = %gpg.fingerprint(), "using OpenPGP key");
    let state = ServiceState::new(store, gpg);

    // Serve the service object first, then the pre-existing collections and
    // items, and only then claim the well-known name: clients activating us
    // never observe a half-populated object tree.
    let connection = zbus::connection::Builder::session()
        .serve_at(SERVICE_PATH, Service::new(state.clone()))
        .build()
        .await?;
    register_existing(connection.object_server(), &state).await?;
    let reaper = reap_vanished_clients(connection.clone(), state.clone()).await?;
    connection.request_name(SERVICE_NAME).await?;
    info!(name = SERVICE_NAME, "secret service ready");

    wait_for_shutdown(&connection, &state, idle_exit).await;

    reaper.abort();
    let _ = reaper.await;

    // Graceful shutdown: release the name so a future activation starts a
    // fresh instance, then drop the connection.
    let _ = connection.release_name(SERVICE_NAME).await;
    drop(connection);
    info!("exiting");
    Ok(ExitCode::SUCCESS)
}

/// Reap sessions whose owning client left the bus without calling
/// `Session.Close` (most clients don't). Watches `NameOwnerChanged` for
/// unique names losing their owner; leaked sessions would otherwise block
/// idle-exit forever and accumulate cipher state.
async fn reap_vanished_clients(
    connection: zbus::Connection,
    state: Arc<ServiceState>,
) -> zbus::Result<tokio::task::JoinHandle<()>> {
    let proxy = zbus::fdo::DBusProxy::new(&connection).await?;
    // Complete AddMatch before publishing the well-known name. Otherwise a fast client
    // can open a session and vanish before its disconnect is observable.
    let stream = proxy.receive_name_owner_changed().await?;
    Ok(tokio::spawn(async move {
        let mut stream = std::pin::pin!(stream);
        while let Some(signal) = std::future::poll_fn(|cx| stream.as_mut().poll_next(cx)).await {
            let Ok(args) = signal.args() else { continue };
            // A unique name (":x.y") with no new owner means the client is gone.
            if args.new_owner().is_none() && args.name().starts_with(':') {
                let paths = state.remove_sessions_owned_by(args.name().as_str());
                if !paths.is_empty() {
                    for path in &paths {
                        debug!(%path, owner = %args.name(), "reaping session of vanished client");
                        let _ = connection.object_server().remove::<Session, _>(path).await;
                    }
                    state.notify_activity_completion();
                }
            }
        }
    }))
}

/// Wait until SIGTERM/SIGINT or configured idle exit with no open transport sessions or temporary secrets.
/// Zero exits promptly after observed Noirpass application activity completes; -1 waits forever.
async fn wait_for_shutdown(
    connection: &zbus::Connection,
    state: &Arc<ServiceState>,
    idle_exit: i64,
) {
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("installing SIGTERM handler");
    let mut ticker = tokio::time::interval(Duration::from_secs(10));

    loop {
        tokio::select! {
            () = connection.closed() => {
                info!("session bus disconnected");
                state.begin_shutdown();
                state.wait_for_active_calls().await;
                return;
            }
            _ = tokio::signal::ctrl_c() => {
                info!("received SIGINT");
                state.begin_shutdown();
                state.wait_for_active_calls().await;
                return;
            }
            _ = sigterm.recv() => {
                info!("received SIGTERM");
                state.begin_shutdown();
                state.wait_for_active_calls().await;
                return;
            }
            () = state.store().wait_until_poisoned() => {
                info!("store commit outcome indeterminate; shutting down");
                state.begin_shutdown();
                state.wait_for_active_calls().await;
                return;
            }
            () = state.wait_for_activity_completion(), if idle_exit == 0 => {
                if state.try_begin_idle_shutdown(idle_exit) {
                    info!("Noirpass application activity complete");
                    return;
                }
            }
            _ = ticker.tick(), if idle_exit > 0 => {
                debug!(idle_exit, "idle check");
                if state.try_begin_idle_shutdown(idle_exit) {
                    info!(idle_exit, "idle limit reached");
                    return;
                }
            }
        }
    }
}
