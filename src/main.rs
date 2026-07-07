//! noirpass daemon entry point.
//!
//! Connects to the session bus, serves the Secret Service object tree and
//! exits cleanly when idle (or on SIGTERM/SIGINT). Secrets at rest are
//! encrypted to the user's `OpenPGP` key; decryption goes through `gpg-agent`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tracing::{debug, info};
use zbus::export::futures_core::Stream;

use noirpass::gpg::Gpg;
use noirpass::service::{SERVICE_PATH, Service, ServiceState, register_existing};
use noirpass::session::Session;
use noirpass::store::Store;

/// Minimal on-demand GPG-backed freedesktop Secret Service.
#[derive(Parser, Debug)]
#[command(name = "noirpass", version, about)]
struct Cli {
    /// Directory for the metadata index and encrypted secret files.
    ///
    /// Defaults to `$XDG_DATA_HOME/noirpass` (or `~/.local/share/noirpass`).
    #[arg(long, env = "NOIRPASS_STORE")]
    store_dir: Option<PathBuf>,

    /// Fingerprint of the `OpenPGP` key to encrypt secrets to.
    ///
    /// Defaults to the first available secret key.
    #[arg(long)]
    key: Option<String>,

    /// Exit after this many seconds without D-Bus activity (0 = never).
    ///
    /// The daemon only exits when there are also no open sessions.
    #[arg(long, default_value_t = 300)]
    idle_exit: u64,

    /// Well-known bus name to claim (testing hook).
    #[arg(long, hide = true, default_value = "org.freedesktop.secrets")]
    bus_name: String,
}

/// `$XDG_DATA_HOME/noirpass`, falling back to `~/.local/share/noirpass`.
fn default_store_dir() -> PathBuf {
    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share")))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("noirpass")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .compact()
        .init();

    let cli = Cli::parse();
    let store_dir = cli.store_dir.unwrap_or_else(default_store_dir);
    info!(store = %store_dir.display(), "opening store");

    let store = Store::open(&store_dir)?;
    store.ensure_default()?;
    let gpg = Gpg::new(cli.key.as_deref())?;
    info!(key = %gpg.fingerprint(), "using OpenPGP key");
    let state = ServiceState::new(store, gpg);

    // Serve the service object first, then the pre-existing collections and
    // items, and only then claim the well-known name: clients activating us
    // never observe a half-populated object tree.
    let connection = zbus::connection::Builder::session()?
        .serve_at(SERVICE_PATH, Service::new(state.clone()))?
        .build()
        .await?;
    register_existing(connection.object_server(), &state).await?;
    tokio::spawn(reap_vanished_clients(connection.clone(), state.clone()));
    connection.request_name(cli.bus_name.as_str()).await?;
    info!(name = %cli.bus_name, "secret service ready");

    wait_for_shutdown(&state, cli.idle_exit).await;

    // Graceful shutdown: release the name so a future activation starts a
    // fresh instance, then drop the connection.
    let _ = connection.release_name(cli.bus_name.as_str()).await;
    drop(connection);
    info!("exiting");
    Ok(())
}

/// Reap sessions whose owning client left the bus without calling
/// `Session.Close` (most clients don't). Watches `NameOwnerChanged` for
/// unique names losing their owner; leaked sessions would otherwise block
/// idle-exit forever and accumulate cipher state.
async fn reap_vanished_clients(connection: zbus::Connection, state: Arc<ServiceState>) {
    let Ok(proxy) = zbus::fdo::DBusProxy::new(&connection).await else {
        return;
    };
    let Ok(stream) = proxy.receive_name_owner_changed().await else {
        return;
    };
    let mut stream = std::pin::pin!(stream);
    while let Some(signal) = std::future::poll_fn(|cx| stream.as_mut().poll_next(cx)).await {
        let Ok(args) = signal.args() else { continue };
        // A unique name (":x.y") with no new owner means the client is gone.
        if args.new_owner().is_none() && args.name().starts_with(':') {
            for path in state.remove_sessions_owned_by(args.name().as_str()) {
                debug!(%path, owner = %args.name(), "reaping session of vanished client");
                let _ = connection.object_server().remove::<Session, _>(&path).await;
            }
        }
    }
}

/// Wait until SIGTERM/SIGINT, or (when `idle_exit > 0`) until the bus has
/// been quiet for `idle_exit` seconds *and* no sessions are open.
async fn wait_for_shutdown(state: &Arc<ServiceState>, idle_exit: u64) {
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("installing SIGTERM handler");
    let idle_limit = Duration::from_secs(idle_exit);
    let mut ticker = tokio::time::interval(Duration::from_secs(10));

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("received SIGINT");
                return;
            }
            _ = sigterm.recv() => {
                info!("received SIGTERM");
                return;
            }
            _ = ticker.tick() => {
                if idle_exit == 0 {
                    continue;
                }
                let idle = state.idle_for();
                let sessions = state.session_count();
                debug!(?idle, sessions, "idle check");
                if idle >= idle_limit && sessions == 0 {
                    info!(?idle, "idle limit reached");
                    return;
                }
            }
        }
    }
}
