//! noirpass daemon entry point.
//!
//! Connects to the session bus, serves the Secret Service object tree and
//! exits cleanly when idle (or on SIGTERM/SIGINT). Secrets at rest are
//! encrypted to the user's `OpenPGP` key; decryption goes through `gpg-agent`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use tracing::{debug, info};
use zbus::export::futures_core::Stream;

use noirpass::config::{init_from_path, load_recipient, status};
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

    /// Exit after this many seconds without D-Bus activity (0 = never).
    ///
    /// The daemon only exits when there are also no open sessions.
    #[arg(long, default_value_t = 300)]
    idle_exit: u64,

    /// Well-known bus name to claim (testing hook).
    #[arg(long, hide = true, default_value = "org.freedesktop.secrets")]
    bus_name: String,

    /// One-shot setup/status commands.
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Initialize noirpass with an exported public `OpenPGP` recipient cert.
    Init {
        /// Recipient cert path, or '-' to read from stdin.
        #[arg(long)]
        recipient: String,
    },
    /// Report whether the noirpass store is initialized and usable.
    Status,
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

    match cli.command {
        Some(Command::Init { recipient }) => {
            if store_dir.join("index.redb").exists() || store_dir.join("secrets").exists() {
                Store::probe_health(&store_dir)?;
            }
            let config = init_from_path(&store_dir, &recipient)?;
            let store = Store::open(&store_dir)?;
            store.ensure_default()?;
            println!("initialized: yes");
            println!("data directory: {}", store_dir.display());
            println!("recipient fingerprint: {}", config.recipient_fingerprint);
            return Ok(());
        }
        Some(Command::Status) => {
            let mut status = status(&store_dir);
            if status.usable() {
                match load_recipient(&store_dir)
                    .and_then(|recipient| Gpg::from_cert(recipient.cert))
                {
                    Ok(gpg) => {
                        if let Err(err) = gpg.ensure_recipient_secret_available().await {
                            status.errors.push(err.to_string());
                        }
                    }
                    Err(err) => status.errors.push(err.to_string()),
                }
            }
            print_status(&status);
            if status.usable() {
                return Ok(());
            }
            std::process::exit(1);
        }
        None => {}
    }

    info!(store = %store_dir.display(), "opening store");

    let recipient = load_recipient(&store_dir)?;
    Store::probe_health(&store_dir)?;
    let store = Store::open(&store_dir)?;
    store.ensure_default()?;
    let gpg = Gpg::from_cert(recipient.cert)?;
    gpg.ensure_recipient_secret_available().await?;
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

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn opt_yes_no(value: Option<bool>) -> &'static str {
    value.map_or("unknown", yes_no)
}

fn print_status(status: &noirpass::config::Status) {
    println!("data directory: {}", status.data_dir.display());
    println!("initialized: {}", yes_no(status.usable()));
    println!("config.toml present: {}", yes_no(status.config_present));
    println!(
        "recipient cert present: {}",
        yes_no(status.recipient_cert_present)
    );
    println!(
        "configured recipient fingerprint: {}",
        status
            .configured_fingerprint
            .as_deref()
            .unwrap_or("unknown")
    );
    println!(
        "actual cert fingerprint: {}",
        status.actual_fingerprint.as_deref().unwrap_or("unknown")
    );
    println!(
        "fingerprint matches: {}",
        opt_yes_no(status.fingerprint_matches)
    );
    println!(
        "cert has encryption-capable key: {}",
        opt_yes_no(status.cert_has_encryption_key)
    );
    for err in &status.errors {
        eprintln!("error: {err}");
    }
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
