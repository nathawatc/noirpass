//! noirpass daemon entry point.
//!
//! Connects to the session bus, serves the Secret Service object tree and
//! exits cleanly when idle (or on SIGTERM/SIGINT). Secrets at rest are
//! encrypted to the user's `OpenPGP` key; decryption goes through `gpg-agent`.

use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::builder::styling::{AnsiColor, Styles};
use clap::{Parser, Subcommand};
use tracing::{debug, info};
use zbus::export::futures_core::Stream;

use noirpass::config::{Config, load_recipient};
use noirpass::gpg::Gpg;
use noirpass::service::session::Session;
use noirpass::service::{SERVICE_PATH, Service, ServiceState, register_existing};
use noirpass::store::Store;

const SERVICE_NAME: &str = "org.freedesktop.secrets";

const CLI_STYLES: Styles = Styles::styled()
    .header(AnsiColor::Green.on_default().bold())
    .usage(AnsiColor::Green.on_default().bold())
    .literal(AnsiColor::Cyan.on_default().bold())
    .placeholder(AnsiColor::Cyan.on_default());

mod check;
mod deinit;
mod delete;
mod init;
mod list;
mod status;

/// Minimal on-demand GPG-backed freedesktop Secret Service.
#[derive(Parser, Debug)]
#[command(name = "noirpass", version, about, styles = CLI_STYLES)]
struct Cli {
    /// Directory for the metadata index and encrypted secret files.
    ///
    /// Defaults to `$XDG_DATA_HOME/noirpass` (or `~/.local/share/noirpass`).
    #[arg(long, env = "NOIRPASS_STORE")]
    store_dir: Option<PathBuf>,

    /// Exit after this many seconds without Noirpass application activity (0 = after activity, -1 = never).
    ///
    /// The daemon only exits when there are also no open sessions.
    /// Defaults to `config.toml` `idle_exit`, or 300 when omitted.
    #[arg(
        long,
        allow_negative_numbers = true,
        value_parser = clap::value_parser!(i64).range(-1..)
    )]
    idle_exit: Option<i64>,

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
    /// Permanently delete all Noirpass-owned state after two confirmations.
    Deinit,
    /// Report whether the noirpass store is initialized and usable.
    Status,
    /// List indexed secrets without decrypting them.
    List,
    /// Delete one indexed secret and its ciphertext file.
    Delete {
        /// Secret id shown by `noirpass list`.
        id: String,
        /// Skip the interactive confirmation.
        #[arg(short, long)]
        yes: bool,
    },
    /// Check redb item records against `.gpg` files and offer safe repair.
    Check {
        /// Delete every stale redb item record without prompting.
        #[arg(short, long)]
        yes: bool,
    },
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

pub(crate) async fn run() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .compact()
        .init();

    let cli = Cli::parse();
    let store_dir = cli.store_dir.unwrap_or_else(default_store_dir);

    match cli.command {
        Some(Command::Init { recipient }) => {
            return init::run(&store_dir, &recipient).map_err(Into::into);
        }
        Some(Command::Deinit) => return deinit::run(&store_dir).map_err(Into::into),
        Some(Command::Status) => return status::run(&store_dir).await.map_err(Into::into),
        Some(Command::List) => return list::run(&store_dir).map_err(Into::into),
        Some(Command::Delete { id, yes }) => {
            return delete::run(&store_dir, &id, yes).map_err(Into::into);
        }
        Some(Command::Check { yes }) => {
            return check::run(&store_dir, yes).map(|_| ()).map_err(Into::into);
        }
        None => {}
    }

    info!(store = %store_dir.display(), "opening store");

    let idle_exit = cli.idle_exit.unwrap_or(Config::load(&store_dir)?.idle_exit);
    let recipient = load_recipient(&store_dir)?;
    Store::probe_health(&store_dir)?;
    let store = Store::open(&store_dir)?;
    store.recover_interrupted_operations()?;
    store.ensure_default()?;
    store.ensure_safe_to_serve()?;
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
    connection.request_name(SERVICE_NAME).await?;
    info!(name = SERVICE_NAME, "secret service ready");

    wait_for_shutdown(&state, idle_exit).await;

    // Graceful shutdown: release the name so a future activation starts a
    // fresh instance, then drop the connection.
    let _ = connection.release_name(SERVICE_NAME).await;
    drop(connection);
    info!("exiting");
    Ok(())
}

fn confirm(prompt: &str, assume_yes: bool) -> noirpass::Result<bool> {
    if assume_yes {
        return Ok(true);
    }
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        return Err(noirpass::Error::Config(
            "interactive confirmation requires a terminal; pass --yes for unattended maintenance"
                .into(),
        ));
    }

    eprint!("{prompt} [y/N] ");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    stdin.read_line(&mut answer)?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
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

/// Wait until SIGTERM/SIGINT or configured idle exit with no open sessions.
/// Zero exits promptly after observed Noirpass application activity completes; -1 waits forever.
async fn wait_for_shutdown(state: &Arc<ServiceState>, idle_exit: i64) {
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("installing SIGTERM handler");
    let mut ticker = tokio::time::interval(Duration::from_secs(10));
    let mut poison_ticker = tokio::time::interval(Duration::from_millis(100));

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
            _ = poison_ticker.tick() => {
                if state.store().is_poisoned() {
                    info!("store commit outcome indeterminate; shutting down");
                    return;
                }
                if idle_exit == 0 && state.try_begin_idle_shutdown(idle_exit) {
                    info!("Noirpass application activity complete");
                    return;
                }
            }
            _ = ticker.tick() => {
                debug!(idle_exit, "idle check");
                if idle_exit > 0 && state.try_begin_idle_shutdown(idle_exit) {
                    info!(idle_exit, "idle limit reached");
                    return;
                }
            }
        }
    }
}
