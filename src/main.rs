//! noirpass daemon entry point.
//!
//! Connects to the session bus, serves the Secret Service object tree and
//! exits cleanly when idle (or on SIGTERM/SIGINT). Secrets at rest are
//! encrypted to the user's `OpenPGP` key; decryption goes through `gpg-agent`.

use std::collections::{HashMap, HashSet};
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::builder::styling::{AnsiColor, Styles};
use clap::{Parser, Subcommand};
use tracing::{debug, info};
use zbus::export::futures_core::Stream;

use noirpass::config::{Config, init_from_path, load_recipient, status};
use noirpass::gpg::Gpg;
use noirpass::service::{SERVICE_PATH, Service, ServiceState, register_existing};
use noirpass::session::Session;
use noirpass::store::{ItemMeta, Store};

const CLI_STYLES: Styles = Styles::styled()
    .header(AnsiColor::Green.on_default().bold())
    .usage(AnsiColor::Green.on_default().bold())
    .literal(AnsiColor::Cyan.on_default().bold())
    .placeholder(AnsiColor::Cyan.on_default());

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
        Some(Command::List) => {
            let store = Store::open_existing(&store_dir)?;
            store.recover_interrupted_operations()?;
            print_items(&store)?;
            return Ok(());
        }
        Some(Command::Delete { id, yes }) => {
            let store = Store::open_existing(&store_dir)?;
            store.recover_interrupted_operations()?;
            let item = store.get_item(&id)?;
            if confirm(
                &format!(
                    "delete secret {} with label {}?",
                    id,
                    serde_json::to_string(&item.label)?
                ),
                yes,
            )? {
                store.delete_item(&id)?;
                println!("deleted: {id}");
            } else {
                println!("not deleted: {id}");
            }
            return Ok(());
        }
        Some(Command::Check { yes }) => {
            let store = Store::open_existing(&store_dir)?;
            store.recover_interrupted_operations()?;
            if check_and_repair(&store, yes)? {
                return Ok(());
            }
            std::process::exit(1);
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
    connection.request_name(cli.bus_name.as_str()).await?;
    info!(name = %cli.bus_name, "secret service ready");

    wait_for_shutdown(&state, idle_exit).await;

    // Graceful shutdown: release the name so a future activation starts a
    // fresh instance, then drop the connection.
    let _ = connection.release_name(cli.bus_name.as_str()).await;
    drop(connection);
    info!("exiting");
    Ok(())
}

fn print_items(store: &Store) -> noirpass::Result<()> {
    let items = store.search_items(&HashMap::new())?;
    if items.is_empty() {
        println!("no secrets");
        return Ok(());
    }

    let collections: HashMap<String, String> = store
        .list_collections()?
        .into_iter()
        .map(|collection| (collection.id, collection.label))
        .collect();
    let missing: HashSet<String> = store
        .check_integrity()?
        .missing_secret_items
        .into_iter()
        .map(|item| item.table_key)
        .collect();

    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            println!();
        }
        print_item(item, &collections, missing.contains(&item.id))?;
    }
    Ok(())
}

fn print_item(
    item: &ItemMeta,
    collections: &HashMap<String, String>,
    missing_ciphertext: bool,
) -> noirpass::Result<()> {
    let collection_label = collections
        .get(&item.collection)
        .map_or("<missing collection>", String::as_str);
    println!("id: {}", item.id);
    println!("label: {}", serde_json::to_string(&item.label)?);
    println!(
        "collection: {} ({})",
        serde_json::to_string(collection_label)?,
        item.collection
    );
    println!("attributes: {}", serde_json::to_string(&item.attributes)?);
    let ciphertext_state = if missing_ciphertext {
        "missing"
    } else {
        "present"
    };
    println!("ciphertext: {ciphertext_state}");
    Ok(())
}

fn confirm(prompt: &str, assume_yes: bool) -> noirpass::Result<bool> {
    if assume_yes {
        return Ok(true);
    }
    let stdin = io::stdin();
    if !stdin.is_terminal() {
        return Err(noirpass::Error::Config(
            "interactive confirmation requires a terminal; pass --yes for unattended maintenance"
                .into(),
        ));
    }

    eprint!("{prompt} [y/N] ");
    io::stderr().flush()?;
    let mut answer = String::new();
    stdin.read_line(&mut answer)?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

#[allow(
    clippy::too_many_lines,
    reason = "linear reporting and repair keep each integrity category paired with its action"
)]
fn check_and_repair(store: &Store, assume_yes: bool) -> noirpass::Result<bool> {
    let report = store.check_integrity()?;
    if report.is_healthy() {
        println!("store health: ok");
        return Ok(true);
    }

    let mut collections = HashMap::new();
    for item in &report.missing_secret_items {
        if let Ok(collection) = store.get_collection(&item.metadata.collection) {
            collections.insert(collection.id, collection.label);
        }
    }

    for collection in &report.corrupt_collections {
        eprintln!(
            "corrupt collection entry: {} ({})",
            collection.table_key, collection.error
        );
    }
    for item in &report.missing_secret_items {
        eprintln!(
            "missing ciphertext: {} label={} collection={}",
            item.table_key,
            serde_json::to_string(&item.metadata.label)?,
            collections
                .get(&item.metadata.collection)
                .map_or(item.metadata.collection.as_str(), String::as_str)
        );
    }
    for item in &report.corrupt_items {
        eprintln!("corrupt redb entry: {} ({})", item.table_key, item.error);
    }
    for item in &report.ciphertext_mismatches {
        eprintln!(
            "ciphertext digest mismatch: {} label={} (kept)",
            item.table_key,
            serde_json::to_string(&item.metadata.label)?
        );
    }
    for item in &report.items_with_invalid_collection {
        eprintln!(
            "item with invalid collection: {} ({}) (kept)",
            item.table_key, item.error
        );
    }
    for (alias, collection) in &report.corrupt_aliases {
        eprintln!("corrupt alias: {alias} targets missing collection {collection}");
    }
    for (alias, collection) in &report.aliases_with_corrupt_collection {
        eprintln!("alias with corrupt collection: {alias} targets {collection} (kept)");
    }
    for file in &report.orphan_secret_files {
        eprintln!("orphan ciphertext: {file} (kept; inspect before manual deletion)");
    }
    for file in &report.recovery_secret_files {
        eprintln!("recoverable ciphertext: {file} (kept; inspect before manual deletion)");
    }

    let mut declined = 0usize;
    for item in report.missing_secret_items {
        if confirm(
            &format!(
                "delete stale redb entry {} with label {}?",
                item.table_key,
                serde_json::to_string(&item.metadata.label)?
            ),
            assume_yes,
        )? {
            store.delete_item(&item.table_key)?;
            println!("deleted stale entry: {}", item.table_key);
        } else {
            declined += 1;
        }
    }
    for item in report.corrupt_items {
        if confirm(
            &format!("delete corrupt redb entry {}?", item.table_key),
            assume_yes,
        )? {
            if item.table_key.len() == 32
                && item
                    .table_key
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                store.delete_item(&item.table_key)?;
            } else {
                store.delete_item_metadata(&item.table_key)?;
            }
            println!("deleted corrupt entry: {}", item.table_key);
        } else {
            declined += 1;
        }
    }

    for (alias, _) in report.corrupt_aliases {
        if confirm(&format!("delete corrupt alias {alias}?"), assume_yes)? {
            store.set_alias(&alias, None)?;
            println!("deleted corrupt alias: {alias}");
        } else {
            declined += 1;
        }
    }

    let remaining = store.check_integrity()?;
    if remaining.is_healthy() {
        println!("store health: repaired");
        return Ok(true);
    }
    eprintln!(
        concat!(
            "store health: needs attention ({} corrupt collections, {} missing ciphertext, ",
            "{} corrupt items, {} ciphertext mismatches, {} items with invalid collections, ",
            "{} corrupt aliases, {} aliases with corrupt collections, {} orphan ciphertext, ",
            "{} recoverable ciphertext, {} repair declined)"
        ),
        remaining.corrupt_collections.len(),
        remaining.missing_secret_items.len(),
        remaining.corrupt_items.len(),
        remaining.ciphertext_mismatches.len(),
        remaining.items_with_invalid_collection.len(),
        remaining.corrupt_aliases.len(),
        remaining.aliases_with_corrupt_collection.len(),
        remaining.orphan_secret_files.len(),
        remaining.recovery_secret_files.len(),
        declined
    );
    Ok(false)
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
