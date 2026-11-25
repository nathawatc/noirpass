//! noirpass CLI argument parsing, command dispatch, and confirmation helpers.

use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::builder::styling::{AnsiColor, Styles};
use clap::{Parser, Subcommand};

use noirpass::config::{MIN_IDLE_EXIT_SECONDS, init_store_from_path};

const CLI_STYLES: Styles = Styles::styled()
    .header(AnsiColor::Green.on_default().bold())
    .usage(AnsiColor::Green.on_default().bold())
    .literal(AnsiColor::Cyan.on_default().bold())
    .placeholder(AnsiColor::Cyan.on_default());

mod check;
mod daemon;
mod deinit;
mod delete;
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
    /// The daemon only exits when there are also no open transport sessions
    /// and no temporary secrets in the standard session collection.
    /// Defaults to `config.toml` `idle_exit`, or 300 when omitted.
    #[arg(
        long,
        allow_negative_numbers = true,
        value_parser = clap::value_parser!(i64).range(MIN_IDLE_EXIT_SECONDS..)
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

pub(crate) async fn run() -> Result<ExitCode, Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .compact()
        .init();

    let cli = Cli::parse();
    let store_dir = cli.store_dir.unwrap_or_else(default_store_dir);

    match cli.command {
        Some(Command::Init { recipient }) => {
            let config = init_store_from_path(&store_dir, &recipient)?;
            println!("initialized: yes");
            println!("data directory: {}", store_dir.display());
            println!("recipient fingerprint: {}", config.recipient_fingerprint);
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::Deinit) => {
            deinit::run(&store_dir)?;
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::Status) => status::run(&store_dir).await.map_err(Into::into),
        Some(Command::List) => {
            list::run(&store_dir)?;
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::Delete { id, yes }) => {
            delete::run(&store_dir, &id, yes)?;
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::Check { yes }) => check::run(&store_dir, yes).map_err(Into::into),
        None => daemon::run(&store_dir, cli.idle_exit).await,
    }
}

fn confirm(prompt: &str, assume_yes: bool) -> noirpass::Result<bool> {
    if assume_yes {
        return Ok(true);
    }
    confirm_terminal(
        prompt,
        "interactive confirmation requires a terminal; pass --yes for unattended maintenance",
    )
}

fn confirm_terminal(prompt: &str, non_tty_error: &str) -> noirpass::Result<bool> {
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        return Err(noirpass::Error::Config(non_tty_error.into()));
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
