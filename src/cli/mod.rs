//! noirpass CLI argument parsing, command dispatch, and confirmation helpers.

use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::builder::styling::{AnsiColor, Styles};
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};

use noirpass::config::{
    CONFIG_FILE, DEFAULT_IDLE_EXIT_SECONDS, IDLE_EXIT_KEY, MIN_IDLE_EXIT_SECONDS,
    init_store_from_path,
};

const STORE_DIR_ENV: &str = "NOIRPASS_STORE";
const DEFAULT_STORE_SUBDIR: &str = "noirpass";
const XDG_DATA_HOME_ENV: &str = "XDG_DATA_HOME";
const HOME_ENV: &str = "HOME";
const FALLBACK_DATA_SUBDIR: &str = ".local/share";

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
    #[arg(long, env = STORE_DIR_ENV)]
    store_dir: Option<PathBuf>,

    /// Exit after this many seconds without Noirpass application activity (0 = after activity, -1 = never).
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
    /// Check redb metadata against `.gpg` files and offer safe repair.
    Check {
        /// Delete stale/corrupt entries (including canonical ciphertext) and corrupt aliases without prompting.
        #[arg(short, long)]
        yes: bool,
    },
}

/// `$XDG_DATA_HOME/noirpass`, falling back to `~/.local/share/noirpass`.
fn default_store_dir() -> noirpass::Result<PathBuf> {
    std::env::var_os(XDG_DATA_HOME_ENV)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| {
            std::env::var_os(HOME_ENV)
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .map(|home| home.join(FALLBACK_DATA_SUBDIR))
        })
        .map(|base| base.join(DEFAULT_STORE_SUBDIR))
        .ok_or_else(|| {
            noirpass::Error::Config(format!(
                "cannot determine default store directory: set an absolute {XDG_DATA_HOME_ENV} or {HOME_ENV}, or pass --store-dir / {STORE_DIR_ENV}"
            ))
        })
}

pub(crate) fn cli_command() -> clap::Command {
    let idle_exit_long_help = format!(
        "Exit after this many seconds without Noirpass application activity (0 = after activity, {MIN_IDLE_EXIT_SECONDS} = never).\n\n\
         The daemon only exits when there are also no open transport sessions \
         and no temporary secrets in the standard session collection.\n\
         Defaults to `{CONFIG_FILE}` `{IDLE_EXIT_KEY}`, or {DEFAULT_IDLE_EXIT_SECONDS} when omitted."
    );
    Cli::command().mut_arg("idle_exit", move |arg| arg.long_help(idle_exit_long_help))
}

pub(crate) async fn run() -> Result<ExitCode, Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .compact()
        .init();

    let matches = cli_command().get_matches();
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|err| err.exit());
    if cli.command.is_some() && cli.idle_exit.is_some() {
        return Err(noirpass::Error::Config(
            "--idle-exit applies only to the daemon and cannot be used with subcommands".into(),
        )
        .into());
    }
    let store_dir = match cli.store_dir {
        Some(dir) => dir,
        None => default_store_dir()?,
    };

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

#[cfg(test)]
mod man;
