//! Single-source-of-truth man page renderer and drift tests.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::{Arg, ArgAction};

use noirpass::config::{
    CONFIG_FILE, CONFIG_VERSION, DEFAULT_IDLE_EXIT_SECONDS, IDLE_EXIT_KEY, MIN_IDLE_EXIT_SECONDS,
    RECIPIENT_CERT_KEY, RECIPIENT_FINGERPRINT_KEY, RECIPIENT_REL, VERSION_KEY,
};
use noirpass::service::{SERVICE_NAME, SESSION_COLLECTION_ID};
use noirpass::store::{INDEX_FILE, SECRETS_DIR};

use super::{
    DEFAULT_STORE_SUBDIR, FALLBACK_DATA_SUBDIR, HOME_ENV, STORE_DIR_ENV, XDG_DATA_HOME_ENV,
    cli_command,
};

const MAN_DATE: &str = "2026-11-25";
const MAX_ROFF_LINE_BYTES: usize = 78;

fn man_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("man")
}

fn escape_roff(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str(r"\e"),
            '-' => out.push_str(r"\-"),
            _ => out.push(ch),
        }
    }
    out
}

fn finish_roff_line(line: &str) -> String {
    if line.starts_with('.') || line.starts_with('\'') {
        format!(r"\&{line}")
    } else {
        line.to_string()
    }
}

fn write_wrapped_roff(out: &mut String, roff_text: &str) {
    let mut current = String::new();
    for word in roff_text.split_whitespace() {
        if current.is_empty() {
            current.push_str(word);
        } else if current.len() + 1 + word.len() <= MAX_ROFF_LINE_BYTES {
            current.push(' ');
            current.push_str(word);
        } else {
            let _ = writeln!(out, "{}", finish_roff_line(&current));
            current.clear();
            current.push_str(word);
        }
    }
    if !current.is_empty() {
        let _ = writeln!(out, "{}", finish_roff_line(&current));
    }
}

fn write_paragraphs(out: &mut String, text: &str) {
    let mut first_para = true;
    for para in text.split("\n\n") {
        let joined = para
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        if joined.is_empty() {
            continue;
        }
        if !first_para {
            let _ = writeln!(out, ".PP");
        }
        first_para = false;
        write_wrapped_roff(out, &escape_roff(&joined));
    }
}

fn format_arg_heading(arg: &Arg) -> String {
    let mut parts = Vec::new();
    if let Some(short) = arg.get_short() {
        parts.push(format!(r"\fB\-{short}\fR"));
    }
    if let Some(long) = arg.get_long() {
        parts.push(format!(r"\fB\-\-{}\fR", escape_roff(long)));
    }
    let mut heading = if parts.is_empty() {
        let name = arg
            .get_value_names()
            .and_then(|names| names.first())
            .map_or_else(|| arg.get_id().as_str(), clap::builder::Str::as_str);
        format!(r"\fI{}\fR", escape_roff(name))
    } else {
        parts.join(", ")
    };

    if arg.get_action().takes_values() && !parts.is_empty() {
        let value_name = arg
            .get_value_names()
            .and_then(|names| names.first())
            .map_or_else(|| arg.get_id().as_str(), clap::builder::Str::as_str);
        let _ = write!(heading, r" \fI<{}>\fR", escape_roff(value_name));
    }
    heading
}

fn render_arg_list(out: &mut String, args: &[&Arg], leading_pp: bool) {
    for (idx, arg) in args.iter().enumerate() {
        if idx > 0 || leading_pp {
            let _ = writeln!(out, ".PP");
        }
        let _ = writeln!(out, "{}", format_arg_heading(arg));
        let _ = writeln!(out, ".RS");
        if let Some(help) = arg.get_long_help().or_else(|| arg.get_help()) {
            write_paragraphs(out, &help.to_string());
        }
        if let Some(env) = arg.get_env() {
            let _ = writeln!(out, ".PP");
            let _ = writeln!(out, r"[env: \fB{}\fR]", escape_roff(&env.to_string_lossy()));
        }
        let _ = writeln!(out, ".RE");
    }
}

fn format_subcommand_synopsis(sub: &clap::Command) -> String {
    let mut parts = vec![format!(r"\fBnoirpass {}\fR", escape_roff(sub.get_name()))];
    let has_options = sub.get_arguments().any(|arg| {
        !arg.is_positional() && !matches!(arg.get_action(), ArgAction::Help | ArgAction::Version)
    });
    if has_options {
        parts.push(r"[\fIOPTIONS\fR]".to_string());
    }
    for arg in sub.get_positionals() {
        let name = arg
            .get_value_names()
            .and_then(|names| names.first())
            .map_or_else(|| arg.get_id().as_str(), clap::builder::Str::as_str);
        let formatted = format!(r"\fI<{}>\fR", escape_roff(name));
        if arg.is_required_set() {
            parts.push(formatted);
        } else {
            parts.push(format!("[{formatted}]"));
        }
    }
    parts.join(" ")
}

fn render_noirpass_commands(out: &mut String, cmd: &clap::Command) {
    let subcommands: Vec<_> = cmd
        .get_subcommands()
        .filter(|sub| !sub.is_hide_set() && sub.get_name() != "help")
        .collect();
    if subcommands.is_empty() {
        return;
    }
    let _ = writeln!(out, ".SH COMMANDS");
    for sub in subcommands {
        let _ = writeln!(out, ".SS {}", escape_roff(sub.get_name()));
        let _ = writeln!(out, "{}", format_subcommand_synopsis(sub));
        if let Some(sub_about) = sub.get_long_about().or_else(|| sub.get_about()) {
            let _ = writeln!(out, ".PP");
            write_paragraphs(out, &sub_about.to_string());
        }
        let sub_args: Vec<_> = sub
            .get_arguments()
            .filter(|arg| !arg.is_hide_set() && !matches!(arg.get_action(), ArgAction::Help))
            .collect();
        render_arg_list(out, &sub_args, true);
    }
}

fn render_noirpass_env_and_files(out: &mut String) {
    let _ = writeln!(out, ".SH ENVIRONMENT");
    for (var, desc) in [
        (
            STORE_DIR_ENV,
            r"Overrides the store directory when \fB\-\-store\-dir\fR is not passed.".to_string(),
        ),
        (
            XDG_DATA_HOME_ENV,
            format!(
                r"Base directory for the default store \fI${XDG_DATA_HOME_ENV}/{DEFAULT_STORE_SUBDIR}\fR when set to an absolute path."
            ),
        ),
        (
            HOME_ENV,
            format!(
                r"Fallback base directory for \fI~/{FALLBACK_DATA_SUBDIR}/{DEFAULT_STORE_SUBDIR}\fR when \fB{XDG_DATA_HOME_ENV}\fR is unset."
            ),
        ),
        (
            "RUST_LOG",
            r"Controls diagnostic log filtering via \fBtracing_subscriber\fR.".to_string(),
        ),
        (
            "DBUS_SESSION_BUS_ADDRESS",
            r"Session bus socket used by the daemon.".to_string(),
        ),
        (
            "GNUPGHOME",
            r"GnuPG home directory used when locating \fBgpg\-agent\fR(1).".to_string(),
        ),
    ] {
        let _ = writeln!(out, ".TP");
        let _ = writeln!(out, r"\fB{}\fR", escape_roff(var));
        write_wrapped_roff(out, &desc);
    }

    let _ = writeln!(out, ".SH FILES");
    for (path, desc) in [
        (
            format!(r"\fI${XDG_DATA_HOME_ENV}/{DEFAULT_STORE_SUBDIR}\fR"),
            format!(
                r"Default store directory (or \fI~/{FALLBACK_DATA_SUBDIR}/{DEFAULT_STORE_SUBDIR}\fR when \fB{XDG_DATA_HOME_ENV}\fR is unset)."
            ),
        ),
        (
            format!(r"\fI<STORE_DIR>/{CONFIG_FILE}\fR"),
            r"Persisted store configuration and runtime settings. See \fBnoirpass.toml\fR(5)."
                .to_string(),
        ),
        (
            format!(r"\fI<STORE_DIR>/{RECIPIENT_REL}\fR"),
            r"Stored binary OpenPGP public certificate for the configured recipient.".to_string(),
        ),
        (
            format!(r"\fI<STORE_DIR>/{INDEX_FILE}\fR"),
            r"Metadata database for collections, aliases, and item attributes.".to_string(),
        ),
        (
            format!(r"\fI<STORE_DIR>/{SECRETS_DIR}/\fR"),
            r"Directory holding per\-item OpenPGP ciphertext files.".to_string(),
        ),
    ] {
        let _ = writeln!(out, ".TP");
        let _ = writeln!(out, "{path}");
        write_wrapped_roff(out, &desc);
    }
}

/// Render `man/noirpass.1` from the Clap command definition and config/service constants.
#[must_use]
pub(super) fn render_noirpass_1() -> String {
    let mut cmd = cli_command();
    cmd.build();

    let version = env!("CARGO_PKG_VERSION");
    let about = cmd
        .get_about()
        .map_or_else(String::new, ToString::to_string);

    let mut out = String::new();
    let _ = writeln!(
        out,
        r#".TH "NOIRPASS" "1" "{MAN_DATE}" "noirpass {}" "User Commands""#,
        escape_roff(version)
    );
    let _ = writeln!(out, ".SH NAME");
    let _ = writeln!(
        out,
        r"{} \- {}",
        escape_roff(cmd.get_name()),
        escape_roff(&about)
    );
    let _ = writeln!(out, ".SH SYNOPSIS");
    let _ = writeln!(
        out,
        r"\fB{}\fR [\fIOPTIONS\fR] [\fICOMMAND\fR]",
        escape_roff(cmd.get_name())
    );
    let _ = writeln!(out, ".SH DESCRIPTION");
    write_wrapped_roff(&mut out, &escape_roff(&about));
    let _ = writeln!(out, ".PP");
    write_wrapped_roff(
        &mut out,
        &format!(
            r"When invoked without a subcommand, \fBnoirpass\fR starts the D\-Bus daemon and claims \fB{}\fR on the session bus once the object tree is ready. Persistent values are encrypted at rest with OpenPGP and decrypted via \fBgpg\-agent\fR(1); temporary secrets in the \fB{}\fR collection stay in zeroizing memory until deleted or daemon exit.",
            escape_roff(SERVICE_NAME),
            escape_roff(SESSION_COLLECTION_ID),
        ),
    );
    let _ = writeln!(out, ".PP");
    write_wrapped_roff(
        &mut out,
        &format!(
            r"Configuration defaults come from \fB{}\fR (see \fBnoirpass.toml\fR(5)).",
            escape_roff(CONFIG_FILE),
        ),
    );

    let options: Vec<_> = cmd
        .get_arguments()
        .filter(|arg| !arg.is_positional() && !arg.is_hide_set())
        .collect();
    if !options.is_empty() {
        let _ = writeln!(out, ".SH OPTIONS");
        render_arg_list(&mut out, &options, false);
    }

    render_noirpass_commands(&mut out, &cmd);
    render_noirpass_env_and_files(&mut out);

    let _ = writeln!(out, ".SH EXIT STATUS");
    write_wrapped_roff(
        &mut out,
        r"Exits \fB0\fR on success and a non\-zero status on configuration, store, agent, D\-Bus, or confirmation failure.",
    );
    let _ = writeln!(out, ".SH SEE ALSO");
    let _ = writeln!(
        out,
        r"\fBnoirpass.toml\fR(5), \fBgpg\fR(1), \fBgpg\-agent\fR(1), \fBsystemctl\fR(1)"
    );
    out
}

fn render_toml_settings(out: &mut String) {
    let _ = writeln!(out, ".SH SETTINGS");
    let _ = writeln!(
        out,
        r"\fB{}\fR (integer, default \fB{}\fR, minimum \fB{}\fR)",
        escape_roff(IDLE_EXIT_KEY),
        DEFAULT_IDLE_EXIT_SECONDS,
        escape_roff(&MIN_IDLE_EXIT_SECONDS.to_string()),
    );
    let _ = writeln!(out, ".RS");
    write_wrapped_roff(
        out,
        &format!(
            r"Controls how the daemon exits when no transport session is open and the temporary \fB{}\fR collection is empty:",
            escape_roff(SESSION_COLLECTION_ID),
        ),
    );
    let _ = writeln!(out, ".TP");
    let _ = writeln!(
        out,
        r"\fB{}\fR",
        escape_roff(&MIN_IDLE_EXIT_SECONDS.to_string())
    );
    write_wrapped_roff(
        out,
        r"Keep the daemon running until a signal (\fBSIGINT\fR/\fBSIGTERM\fR), session bus disconnect, or fatal store error.",
    );
    let _ = writeln!(out, ".TP");
    let _ = writeln!(out, r"\fB0\fR");
    write_wrapped_roff(
        out,
        r"Exit after the first completed Noirpass application method or property handler, once no handler is active, no transport session is open, and no temporary secret remains.",
    );
    let _ = writeln!(out, ".TP");
    let _ = writeln!(out, r"\fIPositive integer\fR");
    write_wrapped_roff(
        out,
        r"Exit after this many seconds without Noirpass application activity, once no handler is active, no transport session is open, and no temporary secret remains.",
    );
    let _ = writeln!(out, ".PP");
    write_wrapped_roff(
        out,
        &format!(
            r"Default is \fB{DEFAULT_IDLE_EXIT_SECONDS}\fR. An existing \fB{}\fR without \fB{}\fR uses the same default. Re\-running \fBnoirpass init\fR for the same primary recipient preserves the current deserialized value. Command\-line \fB\-\-idle\-exit <VALUE>\fR overrides configuration for one daemon invocation.",
            escape_roff(CONFIG_FILE),
            escape_roff(IDLE_EXIT_KEY),
        ),
    );
    let _ = writeln!(out, ".PP");
    write_wrapped_roff(
        out,
        &format!(
            r"A temporary secret in the \fB{}\fR collection deliberately pins the daemon so Secret Service clients requesting \(lqremember for this session\(rq keep that secret until they delete it or the daemon/login session ends. Calls managed directly by \fBzbus\fR, including \fBorg.freedesktop.DBus.Peer.Ping\fR and \fBorg.freedesktop.DBus.Introspectable.Introspect\fR, do not count as Noirpass application activity.",
            escape_roff(SESSION_COLLECTION_ID),
        ),
    );
    let _ = writeln!(out, ".RE");
}

fn render_toml_managed_and_examples(out: &mut String) {
    let _ = writeln!(out, ".SH MANAGED FIELDS");
    write_wrapped_roff(
        out,
        r"These fields are written by \fBnoirpass init\fR and validated on startup and maintenance:",
    );
    let _ = writeln!(out, ".TP");
    let _ = writeln!(
        out,
        r"\fB{}\fR (integer, currently \fB{CONFIG_VERSION}\fR)",
        escape_roff(VERSION_KEY)
    );
    let _ = writeln!(out, "Persisted configuration format version.");
    let _ = writeln!(out, ".TP");
    let _ = writeln!(
        out,
        r"\fB{}\fR (string)",
        escape_roff(RECIPIENT_FINGERPRINT_KEY)
    );
    let _ = writeln!(
        out,
        "Expected uppercase hex primary OpenPGP fingerprint of the store recipient."
    );
    let _ = writeln!(out, ".TP");
    let _ = writeln!(
        out,
        r"\fB{}\fR (string, default \fB{}\fR)",
        escape_roff(RECIPIENT_CERT_KEY),
        escape_roff(RECIPIENT_REL)
    );
    write_wrapped_roff(
        out,
        r"Store\-relative path to the stored binary recipient certificate; must contain only normal relative path components inside the store directory.",
    );

    let _ = writeln!(out, ".SH EXAMPLES");
    write_wrapped_roff(
        out,
        "Exit after the first Noirpass handler finishes with no transport session or temporary secret:",
    );
    let _ = writeln!(out, ".RS");
    let _ = writeln!(out, ".nf");
    let _ = writeln!(out, r"{} = 0", escape_roff(IDLE_EXIT_KEY));
    let _ = writeln!(out, ".fi");
    let _ = writeln!(out, ".RE");
    let _ = writeln!(out, ".PP");
    write_wrapped_roff(out, "Keep the daemon running:");
    let _ = writeln!(out, ".RS");
    let _ = writeln!(out, ".nf");
    let _ = writeln!(
        out,
        r"{} = {}",
        escape_roff(IDLE_EXIT_KEY),
        escape_roff(&MIN_IDLE_EXIT_SECONDS.to_string())
    );
    let _ = writeln!(out, ".fi");
    let _ = writeln!(out, ".RE");
    let _ = writeln!(out, ".PP");
    write_wrapped_roff(out, "Exit after ten inactive minutes:");
    let _ = writeln!(out, ".RS");
    let _ = writeln!(out, ".nf");
    let _ = writeln!(out, r"{} = 600", escape_roff(IDLE_EXIT_KEY));
    let _ = writeln!(out, ".fi");
    let _ = writeln!(out, ".RE");
}

/// Render `man/noirpass.toml.5` from configuration and service constants.
#[must_use]
pub(super) fn render_noirpass_toml_5() -> String {
    let version = env!("CARGO_PKG_VERSION");
    let default_xdg = format!("${XDG_DATA_HOME_ENV}/{DEFAULT_STORE_SUBDIR}/{CONFIG_FILE}");
    let default_home = format!("~/{FALLBACK_DATA_SUBDIR}/{DEFAULT_STORE_SUBDIR}/{CONFIG_FILE}");
    let override_path = format!("<STORE_DIR>/{CONFIG_FILE}");

    let mut out = String::new();
    let _ = writeln!(
        out,
        r#".TH "NOIRPASS.TOML" "5" "{MAN_DATE}" "noirpass {}" "File Formats""#,
        escape_roff(version)
    );
    let _ = writeln!(out, ".SH NAME");
    let _ = writeln!(
        out,
        r"noirpass.toml \- Noirpass configuration file ({})",
        escape_roff(CONFIG_FILE)
    );
    let _ = writeln!(out, ".SH SYNOPSIS");
    let _ = writeln!(out, r"\fI{}\fR", escape_roff(&default_xdg));
    let _ = writeln!(out, ".PP");
    let _ = writeln!(out, r"\fI{}\fR", escape_roff(&default_home));
    let _ = writeln!(out, ".PP");
    let _ = writeln!(out, r"\fI{}\fR", escape_roff(&override_path));
    let _ = writeln!(out, ".SH DESCRIPTION");
    write_wrapped_roff(
        &mut out,
        &format!(
            r"Noirpass stores configuration in \fB{}\fR inside its store directory. By default this is \fI{}\fR when \fB{}\fR is set to an absolute path, or \fI{}\fR otherwise. Passing \fB\-\-store\-dir\fR or setting \fB{}\fR selects \fI{}\fR instead.",
            escape_roff(CONFIG_FILE),
            escape_roff(&default_xdg),
            escape_roff(XDG_DATA_HOME_ENV),
            escape_roff(&default_home),
            escape_roff(STORE_DIR_ENV),
            escape_roff(&override_path),
        ),
    );
    let _ = writeln!(out, ".PP");
    write_wrapped_roff(
        &mut out,
        &format!(
            r"\fBnoirpass init \-\-recipient <FILE|\->\fR creates \fB{}\fR with mode \fB0600\fR inside a \fB0700\fR store directory. Recipient fields are managed by Noirpass; edit only documented runtime settings.",
            escape_roff(CONFIG_FILE),
        ),
    );

    render_toml_settings(&mut out);
    render_toml_managed_and_examples(&mut out);

    let _ = writeln!(out, ".SH SEE ALSO");
    let _ = writeln!(out, r"\fBnoirpass\fR(1)");
    out
}

#[test]
fn man_pages_match_source_of_truth() {
    let dir = man_dir();
    let pages = [
        ("noirpass.1", render_noirpass_1()),
        ("noirpass.toml.5", render_noirpass_toml_5()),
    ];

    if std::env::var_os("UPDATE_MAN_PAGES").is_some() {
        fs::create_dir_all(&dir).expect("create man directory");
        for (name, content) in &pages {
            fs::write(dir.join(name), content).expect("write generated man page");
        }
    }

    for (name, expected) in &pages {
        let path = dir.join(name);
        let actual = fs::read_to_string(&path).unwrap_or_else(|err| {
            panic!(
                "missing {}: {err}; run `UPDATE_MAN_PAGES=1 cargo test --bin noirpass man_pages_match_source_of_truth`",
                path.display()
            )
        });
        assert_eq!(
            actual,
            *expected,
            "{} is out of date; run `UPDATE_MAN_PAGES=1 cargo test --bin noirpass man_pages_match_source_of_truth`",
            path.display()
        );
    }

    if let Ok(output) = Command::new("mandoc")
        .arg("-Tlint")
        .args(pages.iter().map(|(name, _)| dir.join(name)))
        .output()
    {
        assert!(
            output.status.success(),
            "mandoc -Tlint failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn cli_help_reflects_config_constants() {
    let cmd = cli_command();
    let idle_exit = cmd
        .get_arguments()
        .find(|arg| arg.get_id() == "idle_exit")
        .expect("idle_exit arg exists");
    let help = idle_exit
        .get_long_help()
        .expect("idle_exit long_help")
        .to_string();
    assert!(help.contains(&DEFAULT_IDLE_EXIT_SECONDS.to_string()));
    assert!(help.contains(CONFIG_FILE));
    assert!(help.contains(IDLE_EXIT_KEY));
}
