use super::super::format::parse_config;
use super::super::{Config, DEFAULT_IDLE_EXIT_SECONDS, config_path, init_from_bytes};
use crate::gpg::test_support::TestGnupg;
use std::fs;

#[test]
fn config_idle_exit_defaults_and_accepts_override() {
    let base = "version = 1\nrecipient_fingerprint = \"fingerprint\"\nrecipient_cert = \"keys/recipient.pgp\"\n";

    assert_eq!(
        parse_config(base).unwrap().idle_exit,
        DEFAULT_IDLE_EXIT_SECONDS
    );
    assert_eq!(
        parse_config(&format!("{base}idle_exit = 42\n"))
            .unwrap()
            .idle_exit,
        42
    );
}

#[test]
fn generated_config_idle_exit_matches_parser_fallback() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    init_from_bytes(tmp.path(), &gnupg.export_public_binary()).unwrap();
    let generated = fs::read_to_string(config_path(tmp.path())).unwrap();
    assert!(generated.contains(&format!("idle_exit = {DEFAULT_IDLE_EXIT_SECONDS}")));
    let without_idle_exit = generated
        .lines()
        .filter(|line| !line.starts_with("idle_exit = "))
        .collect::<Vec<_>>()
        .join("\n");

    assert_eq!(
        Config::load(tmp.path()).unwrap().idle_exit,
        parse_config(&without_idle_exit).unwrap().idle_exit
    );
}

#[test]
fn config_idle_exit_accepts_minus_one_and_rejects_lower_values() {
    let base = "version = 1\nrecipient_fingerprint = \"fingerprint\"\nrecipient_cert = \"keys/recipient.pgp\"\n";

    assert_eq!(
        parse_config(&format!("{base}idle_exit = -1\n"))
            .unwrap()
            .idle_exit,
        -1
    );
    let err = parse_config(&format!("{base}idle_exit = -2\n")).unwrap_err();
    assert!(err.to_string().contains("must be -1 or greater"));
}
