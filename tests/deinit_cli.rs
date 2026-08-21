//! Focused CLI tests for interactive Noirpass deinitialization.
//!
//! These tests use temporary stores containing only synthetic Noirpass paths.
//! An in-process POSIX pseudo-terminal makes accepted confirmations exercise the
//! same TTY gate used by the production binary.

use std::ffi::{CStr, c_char, c_int};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::fd::FromRawFd;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use noirpass::store::Store;
use sequoia_openpgp::cert::CertBuilder;
use sequoia_openpgp::serialize::Serialize;
use tempfile::{TempDir, tempdir};

unsafe extern "C" {
    fn posix_openpt(flags: c_int) -> c_int;
    fn grantpt(fd: c_int) -> c_int;
    fn unlockpt(fd: c_int) -> c_int;
    fn ptsname_r(fd: c_int, buffer: *mut c_char, length: usize) -> c_int;
}

const ITEM_ID: &str = "0123456789abcdef0123456789abcdef";
const RECOVERY: &str = ".noirpass-create-0123456789abcdef0123456789abcdef-0123456789abcdef.gpg";
const CONFIG_TMP: &str = ".noirpass-tmp-0123456789abcdef";

fn seeded_store() -> TempDir {
    let store = tempdir().unwrap();
    fs::create_dir(store.path().join("keys")).unwrap();
    fs::create_dir(store.path().join("secrets")).unwrap();
    fs::write(
        store.path().join("config.toml"),
        "version = 1\nrecipient_fingerprint = \"test\"\nrecipient_cert = \"keys/recipient.pgp\"\nidle_exit = 300\n",
    )
    .unwrap();
    fs::write(store.path().join("keys/recipient.pgp"), b"recipient").unwrap();
    fs::write(
        store.path().join("keys/.noirpass-tmp-0123456789abcdef"),
        b"temporary",
    )
    .unwrap();
    drop(Store::open(store.path()).unwrap());
    fs::write(
        store.path().join("secrets").join(format!("{ITEM_ID}.gpg")),
        b"ciphertext",
    )
    .unwrap();
    fs::write(store.path().join("secrets").join(RECOVERY), b"recovery").unwrap();
    fs::write(store.path().join("secrets/keep.txt"), b"unrelated").unwrap();
    fs::write(store.path().join(CONFIG_TMP), b"temporary").unwrap();
    fs::write(store.path().join("keep.txt"), b"unrelated").unwrap();
    store
}

fn write_recipient(store: &Path, file_name: &str, userid: &str) -> PathBuf {
    let (cert, _) = CertBuilder::new()
        .add_userid(userid)
        .add_storage_encryption_subkey()
        .generate()
        .unwrap();
    let mut bytes = Vec::new();
    cert.serialize(&mut bytes).unwrap();
    let path = store.join(file_name);
    fs::write(&path, bytes).unwrap();
    path
}

fn run_init(store: &Path, recipient: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .arg("--store-dir")
        .arg(store)
        .args(["init", "--recipient"])
        .arg(recipient)
        .output()
        .unwrap()
}

fn open_pty() -> (File, File) {
    let master_fd = unsafe { posix_openpt(0o2) };
    assert!(
        master_fd >= 0,
        "posix_openpt failed: {}",
        std::io::Error::last_os_error()
    );
    assert_eq!(unsafe { grantpt(master_fd) }, 0, "grantpt failed");
    assert_eq!(unsafe { unlockpt(master_fd) }, 0, "unlockpt failed");

    let mut name = [0 as c_char; 128];
    assert_eq!(
        unsafe { ptsname_r(master_fd, name.as_mut_ptr(), name.len()) },
        0,
        "ptsname_r failed"
    );
    let name = unsafe { CStr::from_ptr(name.as_ptr()) };
    let slave = OpenOptions::new()
        .read(true)
        .write(true)
        .open(name.to_str().unwrap())
        .unwrap();
    let master = unsafe { File::from_raw_fd(master_fd) };
    (master, slave)
}

fn run_tty(store: &Path, input: &[u8]) -> Output {
    run_tty_with_input(store, input)
}

fn run_tty_eof(store: &Path, input: &[u8]) -> Output {
    let mut input_with_eof = input.to_vec();
    input_with_eof.push(0x04);
    run_tty_with_input(store, &input_with_eof)
}

fn run_tty_with_input(store: &Path, input: &[u8]) -> Output {
    let (mut master, slave) = open_pty();
    let child = Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .arg("--store-dir")
        .arg(store)
        .arg("deinit")
        .stdin(Stdio::from(slave))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    master.write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    drop(master);
    output
}

fn run_piped(store: &Path, args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .arg("--store-dir")
        .arg(store)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

fn assert_intact(snapshot: &[(PathBuf, Vec<u8>)]) {
    for (path, bytes) in snapshot {
        assert_eq!(
            fs::read(path).unwrap(),
            bytes.as_slice(),
            "changed {}",
            path.display()
        );
    }
}

fn snapshot(store: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    [
        "config.toml",
        "keys/recipient.pgp",
        "keys/.noirpass-tmp-0123456789abcdef",
        "index.redb",
        &format!("secrets/{ITEM_ID}.gpg"),
        &format!("secrets/{RECOVERY}"),
        "secrets/keep.txt",
        CONFIG_TMP,
        "keep.txt",
    ]
    .into_iter()
    .map(|relative| {
        let path = store.join(relative);
        (path.clone(), fs::read(path).unwrap())
    })
    .collect()
}

#[test]
fn first_confirmation_declined_preserves_store() {
    let store = seeded_store();
    let before = snapshot(store.path());

    let output = run_tty(store.path(), b"n\n");

    assert!(output.status.success());
    assert_intact(&before);
}

#[test]
fn first_accepted_second_declined_preserves_store() {
    let store = seeded_store();
    let before = snapshot(store.path());

    let output = run_tty(store.path(), b"y\nn\n");

    assert!(output.status.success());
    assert_intact(&before);
}

#[test]
fn both_confirmations_delete_known_store_state() {
    let store = seeded_store();

    let output = run_tty(store.path(), b"y\ny\n");

    assert!(output.status.success());
    assert!(!store.path().join("config.toml").exists());
    assert!(!store.path().join("keys/recipient.pgp").exists());
    assert!(
        !store
            .path()
            .join("keys/.noirpass-tmp-0123456789abcdef")
            .exists()
    );
    assert!(!store.path().join("keys").exists());
    assert!(!store.path().join("index.redb").exists());
    assert!(!store.path().join(format!("secrets/{ITEM_ID}.gpg")).exists());
    assert!(!store.path().join("secrets").join(RECOVERY).exists());
    assert!(!store.path().join(CONFIG_TMP).exists());
    assert!(store.path().join("secrets/keep.txt").exists());
    assert!(store.path().join("keep.txt").exists());
}

#[test]
fn deinit_then_init_new_recipient_preserves_unknown_files() {
    let store = seeded_store();

    let deinit_output = run_tty(store.path(), b"y\ny\n");
    assert!(deinit_output.status.success());
    assert!(!store.path().join("config.toml").exists());
    assert!(!store.path().join("index.redb").exists());
    assert_eq!(
        fs::read(store.path().join("secrets/keep.txt")).unwrap(),
        b"unrelated"
    );

    let recipient = write_recipient(store.path(), "recipient-b.pgp", "recipient-b");
    let init_output = run_init(store.path(), &recipient);

    assert!(
        init_output.status.success(),
        "init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&init_output.stdout),
        String::from_utf8_lossy(&init_output.stderr)
    );
    assert!(store.path().join("config.toml").exists());
    assert!(store.path().join("index.redb").exists());
    assert_eq!(
        fs::read(store.path().join("secrets/keep.txt")).unwrap(),
        b"unrelated"
    );
}

#[test]
fn unknown_secrets_directory_without_database_does_not_block_init() {
    let store = tempdir().unwrap();
    fs::create_dir(store.path().join("secrets")).unwrap();
    fs::write(store.path().join("secrets/keep.txt"), b"unrelated").unwrap();
    let recipient = write_recipient(store.path(), "recipient.pgp", "unknown-only");

    let output = run_init(store.path(), &recipient);

    assert!(output.status.success());
    assert_eq!(
        fs::read(store.path().join("secrets/keep.txt")).unwrap(),
        b"unrelated"
    );
    assert!(store.path().join("config.toml").exists());
    assert!(store.path().join("index.redb").exists());
}

#[test]
fn secrets_symlink_without_database_fails_closed() {
    let store = tempdir().unwrap();
    let outside = tempdir().unwrap();
    fs::write(outside.path().join("keep.txt"), b"outside").unwrap();
    symlink(outside.path(), store.path().join("secrets")).unwrap();
    let recipient = write_recipient(store.path(), "recipient.pgp", "secrets-symlink");

    let output = run_init(store.path(), &recipient);

    assert!(!output.status.success());
    assert!(!store.path().join("config.toml").exists());
    assert!(!store.path().join("index.redb").exists());
    assert!(!store.path().join("keys/recipient.pgp").exists());
    assert!(
        fs::symlink_metadata(store.path().join("secrets"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        fs::read(outside.path().join("keep.txt")).unwrap(),
        b"outside"
    );
}

#[test]
fn secrets_regular_file_without_database_fails_closed() {
    let store = tempdir().unwrap();
    fs::write(store.path().join("secrets"), b"not a directory").unwrap();
    let recipient = write_recipient(store.path(), "recipient.pgp", "secrets-file");

    let output = run_init(store.path(), &recipient);

    assert!(!output.status.success());
    assert!(!store.path().join("config.toml").exists());
    assert!(!store.path().join("index.redb").exists());
    assert_eq!(
        fs::read(store.path().join("secrets")).unwrap(),
        b"not a directory"
    );
}

#[test]
fn gpg_symlink_without_database_fails_closed_without_following_target() {
    let store = tempdir().unwrap();
    let outside = tempdir().unwrap();
    let outside_ciphertext = outside.path().join("old.gpg");
    fs::write(&outside_ciphertext, b"outside ciphertext").unwrap();
    fs::create_dir(store.path().join("secrets")).unwrap();
    symlink(&outside_ciphertext, store.path().join("secrets/old.gpg")).unwrap();
    let recipient = write_recipient(store.path(), "recipient.pgp", "gpg-symlink");

    let output = run_init(store.path(), &recipient);

    assert!(!output.status.success());
    assert!(!store.path().join("config.toml").exists());
    assert!(!store.path().join("index.redb").exists());
    assert!(
        fs::symlink_metadata(store.path().join("secrets/old.gpg"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read(outside_ciphertext).unwrap(), b"outside ciphertext");
}

#[test]
fn ambiguous_ciphertext_without_database_fails_closed() {
    let store = tempdir().unwrap();
    fs::create_dir(store.path().join("secrets")).unwrap();
    let ciphertext = store.path().join(format!("secrets/{ITEM_ID}.gpg"));
    fs::write(&ciphertext, b"old ciphertext").unwrap();
    let recipient = write_recipient(store.path(), "recipient.pgp", "ambiguous");

    let output = run_init(store.path(), &recipient);

    assert!(!output.status.success());
    assert!(!store.path().join("config.toml").exists());
    assert!(!store.path().join("index.redb").exists());
    assert_eq!(fs::read(ciphertext).unwrap(), b"old ciphertext");
}

#[test]
fn empty_secrets_directory_without_database_does_not_block_init() {
    let store = tempdir().unwrap();
    fs::create_dir(store.path().join("secrets")).unwrap();
    let recipient = write_recipient(store.path(), "recipient.pgp", "empty-secrets");

    let output = run_init(store.path(), &recipient);

    assert!(output.status.success());
    assert!(store.path().join("config.toml").exists());
    assert!(store.path().join("index.redb").exists());
}

#[test]
fn existing_valid_database_still_gets_health_probe() {
    let store = tempdir().unwrap();
    drop(Store::open(store.path()).unwrap());
    let recipient = write_recipient(store.path(), "recipient.pgp", "existing-db");

    let output = run_init(store.path(), &recipient);

    assert!(output.status.success());
    assert!(store.path().join("config.toml").exists());
    assert!(store.path().join("index.redb").exists());
}

#[test]
fn eof_at_first_confirmation_preserves_store() {
    let store = seeded_store();
    let before = snapshot(store.path());

    let _output = run_tty_eof(store.path(), b"");

    assert_intact(&before);
}

#[test]
fn eof_at_second_confirmation_preserves_store() {
    let store = seeded_store();
    let before = snapshot(store.path());

    let _output = run_tty_eof(store.path(), b"y\n");

    assert_intact(&before);
}

#[test]
fn piped_confirmation_is_rejected_and_preserves_store() {
    let store = seeded_store();
    let before = snapshot(store.path());

    let output = run_piped(store.path(), &["deinit"], b"y\ny\n");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("interactive terminal"));
    assert_intact(&before);
}

#[test]
fn symlinked_known_state_is_rejected_without_touching_target() {
    let store = seeded_store();
    let outside = tempdir().unwrap();
    let outside_secret = outside.path().join(format!("{ITEM_ID}.gpg"));
    fs::write(&outside_secret, b"outside").unwrap();
    fs::remove_dir_all(store.path().join("secrets")).unwrap();
    symlink(outside.path(), store.path().join("secrets")).unwrap();

    let output = run_tty(store.path(), b"y\ny\n");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("refusing to follow symlink"));
    assert!(store.path().join("config.toml").exists());
    assert!(store.path().join("keys/recipient.pgp").exists());
    assert!(store.path().join("index.redb").exists());
    assert!(outside_secret.exists());
}

#[test]
fn deinit_yes_option_is_rejected_and_preserves_store() {
    let store = seeded_store();
    let before = snapshot(store.path());

    let output = run_piped(store.path(), &["deinit", "--yes"], b"");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unexpected argument"));
    assert_intact(&before);
}

#[test]
fn custom_store_directory_only_selected_store_is_deleted() {
    let selected = seeded_store();
    let other = seeded_store();
    let other_before = snapshot(other.path());

    let output = run_tty(selected.path(), b"y\ny\n");

    assert!(output.status.success());
    assert!(!selected.path().join("config.toml").exists());
    assert_intact(&other_before);
}
