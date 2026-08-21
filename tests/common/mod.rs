//! Shared child-process and private-bus fixtures for integration tests.

use std::io::{BufRead, BufReader, Write as _};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Start every Noirpass child with ambient store selection removed.
pub fn noirpass_command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_noirpass"));
    command.env_remove("NOIRPASS_STORE");
    command
}

/// Generate an empty-passphrase key in a fresh, hermetic `GNUPGHOME`.
pub fn setup_gnupg(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(dir.join("gpg-agent.conf"), "allow-loopback-pinentry\n").unwrap();
    let status = Command::new("gpg")
        .args(["--batch", "--no-tty", "--homedir"])
        .arg(dir)
        .args([
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--quick-gen-key",
            "noirpass e2e <e2e@t>",
            "default",
            "default",
            "never",
        ])
        .status()
        .expect("spawn gpg");
    assert!(status.success(), "gpg --quick-gen-key failed");
}

fn secret_fingerprint(dir: &Path) -> String {
    let output = Command::new("gpg")
        .args(["--batch", "--no-tty", "--homedir"])
        .arg(dir)
        .args(["--list-secret-keys", "--with-colons"])
        .output()
        .expect("spawn gpg --list-secret-keys");
    assert!(output.status.success(), "gpg --list-secret-keys failed");
    let text = String::from_utf8_lossy(&output.stdout);
    let mut seen_sec = false;
    for line in text.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        match fields.first().copied() {
            Some("sec") => seen_sec = true,
            Some("fpr") if seen_sec => {
                if let Some(fpr) = fields.get(9)
                    && !fpr.is_empty()
                {
                    return (*fpr).to_string();
                }
            }
            _ => {}
        }
    }
    panic!("no test secret key fingerprint")
}

/// Export the public certificate from an isolated `GnuPG` home.
pub fn export_public_cert(dir: &Path) -> Vec<u8> {
    let fingerprint = secret_fingerprint(dir);
    let output = Command::new("gpg")
        .args(["--batch", "--no-tty", "--homedir"])
        .arg(dir)
        .args(["--armor", "--export", &fingerprint])
        .output()
        .expect("spawn gpg --export");
    assert!(output.status.success(), "gpg --export failed");
    output.stdout
}

/// Initialize an isolated store with an explicit recipient certificate.
pub fn init_noirpass_store(store: &Path, recipient: &[u8]) {
    let recipient_path = store.join("recipient.asc");
    std::fs::write(&recipient_path, recipient).unwrap();
    let output = noirpass_command()
        .arg("--store-dir")
        .arg(store)
        .arg("init")
        .arg("--recipient")
        .arg(&recipient_path)
        .output()
        .expect("spawn noirpass init");
    assert!(
        output.status.success(),
        "noirpass init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Initialize an isolated store by streaming a certificate on stdin.
#[allow(dead_code)]
pub fn init_noirpass_store_from_stdin(store: &Path, recipient: &[u8]) {
    let mut child = noirpass_command()
        .arg("--store-dir")
        .arg(store)
        .arg("init")
        .arg("--recipient")
        .arg("-")
        .stdin(Stdio::piped())
        .spawn()
        .expect("spawn noirpass init stdin");
    child.stdin.as_mut().unwrap().write_all(recipient).unwrap();
    let status = child.wait().expect("wait noirpass init stdin");
    assert!(status.success(), "noirpass init --recipient - failed");
}

/// Create a fake `gpg` executable that records unexpected production spawns.
pub fn fake_gpg_dir() -> (tempfile::TempDir, std::path::PathBuf) {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("gpg.log");
    let script = format!(
        "#!/bin/sh\necho gpg-spawn >> '{}'\nexit 99\n",
        log.display()
    );
    let gpg = dir.path().join("gpg");
    std::fs::write(&gpg, script).unwrap();
    std::fs::set_permissions(&gpg, std::fs::Permissions::from_mode(0o755)).unwrap();
    (dir, log)
}

/// Spawn a private session bus and return `(child, address)`.
pub fn spawn_dbus_daemon() -> (Child, String) {
    let mut child = Command::new("dbus-daemon")
        .args(["--session", "--nofork", "--print-address"])
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn dbus-daemon");
    let stdout = child.stdout.take().expect("dbus-daemon stdout");
    let mut address = String::new();
    BufReader::new(stdout)
        .read_line(&mut address)
        .expect("read dbus address");
    let address = address.trim().to_string();
    assert!(!address.is_empty(), "dbus-daemon printed no address");
    (child, address)
}

/// Spawn the real daemon binary against a private bus, `GnuPG` home, and store.
pub fn spawn_daemon(
    bus: &str,
    gnupg: &Path,
    store: &Path,
    idle_exit: &str,
    fake_gpg_dir: Option<&Path>,
) -> Child {
    let mut command = noirpass_command();
    command.arg("--store-dir").arg(store);
    if !idle_exit.is_empty() {
        command.args(["--idle-exit", idle_exit]);
    }
    command
        .env("DBUS_SESSION_BUS_ADDRESS", bus)
        .env("GNUPGHOME", gnupg)
        .env("RUST_LOG", "info");
    if let Some(fake_gpg_dir) = fake_gpg_dir {
        let old_path = std::env::var_os("PATH").unwrap_or_default();
        let mut paths = vec![fake_gpg_dir.to_path_buf()];
        paths.extend(std::env::split_paths(&old_path));
        command.env("PATH", std::env::join_paths(paths).unwrap());
    }
    command.spawn().expect("spawn noirpass daemon")
}

/// Poll until `org.freedesktop.secrets` has an owner on the private bus.
pub fn wait_for_name(bus: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let output = Command::new("dbus-send")
            .arg(format!("--bus={bus}"))
            .args([
                "--print-reply",
                "--dest=org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus.NameHasOwner",
                "string:org.freedesktop.secrets",
            ])
            .output()
            .expect("spawn dbus-send");
        if String::from_utf8_lossy(&output.stdout).contains("boolean true") {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("daemon did not claim org.freedesktop.secrets within 10s");
}

/// Wait for a child to exit, with a timeout.
pub fn wait_with_timeout(child: &mut Child, timeout: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            return status;
        }
        assert!(Instant::now() < deadline, "process did not exit in time");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Signal one exact fixture-owned child PID.
pub fn sigterm(pid: u32) {
    let _ = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status();
}

/// Record one exact fixture-owned daemon PID for abort cleanup.
#[allow(dead_code)]
pub fn record_daemon_pid(path: &Path, daemon: &Child) {
    std::fs::write(path, daemon.id().to_string()).expect("record daemon pid");
}
