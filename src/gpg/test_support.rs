//! Shared test fixture: an ephemeral, hermetic `GnuPG` home.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use sequoia_openpgp::Cert;
use sequoia_openpgp::serialize::Serialize;

/// An ephemeral `GnuPG` home with a freshly generated, empty-passphrase key.
///
/// Never touches the user's real `~/.gnupg`: every `gpg`/`gpgconf` call and
/// every Sequoia context is scoped to this temporary directory. The agent
/// is killed on drop.
pub struct TestGnupg {
    dir: tempfile::TempDir,
    fingerprint: String,
}

impl TestGnupg {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();

        // Allow loopback pinentry so key generation with an empty
        // passphrase works headlessly.
        fs::write(
            dir.path().join("gpg-agent.conf"),
            "allow-loopback-pinentry\n",
        )
        .unwrap();

        Self::from_dir_with(dir, |path| {
            let status = Command::new("gpg")
                .args(["--batch", "--no-tty", "--homedir"])
                .arg(path)
                .args([
                    "--pinentry-mode",
                    "loopback",
                    "--passphrase",
                    "",
                    "--quick-gen-key",
                    "noirpass test <t@t>",
                    "default",
                    "default",
                    "never",
                ])
                .status()
                .expect("spawn gpg");
            assert!(status.success(), "gpg --quick-gen-key failed");
        })
    }

    pub fn import(cert: &Cert) -> Self {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();

        fs::write(
            dir.path().join("gpg-agent.conf"),
            "allow-loopback-pinentry\n",
        )
        .unwrap();

        Self::from_dir_with(dir, |path| {
            let mut tsk = Vec::new();
            cert.as_tsk().serialize(&mut tsk).unwrap();
            let mut child = Command::new("gpg")
                .args(["--batch", "--no-tty", "--homedir"])
                .arg(path)
                .arg("--import")
                .stdin(std::process::Stdio::piped())
                .spawn()
                .expect("spawn gpg --import");
            child.stdin.as_mut().unwrap().write_all(&tsk).unwrap();
            let status = child.wait().expect("wait gpg --import");
            assert!(status.success(), "gpg --import failed");
        })
    }

    fn from_dir_with(dir: tempfile::TempDir, init: impl FnOnce(&Path)) -> Self {
        init(dir.path());
        let status = Command::new("gpg")
            .args(["--batch", "--no-tty", "--homedir"])
            .arg(dir.path())
            .arg("--list-secret-keys")
            .status()
            .expect("spawn gpg --list-secret-keys");
        assert!(status.success(), "gpg --list-secret-keys failed");

        let fingerprint = secret_fingerprint(dir.path());
        Self { dir, fingerprint }
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn export_public_binary(&self) -> Vec<u8> {
        export_public(self.dir.path(), &self.fingerprint, false)
    }

    pub fn export_public_armored(&self) -> Vec<u8> {
        export_public(self.dir.path(), &self.fingerprint, true)
    }
}

impl Drop for TestGnupg {
    fn drop(&mut self) {
        let _ = Command::new("gpgconf")
            .arg("--homedir")
            .arg(self.dir.path())
            .args(["--kill", "gpg-agent"])
            .status();
    }
}

fn export_public(homedir: &Path, fingerprint: &str, armor: bool) -> Vec<u8> {
    let mut cmd = Command::new("gpg");
    cmd.args(["--batch", "--no-tty", "--homedir"]).arg(homedir);
    if armor {
        cmd.arg("--armor");
    }
    let output = cmd
        .arg("--export")
        .arg(fingerprint)
        .output()
        .expect("gpg export");
    assert!(output.status.success(), "gpg --export failed");
    output.stdout
}

fn secret_fingerprint(homedir: &Path) -> String {
    let output = Command::new("gpg")
        .args(["--batch", "--no-tty", "--homedir"])
        .arg(homedir)
        .args(["--list-secret-keys", "--with-colons"])
        .output()
        .expect("gpg list secret keys");
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
    panic!("test gpg key has no fingerprint")
}
