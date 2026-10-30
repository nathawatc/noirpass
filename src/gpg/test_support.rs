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
        Self::from_dir_with(|path| {
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
        Self::from_dir_with(|path| {
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

    fn from_dir_with(init: impl FnOnce(&Path)) -> Self {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        // Allow loopback pinentry so key generation with an empty
        // passphrase works headlessly.
        fs::write(
            dir.path().join("gpg-agent.conf"),
            "allow-loopback-pinentry\n",
        )
        .unwrap();
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

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .skip_while(|line| !line.starts_with("sec:"))
        .find_map(|line| {
            line.strip_prefix("fpr:")
                .and_then(|rest| rest.split(':').nth(8))
        })
        .filter(|fpr| !fpr.is_empty())
        .expect("test gpg key has no fingerprint")
        .to_string()
}
