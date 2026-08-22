use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use super::super::common::{
    export_public_cert, fake_gpg_dir, init_noirpass_store, record_daemon_pid, setup_gnupg, sigterm,
    spawn_daemon, spawn_dbus_daemon, wait_for_name, wait_with_timeout,
};

pub(super) struct Harness {
    pub(super) gnupg_home: PathBuf,
    pub(super) store_dir: PathBuf,
    pub(super) fake_gpg_dir: PathBuf,
    pub(super) fake_gpg_log: PathBuf,
    bus_address: String,
    pub(super) dbus_pid: u32,
    daemon_pid_file: PathBuf,
    daemon: Mutex<Child>,
    _keep: Vec<tempfile::TempDir>,
}

static HARNESS: OnceLock<Harness> = OnceLock::new();

pub(super) fn harness() -> &'static Harness {
    HARNESS.get_or_init(Harness::init)
}

impl Harness {
    fn init() -> Self {
        let gnupg_tmp = tempfile::tempdir().unwrap();
        setup_gnupg(gnupg_tmp.path());
        let recipient = export_public_cert(gnupg_tmp.path());

        let (dbus, bus_address) = spawn_dbus_daemon();
        let dbus_pid = dbus.id();
        // The dbus-daemon Child is intentionally leaked (statics never drop);
        // the reaper below cleans it up when the test process exits.
        std::mem::forget(dbus);

        let daemon_pid_tmp = tempfile::tempdir().unwrap();
        let daemon_pid_file = daemon_pid_tmp.path().join("daemon.pid");

        // The high-level oo7/zbus session helpers used by scenarios read
        // DBUS_SESSION_BUS_ADDRESS from process environment, so child-only injection cannot
        // configure them. This one shared fixture sets it before dependent tests begin.
        // SAFETY: called once, from the OnceLock initializer, before any test
        // creates a zbus/oo7 connection or reads these variables. The other
        // test thread is blocked on the OnceLock during this call.
        unsafe {
            std::env::set_var("DBUS_SESSION_BUS_ADDRESS", &bus_address);
            std::env::set_var("GNUPGHOME", gnupg_tmp.path());
        }

        let store_tmp = tempfile::tempdir().unwrap();
        init_noirpass_store(store_tmp.path(), &recipient);
        let (fake_gpg_tmp, fake_gpg_log) = fake_gpg_dir();
        let fake_gpg_dir = fake_gpg_tmp.path().to_path_buf();
        let daemon = spawn_daemon(
            &bus_address,
            gnupg_tmp.path(),
            store_tmp.path(),
            "-1",
            Some(&fake_gpg_dir),
        );
        record_daemon_pid(&daemon_pid_file, &daemon);
        wait_for_name(&bus_address);

        let gnupg_home = gnupg_tmp.path().to_path_buf();
        let store_dir = store_tmp.path().to_path_buf();

        // Reaper: if the test process dies (success or abort), terminate the
        // exact fixture-owned daemon PID (SIGTERM, so it flushes coverage), the
        // private bus, and the test-owned gpg-agent. The PID file is updated
        // when the harness respawns its daemon.
        let test_pid = std::process::id();
        let script = format!(
            "while kill -0 {test_pid} 2>/dev/null; do sleep 0.5; done; \\
             if test -r '{pid_file}'; then \\
               IFS= read -r daemon_pid < '{pid_file}' || daemon_pid=; \\
               case \"$daemon_pid\" in \\
                 ''|*[!0-9]*) ;; \\
                 *) kill -TERM \"$daemon_pid\" 2>/dev/null ;; \\
               esac; \\
             fi; \\
             kill -TERM {dbus_pid} 2>/dev/null; \\
             gpgconf --homedir '{gnupg}' --kill gpg-agent 2>/dev/null; true",
            pid_file = daemon_pid_file.display(),
            gnupg = gnupg_home.display(),
        );
        #[allow(
            clippy::zombie_processes,
            reason = "the reaper must outlive the test process by design"
        )]
        Command::new("sh")
            .args(["-c", &script])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn reaper");

        Self {
            gnupg_home,
            store_dir,
            fake_gpg_dir,
            fake_gpg_log,
            bus_address,
            dbus_pid,
            daemon_pid_file,
            daemon: Mutex::new(daemon),
            _keep: vec![gnupg_tmp, store_tmp, fake_gpg_tmp, daemon_pid_tmp],
        }
    }

    /// SIGTERM the daemon and assert it exits cleanly.
    pub(super) fn stop_daemon(&self) {
        let mut child = self.daemon.lock().unwrap();
        sigterm(child.id());
        let status = wait_with_timeout(&mut child, Duration::from_secs(10));
        std::fs::write(&self.daemon_pid_file, "").expect("clear daemon pid");
        assert!(status.success(), "daemon exited with {status}");
    }

    /// Start a fresh daemon on the same bus and store, waiting for the name.
    pub(super) fn respawn_daemon(&self) {
        let fresh = spawn_daemon(
            &self.bus_address,
            &self.gnupg_home,
            &self.store_dir,
            "-1",
            Some(&self.fake_gpg_dir),
        );
        record_daemon_pid(&self.daemon_pid_file, &fresh);
        *self.daemon.lock().unwrap() = fresh;
        wait_for_name(&self.bus_address);
    }
}
