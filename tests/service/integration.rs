//! End-to-end integration tests.
//!
//! One shared fixture (built once per test process) provides:
//! an ephemeral `GNUPGHOME` with an empty-passphrase key, a private
//! `dbus-daemon --session`, and the real `noirpass` daemon binary
//! (`CARGO_BIN_EXE_noirpass`, so `cargo llvm-cov` instruments it and its
//! coverage is collected when it exits gracefully).
//!
//! All Secret Service scenarios run sequentially inside a single orchestrator
//! test (`end_to_end`): environment variables are process-global, the daemon
//! is shared, and running scenarios in-order lets the final teardown SIGTERM
//! the daemon *before* the test process exits so its coverage profile is
//! flushed deterministically. The idle-exit scenario runs as a separate test
//! against its own private bus and store, so it can run in parallel.
//!
//! A background "reaper" shell watches the test process and kills the
//! spawned daemons if the tests abort early, so nothing leaks on failure.

mod harness;
mod helpers;
mod runtime;
mod scenarios;
mod startup;

use std::process::Command;

use super::common::sigterm;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn end_to_end() {
    // Force fixture setup (bus + daemon + GNUPGHOME env) before any scenario.
    harness::harness();

    scenarios::run_ordered().await;
    eprintln!("scenario 14: no daemon gpg spawn");
    runtime::daemon_runtime_does_not_spawn_gpg();

    // Graceful teardown before the process exits: SIGTERM (asserts a clean
    // exit and flushes the daemon's coverage profile), then stop the bus and
    // agent. The reaper is the fallback for panics before this point.
    eprintln!("teardown");
    tokio::task::spawn_blocking(|| {
        let h = harness::harness();
        h.stop_daemon();
        sigterm(h.dbus_pid);
        let _ = Command::new("gpgconf")
            .arg("--homedir")
            .arg(&h.gnupg_home)
            .args(["--kill", "gpg-agent"])
            .status();
    })
    .await
    .unwrap();
}
