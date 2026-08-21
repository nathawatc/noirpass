# Test Ownership

Own hermetic unit/integration fixtures, subprocesses, private D-Bus setup, temporary GnuPG homes,
PTY/TTY helpers, and CLI test harnesses.

## Hard Invariant

> Mandatory tests must be hermetic and must pass while an installed production Noirpass daemon is
> running concurrently for the same Unix user.

A mandatory test is invalid if correctness depends on no other Noirpass daemon running for the current
Unix user. Supported developer state:

```text
production Noirpass may be running
+
cargo test runs independently
```

No mandatory test may ask the developer to stop, replace, signal, inspect for cleanup, share resources
with, or otherwise interfere with production Noirpass. Tests may signal or terminate only child
processes they created and own.

## Store Isolation

Every test exercising Noirpass state uses a unique temporary store. Never use:

```text
$XDG_DATA_HOME/noirpass
$HOME/.local/share/noirpass
```

or any ambient/default production store. CLI subprocess tests use `CARGO_BIN_EXE_noirpass`, pass an
explicit temporary `--store-dir`, and remove inherited `NOIRPASS_STORE` where practical. They never
rely on ambient store selection. A test specifically covering default-store discovery must override
all relevant `HOME`/XDG variables inside its isolated child so resolution remains test-owned. Never
touch the user's real Noirpass data directory.

## D-Bus Isolation

Mandatory D-Bus tests spawn a private fixture-owned `dbus-daemon`. Every Noirpass/client child in that
scenario receives the private `DBUS_SESSION_BUS_ADDRESS` explicitly. Never connect mandatory tests to
the user's ambient session bus and never request or release `org.freedesktop.secrets` there. Tests
must remain valid while production Noirpass owns that name on the real bus. Ambient desktop-client
smoke tests are optional, explicitly feature-gated, and skip safely when unavailable.

## GnuPG Isolation

Every test invoking `gpg`, `gpgconf`, or GPG-agent-backed code uses a fresh temporary `GNUPGHOME` and
passes `--homedir <temp>` to subprocesses where supported. Every spawned Noirpass process needing
agent access receives that home explicitly. Never use `~/.gnupg`, import fixture keys into the user's
keyring, kill the user's agent, or depend on ambient keys. `gpgconf --kill gpg-agent` is allowed only
with the exact fixture-owned home.

## Process Ownership

Retain `std::process::Child` handles and signal/wait exact owned PIDs. Graceful SIGTERM is preferred
for coverage-enabled daemons so profiles flush before wait. Never use broad cleanup:

```text
pkill noirpass
killall noirpass
pkill -f noirpass
pgrep noirpass | ...
```

Never identify a daemon under test by process name when an owned `Child`/PID exists. Do not terminate
an installed production daemon. Any fallback reaper uses exact fixture-recorded child PIDs and
fixture-owned paths only; pattern-based cleanup is forbidden. Assert actual `ExitStatus`; never infer
status from shell pipelines or output.

## Environment Isolation

Prefer `Command::env(...)` and `Command::env_remove(...)` on child processes over process-global
`std::env::set_var(...)` or `std::env::remove_var(...)`. If global mutation is unavoidable, put it
behind one shared serialized fixture, establish it before concurrent users begin, restore it when
lifetime is not whole-process, and document why child-local injection cannot work. Important variables:

```text
DBUS_SESSION_BUS_ADDRESS
GNUPGHOME
NOIRPASS_STORE
HOME
XDG_DATA_HOME
XDG_RUNTIME_DIR
```

Do not assume caller values are safe.

## Filesystem and CLI Safety

Use unique temporary directories; never use predictable shared paths such as `/tmp/noirpass` or
`/tmp/noirpass-test`. Never follow symlinks into user-owned paths. Cleanup may operate only inside
fixture-owned roots. Every destructive command targets only fixture state. PTY tests pass explicit
temporary store selection and preserve `deinit`'s real-TTY, exactly-two-confirmation, no-`--yes`
policy. Piped-input tests never target a default/production store.

Mandatory unit/integration scenarios must use private bus, temporary store, and temporary GNUPGHOME
fixtures. Real-client/real-desktop coverage is optional only when explicitly gated; it must not turn
mandatory `cargo test` into an ambient bus, keyring, store, or process test.
