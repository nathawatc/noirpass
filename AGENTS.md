# AGENTS.md

Instructions for coding agents working in this repository. Terse and
factual; see module doc comments (`//!` at the top of each `src/*.rs` file)
for the full rationale behind each design decision.

## Environment

- NixOS. There is **no cargo, rustc, clippy, rustfmt, or gpg on the bare
  `PATH`**. Every build/test/lint command must be run through the flake
  devShell:

  ```sh
  nix develop -c cargo <subcommand> ...
  ```

  Running bare `cargo ...` will fail or silently pick up the wrong
  toolchain — do not do it.

- **Never run tests against the real session bus.** The ambient
  `org.freedesktop.secrets` name on this machine's session bus is owned by
  gnome-keyring, not noirpass. `tests/integration.rs` creates its own
  private `dbus-daemon --session` and its own ephemeral `GNUPGHOME` per
  test process — it never touches `~/.gnupg` or the real
  `DBUS_SESSION_BUS_ADDRESS`. Unit tests that need GnuPG use the same
  pattern (`src/gpg.rs::test_support::TestGnupg`).

## Build / Test / Lint / Coverage

```sh
nix develop -c cargo build --release
nix develop -c cargo fmt --check
nix develop -c cargo clippy --all-targets -- -D warnings
nix develop -c cargo test
nix develop -c cargo llvm-cov --all-targets --fail-under-lines 80
```

All four gates (fmt, clippy, test, coverage) must pass with zero warnings
before a change is complete. `Cargo.toml` sets `clippy::all` and
`clippy::pedantic` to `warn` project-wide (with `module_name_repetitions`,
`missing_errors_doc`, `missing_panics_doc` explicitly allowed) — the `-D
warnings` on the command line is what turns those into hard failures.

## Architecture Map

| File | Role |
| --- | --- |
| `src/lib.rs` | Crate root; declares modules, re-exports `Error`/`Result`. |
| `src/main.rs` | Binary entry point: CLI (`clap`), opens the `Store`/`Gpg`, builds the `zbus` connection, serves the service object then pre-existing collections/items/aliases (`register_existing`) *before* claiming the well-known name, spawns the `NameOwnerChanged` reaper, runs the idle/signal shutdown loop. |
| `src/service.rs` | `ServiceState` (shared: `Store`, `Gpg`, session table, activity clock), the `org.freedesktop.Secret.Service` D-Bus object, D-Bus object-path helpers, object registration/unregistration helpers. |
| `src/collection.rs` | `org.freedesktop.Secret.Collection` D-Bus object. One `Collection` type serves both the canonical `/collection/<id>` path and the `/aliases/<name>` paths (via an internal `Target::Collection` / `Target::Alias` enum); alias-backed instances re-resolve the alias on every call. |
| `src/item.rs` | `org.freedesktop.Secret.Item` D-Bus object. |
| `src/session.rs` | `org.freedesktop.Secret.Session` D-Bus object (`Close` only) and the `Secret` wire struct (`(oayays)`). |
| `src/crypto.rs` | Session transport crypto: `DhHandshake` (1024-bit MODP Diffie-Hellman → HKDF-SHA256 → AES-128 key) and `SessionCipher` (`Plain` / `Dh`, AES-128-CBC-PKCS7). Pure, synchronous, no I/O. |
| `src/gpg.rs` | `Gpg`: exports the recipient certificate once via `gpg --export` at construction, encrypts in-process with Sequoia, decrypts by delegating PKESK unlock to the running `gpg-agent` (`sequoia-gpg-agent`). Also hosts `test_support::TestGnupg`, the hermetic ephemeral-`GNUPGHOME` fixture shared by unit and integration tests. |
| `src/store.rs` | `Store`: redb tables (`collections`, `items`, `aliases`) for metadata, plus `secrets/<id>.gpg` ciphertext files. Every method opens its own short-lived transaction; the store never sees plaintext. |
| `src/error.rs` | Crate-wide `Error` enum (`thiserror`) and its mapping to `zbus::fdo::Error`. |
| `tests/integration.rs` | End-to-end scenarios (real `noirpass` binary, private `dbus-daemon`, `oo7` client for both session transports, real `secret-tool`, restart persistence, signals, idle-exit) run through one shared process-wide `Harness`. |

Object path scheme:

```text
/org/freedesktop/secrets                                  Service
/org/freedesktop/secrets/collection/<collection-id>        Collection
/org/freedesktop/secrets/collection/<collection-id>/<item-id>  Item
/org/freedesktop/secrets/session/s<n>                       Session
/org/freedesktop/secrets/aliases/<name>                     Collection (alias-resolving)
```

## Invariants to Preserve

- Secret bytes never touch `redb` and never appear in a log line.
  Plaintext only ever exists in `zeroize::Zeroizing` buffers, and only for
  as long as it takes to re-encrypt (to the session cipher, or to the GPG
  recipient) or hand off to the caller.
- Every D-Bus method handler calls `state.touch()` as its first action, so
  the idle-exit timer only fires on a genuinely quiet bus. Adding a new
  method without this call will make it invisible to idle tracking.
- Prompts are always the root path `/` (`root_path()` in `service.rs`,
  `no_prompt()` in `collection.rs`/`item.rs`) — noirpass never returns a
  real Prompt object. Keep new methods that have a `prompt` out-arg
  consistent with this.
- `ReadAlias` on an unknown alias returns `/`, not an error.
- `PropertiesChanged` must be emitted whenever `Collections` (Service) or
  `Items` (Collection) changes — libsecret/oo7 clients cache these
  properties and only refresh on the signal. See the
  `collections_changed`/`items_changed` calls after every mutation in
  `service.rs`/`collection.rs`/`item.rs`; a new mutating method needs the
  same treatment.
- Alias objects are served at `/org/freedesktop/secrets/aliases/<name>`
  and must stay in sync with the `aliases` redb table (register on
  `SetAlias`, unregister when cleared or when the target collection is
  deleted).
- Sessions of clients that vanish without calling `Session.Close` are
  reaped via `NameOwnerChanged` (`main.rs::reap_vanished_clients`) —
  required because most real clients never call `Close`, and a leaked
  session would otherwise pin `session_count` above zero forever and block
  idle-exit.
- Dependency policy: use the latest stable version of a crate (check with
  `cargo search`/`cargo add` rather than hand-picking an old version), and
  do not introduce experimental or nonstandard crypto backends — Sequoia
  is pinned to its `crypto-nettle` backend and session crypto uses the
  standard RustCrypto `aes`/`cbc` crates. Follow the spec's mandated
  algorithms exactly rather than substituting something "better."

## Test Pitfalls Learned

- **`pgrep`/`pkill -f` can match themselves.** A pattern like
  `--store-dir <path>` in a `pkill -f` invocation will also match the
  shell command line running that very `pkill`/reaper script. Use a
  character-class trick to break the match, e.g. `'[-]-store-dir <path>'`
  (see the reaper script in `tests/integration.rs::Harness::init`).
- **Cargo/process exit codes get masked by pipes.** Don't pipe
  `cargo test`/the daemon's output through `grep`/`head` etc. and assume
  `$?` reflects cargo's exit code — check `ExitStatus` directly (see
  `wait_with_timeout` in `tests/integration.rs`), and prefer `assert!` on
  the status rather than trusting a piped shell's `$?`.
- **Use `CARGO_BIN_EXE_noirpass` (via `env!("CARGO_BIN_EXE_noirpass")`), not
  a manually built path**, to spawn the daemon binary from integration
  tests — this is the binary `cargo llvm-cov` has instrumented, and its
  coverage is only collected if it's stopped gracefully (`SIGTERM`, not
  `SIGKILL`) so its profile data flushes before the test process exits.
- **Environment variables are process-global in Rust test binaries.**
  `tests/integration.rs` sets `DBUS_SESSION_BUS_ADDRESS`/`GNUPGHOME` once,
  inside a `OnceLock` initializer, before any test creates a connection —
  and then runs every scenario that depends on them sequentially inside
  one orchestrator test (`end_to_end`) rather than as separate `#[test]`
  functions, since Rust's test harness runs tests concurrently by default
  and per-test env vars are not isolated between threads.
