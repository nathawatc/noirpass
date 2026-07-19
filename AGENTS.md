# AGENTS.md

Instructions for coding agents in this repo. Terse, factual.
See module doc comments (`//!` at top of each `src/*.rs`) for full rationale.

## Environment

- NixOS. **No cargo, rustc, clippy, rustfmt, gpg on bare PATH**.
  Every command must run through flake devShell:

  ```sh
  nix develop -c cargo <subcommand> ...
  ```

  Bare `cargo ...` fails or picks wrong toolchain.

- **Never run tests against real session bus.** Ambient
  `org.freedesktop.secrets` owned by gnome-keyring. Integration tests
  create private `dbus-daemon --session` + ephemeral `GNUPGHOME`.
  Never touches `~/.gnupg` or real `DBUS_SESSION_BUS_ADDRESS`.

## Build / Test / Lint / Coverage

```sh
nix develop -c cargo build --release
nix develop -c cargo fmt --check
nix develop -c cargo clippy --all-targets -- -D warnings
nix develop -c cargo test
nix develop -c cargo llvm-cov --all-targets --fail-under-lines 80
```

All four gates must pass clean (zero warnings). `Cargo.toml` sets
`clippy::all` + `clippy::pedantic` to `warn` (allows
`module_name_repetitions`, `missing_errors_doc`, `missing_panics_doc`);
`-D warnings` on CLI turns those into hard failures. Current coverage: ~92%.

Optional smoke test with real `secret-tool`:

```sh
nix develop -c cargo test --features secret-tool-smoke
```

Integration tests need no real GPG key — generate fresh empty-passphrase
key in ephemeral `GNUPGHOME`, spawn private `dbus-daemon --session`, run
real `noirpass` binary against it. Exercises both session transports plus
`oo7` clients.

### Non-Nix Build

On generic Linux, need native deps:

- `gnupg` (`gpg-agent` runtime and test fixture tooling; daemon does not spawn `gpg`)
- `openssl` (Sequoia crypto backend)
- `capnproto` (Sequoia IPC layer build script)
- `pkg-config`

Plus rustc ≥ 1.89 for a release build (edition 2024). The locked test graph
currently requires rustc ≥ 1.92. Then `cargo build --release`.

## Architecture Map

| File | Role |
| --- | --- |
| `src/lib.rs` | Crate root; declares modules, re-exports `Error`/`Result`. |
| `src/main.rs` | CLI (`clap`), opens Store/Gpg, builds zbus connection, serves service object + pre-existing items (`register_existing`) before claiming well-known name, spawns `NameOwnerChanged` reaper, runs idle/signal shutdown loop. |
| `src/service.rs` | `ServiceState` (shared Store/Gpg/session table/activity clock), `org.freedesktop.Secret.Service` D-Bus object, object-path/registration helpers. |
| `src/collection.rs` | `org.freedesktop.Secret.Collection` D-Bus object. One type serves both `/collection/<id>` and `/aliases/<name>` paths via `Target::Collection` / `Target::Alias` enum. |
| `src/item.rs` | `org.freedesktop.Secret.Item` D-Bus object. |
| `src/session.rs` | `org.freedesktop.Secret.Session` D-Bus object (`Close` only) and the `Secret` wire struct (`(oayays)`). |
| `src/crypto.rs` | Session transport crypto: `DhHandshake` (1024-bit MODP Diffie-Hellman → HKDF-SHA256 → AES-128 key) and `SessionCipher` (`Plain` / `Dh`, AES-128-CBC-PKCS7). Pure, synchronous, no I/O. |
| `src/config.rs` | `config.toml` and `keys/recipient.pgp` import/load/status. `noirpass init --recipient <FILE|->` stores an exported public recipient certificate and fingerprint; daemon startup loads this config and fails clearly if missing/broken. |
| `src/gpg.rs` | `Gpg`: owns the configured recipient certificate, encrypts in-process with Sequoia, decrypts by delegating PKESK unlock to the running `gpg-agent` (`sequoia-gpg-agent`). Runtime/startup code must not spawn `gpg`; `test_support::TestGnupg` may spawn it only for hermetic test fixtures. |
| `src/store.rs` | `Store`: redb tables (`collections`, `items`, `aliases`) for metadata, plus `secrets/<id>.gpg` ciphertext files. Every method opens its own short-lived transaction; the store never sees plaintext. |
| `src/error.rs` | Crate-wide `Error` enum (`thiserror`) and its mapping to `zbus::fdo::Error`. |
| `tests/integration.rs` | End-to-end scenarios (real `noirpass` binary, private `dbus-daemon`, `oo7` client for both session transports, real `secret-tool`, restart persistence, signals, idle-exit) run through one shared process-wide `Harness`. |

## Invariants

- Secret bytes never touch redb. Never logged. Plaintext only in
  `zeroize::Zeroizing` buffers, held only long enough to re-encrypt
  (to session cipher or GPG recipient) or return to caller.
- Every D-Bus method handler calls `state.touch()` first. Without it,
  method invisible to idle tracking.
- Prompts always return root `/` — no real Prompt objects. Keep
  consistent for any new method with `prompt` out-arg.
- `ReadAlias` on unknown alias returns `/`, not error.
- `PropertiesChanged` emitted whenever `Collections` (Service) or
  `Items` (Collection) changes. Clients cache these, refresh only on
  signal. See `collections_changed`/`items_changed` calls after every
  mutation.
- Alias objects at `/org/freedesktop/secrets/aliases/<name>` stay in
  sync with `aliases` redb table: register on `SetAlias`, unregister on
  clear or collection delete.
- Lost sessions reaped via `NameOwnerChanged` — most clients never call
  `Close`. Leaked session pins `session_count` above zero, blocks
  idle-exit.
- Dependency policy: latest stable crates. No experimental/nonstandard
  crypto. Sequoia pinned to `crypto-openssl`. Session crypto uses
  standard RustCrypto `aes`/`cbc`. Follow spec algorithms exactly.

## Test Pitfalls

- **`pgrep`/`pkill -f` matches self.** Pattern like `--store-dir <path>`
  matches owning shell. Use character-class trick: `'[-]-store-dir <path>'`.
- **Exit codes masked by pipes.** Don't pipe cargo test output through
  grep/head and trust `$?`. Check `ExitStatus` directly via
  `wait_with_timeout` + `assert!`.
- **Use `CARGO_BIN_EXE_noirpass`** (`env!("CARGO_BIN_EXE_noirpass")`),
  not manually built path, to spawn daemon in tests. This is binary
  `cargo llvm-cov` instrumented. Stop with SIGTERM (not SIGKILL) so
  coverage data flushes.
- **Env vars process-global in Rust test binaries.**
  `DBUS_SESSION_BUS_ADDRESS`/`GNUPGHOME` set once via `OnceLock`.
  Tests depending on them run sequentially inside one orchestrator test
  (`end_to_end`) to avoid concurrent conflict.

## Object Path Scheme

```text
/org/freedesktop/secrets                                  Service
/org/freedesktop/secrets/collection/<id>                    Collection
/org/freedesktop/secrets/collection/<id>/<item-id>          Item
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
  is pinned to its `crypto-openssl` backend and session crypto uses the
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
