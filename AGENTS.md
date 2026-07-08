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

- `gnupg` (gpg binary, used once at startup + by gpg-agent)
- `openssl` (Sequoia crypto backend)
- `capnproto` (Sequoia IPC layer build script)
- `pkg-config`

Plus rustc ≥ 1.85 (edition 2024). Then `cargo build --release`.

## Architecture Map

| File | Role |
| --- | --- |
| `src/lib.rs` | Crate root; declares modules, re-exports `Error`/`Result`. |
| `src/main.rs` | CLI (`clap`), opens Store/Gpg, builds zbus connection, serves service object + pre-existing items (`register_existing`) before claiming well-known name, spawns `NameOwnerChanged` reaper, runs idle/signal shutdown loop. |
| `src/service.rs` | `ServiceState` (shared Store/Gpg/session table/activity clock), `org.freedesktop.Secret.Service` D-Bus object, object-path/registration helpers. |
| `src/collection.rs` | `org.freedesktop.Secret.Collection` D-Bus object. One type serves both `/collection/<id>` and `/aliases/<name>` paths via `Target::Collection` / `Target::Alias` enum. |
| `src/item.rs` | `org.freedesktop.Secret.Item` D-Bus object. |
| `src/session.rs` | `org.freedesktop.Secret.Session` (`Close` only) + `Secret` wire struct `(oayays)`. |
| `src/crypto.rs` | Session transport crypto: `DhHandshake` (1024-bit MODP DH → HKDF-SHA256 → AES-128 key), `SessionCipher` (Plain/Dh, AES-128-CBC-PKCS7). Pure sync, no I/O. |
| `src/gpg.rs` | `Gpg`: exports recipient cert via `gpg --export`, encrypts in-process with Sequoia, decrypts via `sequoia-gpg-agent`. Hosts `test_support::TestGnupg`. |
| `src/store.rs` | `Store`: redb tables (`collections`, `items`, `aliases`) + `secrets/<id>.gpg` files. Short-lived transactions; never sees plaintext. |
| `src/error.rs` | `Error` enum (`thiserror`) + mapping to `zbus::fdo::Error`. |
| `tests/integration.rs` | End-to-end scenarios (real binary, private dbus-daemon, oo7 client, secret-tool, restart persistence, signals, idle-exit) via shared `Harness`. |

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
