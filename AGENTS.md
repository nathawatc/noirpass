# AI Agent Guide

Coding-agent repository instructions. Minimize changes, preserve security properties, use
`ARCHITECTURE.md` as technical source of truth.

## Read First

Before editing:

1. Read affected module-level `//!` documentation.
2. Read relevant sections in `ARCHITECTURE.md`.
3. Trace complete call and persistence flow.
4. Inspect existing tests for intended behavior.

Update `ARCHITECTURE.md` when implementation contracts, storage format, object lifecycle, security
boundaries, or test strategy change. Update `README.md` only for user-visible setup, commands,
behavior, or troubleshooting.

## Environment

Run Rust tooling through flake dev shell first:

```sh
nix develop -c cargo <subcommand> ...
```

Use direct `cargo` only when `nix` unavailable (`command not found`, exit 127). For other Nix
failures, fix or report; never bypass environment.

Never test against real session bus or real GnuPG home. Integration harness provides private
`dbus-daemon`, ephemeral `GNUPGHOME`, and temporary store.

## Required Gates

Run change-relevant checks, then full gates before completion:

```sh
nix develop -c cargo build --release
nix develop -c cargo fmt --check
nix develop -c cargo clippy --all-targets -- -D warnings
nix develop -c cargo test
nix develop -c cargo llvm-cov --all-targets --fail-under-lines 80
```

Optional real-client smoke test:

```sh
nix develop -c cargo test --features secret-tool-smoke
```

All gates must pass with zero warnings. Claim pass only with command output.

## Change Rules

- Fix root cause. Smallest correct diff.
- Reuse existing patterns and dependencies.
- Preserve public D-Bus compatibility and on-disk compatibility unless task explicitly changes them.
- Add regression coverage for non-trivial behavior changes.
- Never log secret bytes or move plaintext outside `Zeroizing` buffers.
- Never spawn `gpg` in daemon/startup paths. Only hermetic test fixtures may spawn it.
- Never substitute cryptographic algorithms or backends. Follow Secret Service specification and
  dependency policy in `ARCHITECTURE.md`.
- Keep object-server registration, persistent state, aliases, and emitted property signals
  synchronized.
- Treat uncertain persistence commit as poisoned store; stop serving and writing.
- Never repair corruption destructively without explicit, evidence-based policy.

## Test Safety

- Use `CARGO_BIN_EXE_noirpass` for daemon spawned by integration tests.
- Stop instrumented daemon with SIGTERM, not SIGKILL, ensuring coverage flushes.
- Serialize tests using process-global `DBUS_SESSION_BUS_ADDRESS` or `GNUPGHOME` in shared harness.
- Never pipe process output to infer status. Assert actual `ExitStatus`.
- `pgrep`/`pkill -f` patterns can match caller. Break option pattern, e.g. `'[-]-store-dir <path>'`.

## Documentation Ownership

- `README.md`: user guidance only. No implementation internals or contributor workflow.
- `AGENTS.md`: AI workflow, constraints, commands, and safety rules.
- `ARCHITECTURE.md`: design, internals, invariants, persistence protocol, implementation guidance,
  and test architecture.
