# AI Agent Guide

Repository-wide coding-agent rules. Current checkout is source of truth. Make smallest correct
change, preserve security properties, and read the nearest scoped guidance before editing.

## Scope

Root rules. Read nearest `AGENTS.md` for narrower ownership guidance.

- `src/cli/AGENTS.md`: CLI entrypoints, commands, confirmation, and daemon orchestration
- `src/config/AGENTS.md`: configuration, initialization, recipient lifecycle, and deinitialization
- `src/crypto/AGENTS.md`: Secret Service transport cryptography and secret-memory handling
- `src/gpg/AGENTS.md`: OpenPGP encryption, certificate validation, and GPG-agent integration
- `src/service/AGENTS.md`: Secret Service D-Bus API, sessions, objects, signals, and lifecycle
- `src/store/AGENTS.md`: redb persistence, ciphertext storage, durability, recovery, and integrity
- `systemd/AGENTS.md`: systemd user service, D-Bus activation, filesystem access, and sandbox hardening
- `tests/AGENTS.md`: hermetic tests and production-isolation requirements

Subsystem Rust files now live under their owning directories above. Keep new files within the
nearest ownership boundary; do not duplicate guidance into child files.

## Product Scope

Noirpass is a simple, fast, secure persistent freedesktop Secret Service backend, not a
password-manager or wallet-management product. Standard Secret Service D-Bus compatibility—including
collections, aliases, sessions, item properties, and required signals—is core scope.

The user-facing CLI is maintenance and lifecycle only: `init`, `deinit`, `status`, `list`, `delete`,
and `check`. Secret editing/reveal, collection or alias management, recipient migration,
re-encryption, import/export, backup management, sync, accounts, profiles, lock managers, prompts,
UI, ACLs, plugins, and networking are out of scope.

Rust module paths and internal Store APIs are implementation details unless explicitly documented
otherwise. Do not add manager functionality unless required for standard Secret Service compatibility
or core secret safety/persistence.

## Read First

Before editing:

1. Read affected module-level `//!` documentation.
2. Read the nearest scoped `AGENTS.md` files for every touched boundary.
3. Trace the complete call, persistence, and error flow.
4. Inspect existing tests for intended behavior and isolation.

README is user-facing documentation. Scoped `AGENTS.md` files own subsystem contracts and invariants;
module docs own local rationale. Do not invent a second central design document.

## Environment and Validation

Run Rust tooling through the flake development shell first:

```sh
nix develop -c cargo <subcommand> ...
```

Use direct `cargo` only when `nix` is unavailable (`command not found`, exit 127). For other Nix
failures, fix or report the failure; do not silently bypass the environment.

Required gates:

```sh
nix develop -c cargo build --release
nix develop -c cargo fmt --check
nix develop -c cargo clippy --all-targets -- -D warnings
nix develop -c cargo test
nix develop -c cargo llvm-cov --all-targets --fail-under-lines 80
git diff --check
```

Claim a gate only from observed command output. Optional real-desktop smoke tests remain feature-
gated and must skip safely when unavailable. Mandatory tests must follow [`tests/AGENTS.md`](tests/AGENTS.md).

## Nix Packaging

- `flake.nix` owns package, app, checks, and development-shell outputs for supported systems.
- Package version follows `Cargo.toml`; do not duplicate or manually drift the release version in the
  flake.
- Package checks and formatting checks remain hermetic and use repository-owned dependencies and test
  fixtures rather than ambient user services, stores, or keyrings.
- Packaged activation and systemd service files must be installed and must reference the packaged
  Noirpass binary, not `/usr/bin/noirpass` from the source templates.

## Global Change Rules

- Fix root cause with the smallest focused diff; reuse existing dependencies and patterns.
- Preserve public D-Bus behavior and on-disk compatibility unless the task explicitly changes the
  contract and includes migration/recovery coverage.
- Add regression coverage for non-trivial behavior. Do not bump dependencies or modify `Cargo.lock`
  without a concrete purpose.
- Never log secret bytes, expose plaintext outside controlled zeroizing storage, or move private
  OpenPGP key material across the agent boundary.
- Never spawn `gpg`, `gpg2`, `gpgconf`, or a shell in production daemon/startup paths. Test fixtures
  may spawn GPG tools only inside exact temporary homes.
- Do not weaken fail-closed validation, destructive confirmation, path/symlink protection, store
  durability, session ownership, or test isolation to make a test pass.
- Do not commit changes or create branches unless explicitly requested.
