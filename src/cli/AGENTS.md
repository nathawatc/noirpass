# CLI Ownership

Own CLI entrypoints and runtime orchestration under `src/cli/`, with `src/main.rs` limited to
process entry.

CLI scope is maintenance and lifecycle only: `init`, `deinit`, `status`, `list`, `delete`, and `check`.
Do not add manager workflows or hidden runtime/testing overrides. The daemon always claims the fixed
`org.freedesktop.secrets` name; test isolation belongs to the private-bus fixtures.

## Command and Output Contracts

- Own `init`, `status`, `list`, `delete`, `check`, and `deinit` parsing, dispatch, exit status, and
  user-visible stdout/stderr.
- `--store-dir` selects state first; otherwise use `NOIRPASS_STORE`, then
  `$XDG_DATA_HOME/noirpass`, then `~/.local/share/noirpass`.
- Pass explicit store paths through all maintenance and test subprocesses. Do not silently fall back
  to a default path after an explicit path is supplied.
- `status` validates configuration, recipient certificate identity/usability, store health, and
  GPG-agent secret-key availability; unusable state exits nonzero.
- `list` reads metadata without decrypting values and reports missing ciphertext. `delete` removes
  one indexed item only after its command's terminal confirmation, unless `--yes` is supplied.
- `check` reports integrity findings and applies only its explicitly confirmed or `--yes` repairs.
  `deinit` is intentionally different: it has no `--yes` or automation bypass.

## Initialization and Maintenance

- `init` must acquire redb ownership before creating lifecycle state for a complete existing store,
  then acquire lifecycle exclusivity and revalidate whether the selected store is fresh or
  existing. Fresh/incomplete state acquires lifecycle exclusivity first, then revalidates before
  creating the store. The persistent `.noirpass-lifecycle.lock` file is normal; kernel fd
  ownership, not file existence, holds the lock, and process exit releases it. Never rely on
  `Store::open` as a probe: it creates `index.redb`. Config-layer preflight rejects configured
  recipient state with a missing index, so `init` cannot rebuild a new empty database around old
  ciphertext. Fresh-store and recipient-lifecycle rules belong to
  [`../config/AGENTS.md`](../config/AGENTS.md).
- For an existing index, run store health validation before configuration writes. After successful
  configuration, open the store, ensure the default collection, and report the selected directory
  and recipient fingerprint.
- `deinit` removes only recognized Noirpass state after both confirmations. It must never invoke
  itself from `init`, change recipient implicitly, or delete unknown files. Store path and symlink
  safety remain enforced by the config/store layers. After pure preflight, it acquires the same
  lifecycle exclusivity before removing recognized temporary files; existing indexes acquire redb
  ownership first, even without `secrets/`, so busy-store rejection cannot create a new lifecycle path.

Complete existing-store lifecycle operations use `Store`/redb → lifecycle-lock ordering. Fresh
initialization, with no existing Store to claim, uses lifecycle-lock → newly created Store ordering.

Lifecycle exclusivity serializes `init`/`deinit` persistence only. It is unrelated to Secret Service
`Item.Locked` and `Collection.Locked`; Noirpass still exposes both properties as `false`.

## Destructive Confirmation

`deinit` fails closed:

```text
interactive TTY required
→ confirmation #1
→ confirmation #2
→ only then destructive work
```

No piped input, environment variable, hidden option, force flag, or `--yes` may bypass either
confirmation. CLI tests must cover declined, EOF, non-TTY, and `deinit --yes` rejection cases.

## Daemon Startup and Shutdown

Startup order is observable security behavior:

1. Load/validate config and recipient.
2. Probe the existing index without creating a replacement.
3. Open the existing store without creating an index, reload/validate config and recipient under
   redb ownership, then recover the store. Preflight data must not outlive a concurrent refresh.
4. Require `ensure_safe_to_serve` before bootstrapping the default collection.
5. Bootstrap the default collection.
6. Verify recipient secret-key access through the GPG-agent boundary.
7. Build/register the complete Secret Service object tree.
8. Complete the client `NameOwnerChanged` subscription; failure aborts startup.
9. Claim `org.freedesktop.secrets` only after registration and subscription complete.

The daemon must honor D-Bus/systemd activation assumptions in `systemd/`; do not claim the
well-known name before persisted collections, items, and aliases are registered. SIGINT and SIGTERM
release the name and terminate gracefully. Idle shutdown is allowed only when configured inactivity
has elapsed, there are no sessions or temporary items, and no Noirpass application handler is
active; new application calls fail once shutdown admission closes. Service-layer synchronization
details belong to [`../service/AGENTS.md`](../service/AGENTS.md).

## Boundaries

- Configuration state machine and atomic config/certificate writes: [`../config/AGENTS.md`](../config/AGENTS.md).
- OpenPGP and agent operations: [`../gpg/AGENTS.md`](../gpg/AGENTS.md).
- D-Bus object/session lifecycle: [`../service/AGENTS.md`](../service/AGENTS.md).
- redb/filesystem durability and repair: [`../store/AGENTS.md`](../store/AGENTS.md).
- CLI fixtures and production-concurrency isolation: [`../../tests/AGENTS.md`](../../tests/AGENTS.md).
