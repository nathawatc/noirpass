# Configuration Ownership

Own configuration parsing, initialization, recipient persistence, recipient lifecycle, and config-
layer deinitialization state under `src/config/`.

## Persisted Configuration

- `config.toml` is versioned. Current version is `1` and contains `recipient_fingerprint`, the
  store-relative `recipient_cert` path, and optional `idle_exit`.
- Missing `idle_exit` uses `300`; valid values are `-1` or greater. `-1` disables idle exit, `0`
  exits after observed application activity completes with no sessions, and positive values are
  inactivity seconds. Command-line `--idle-exit` takes precedence at daemon startup.
- Recipient paths must be relative, non-empty, and contain only normal path components. Never allow
  traversal, absolute paths, or symlink following through configuration.
- Config and recipient certificate writes are atomic and durable. If config persistence fails after
  a certificate replacement, restore the previous certificate; do not leave a partially refreshed
  recipient state.

## Recipient Identity and Lifecycle

```text
recipient identity = primary OpenPGP fingerprint
```

- Parse the supplied certificate and require a usable encryption-capable key before writing.
- A same-primary certificate refresh is allowed only for a complete initialized store with an
  existing metadata database. It may preserve the configured `idle_exit` value.
- A different primary fingerprint is rejected before any write and tells the user to run explicit
  `noirpass deinit` before initializing a new recipient. `init` never migrates, re-encrypts, deletes,
  or implicitly invokes `deinit`.
- A configured recipient state (`config.toml` or the stored recipient certificate) with missing
  `index.redb` is an incomplete initialized store. `init` must fail closed before certificate/config
  writes, must not create a replacement index, and must not delete ciphertext. The user must resolve
  it explicitly through the destructive lifecycle path.
- Keep config/certificate contents unchanged on all rejected lifecycle paths, including corrupt
  config, missing metadata, different-primary input, and failed writes.
- `init` and `deinit` acquire shared lifecycle exclusivity before config, certificate, recognized
  temporary-file, or destructive store mutation. For complete existing stores, they first acquire
  Store/redb ownership so a busy-store rejection cannot create `.noirpass-lifecycle.lock`; they
  then acquire lifecycle ownership and revalidate state. Fresh/incomplete init acquires lifecycle
  ownership first, then revalidates before creating Store state. The guard holds a kernel fd lock on
  persistent `.noirpass-lifecycle.lock`; file existence is not ownership, and process exit releases
  ownership automatically. Existing store-directory and lock-file modes normalize only after flock;
  an absent store directory is created recursively with `0700` before lock-file creation. This
  consistent Store/redb → lifecycle-lock order avoids cycles among complete-store lifecycle
  commands. This lifecycle guard is separate from Secret Service Item/Collection lock state, which
  remains always unlocked.

## Fresh Versus Incomplete State

Initialization must distinguish state instead of guessing:

- No config, no stored recipient, no index, and no possible Noirpass ciphertext is truly fresh; allow
  initialization.
- An empty or unrelated-only `secrets/` directory (for example `secrets/keep.txt`) is not by itself
  Noirpass state; preserve it and allow fresh initialization.
- A possible `.gpg` file without configuration/index is ambiguous ciphertext; reject it fail-closed
  and preserve it.
- A symlinked `secrets` path or symlinked possible ciphertext is rejected without following or
  modifying the target.
- Any existing configured recipient state without `index.redb` is incomplete even when no ciphertext
  is currently visible; never normalize it into a new empty store.

The CLI opens/creates the index only after this preflight succeeds. Store transaction and recovery
invariants belong to [`../store/AGENTS.md`](../store/AGENTS.md).

## Status and Deinitialization Boundary

`status` is read-only and reports config validity, recipient presence, fingerprint equality, key
usability, and store health. Config-layer deinitialization removes only recognized paths inside the
selected store, refuses unsafe symlinks, preserves unknown files, and leaves the CLI's mandatory
interactive confirmation policy to [`../cli/AGENTS.md`](../cli/AGENTS.md).

OpenPGP certificate parsing and usable-key semantics belong to [`../gpg/AGENTS.md`](../gpg/AGENTS.md);
this file owns how the primary fingerprint controls lifecycle decisions.
