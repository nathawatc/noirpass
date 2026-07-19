# Noirpass Architecture

Technical source of truth: design, security boundaries, persistence, D-Bus behavior, implementation
guidance. User instructions: `README.md`; agent workflow: `AGENTS.md`.

## System Purpose

Noirpass implements `org.freedesktop.secrets` on Linux session D-Bus. Searchable metadata lives in
redb. Each secret value independently OpenPGP-encrypted to configured recipient certificate.
In-process Sequoia encrypts; running `gpg-agent` handles private-key decryption operations.

D-Bus-activated daemon serves one shared store; exits after inactivity only with no sessions.

## Component Map

| File                   | Responsibility                                                                                                                                            |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/lib.rs`           | Crate modules and shared `Error`/`Result` exports.                                                                                                        |
| `src/main.rs`          | CLI, setup/maintenance commands, startup validation, D-Bus connection, object registration, name ownership, vanished-client reaper, idle/signal shutdown. |
| `src/config.rs`        | Versioned config, recipient import/load/status, path validation, atomic durable writes, unsafe rotation prevention.                                       |
| `src/gpg.rs`           | Recipient validation, in-process OpenPGP encryption, `gpg-agent` decryption and secret-key availability checks.                                           |
| `src/store.rs`         | redb metadata, ciphertext files, transactional mutation, recovery, integrity reporting, poisoned-store handling.                                          |
| `src/service.rs`       | Shared state, Service interface, session ownership, object-path helpers, registration coordination.                                                       |
| `src/collection.rs`    | Collection interface for canonical and alias-backed paths.                                                                                                |
| `src/item.rs`          | Item properties, secret transport conversion, update, and deletion.                                                                                       |
| `src/session.rs`       | Session object and Secret Service wire structure.                                                                                                         |
| `src/crypto.rs`        | Pure session transport handshake and encryption.                                                                                                          |
| `src/error.rs`         | Internal error taxonomy and D-Bus error mapping.                                                                                                          |
| `tests/integration.rs` | Real binary, private bus, ephemeral GnuPG key, oo7/libsecret flows, restart and lifecycle scenarios.                                                      |
| `systemd/*`            | User service and D-Bus activation definitions.                                                                                                            |

Module-level `//!` comments document local rationale; keep synchronized with this document.

## Runtime Flow

1. Parse CLI and select store directory.
2. For daemon mode, load and validate config plus recipient certificate.
3. Probe store health, open redb, recover interrupted operations, ensure default collection, and
   reject unsafe store state.
4. Verify matching encryption-capable secret key is available through `gpg-agent`.
5. Build session-bus connection with Service object.
6. Register all persisted collection, item, and alias objects.
7. Start vanished-client session reaper.
8. Claim `org.freedesktop.secrets` only after object tree is complete.
9. Serve until SIGINT/SIGTERM or idle timeout with zero sessions.
10. Release well-known name and drop connection cleanly.

Claim bus name last; prevent activated clients observing partially populated object tree.

## Storage Model

Default root: `$XDG_DATA_HOME/noirpass`; fallback: `~/.local/share/noirpass`.

```text
noirpass/
├── config.toml
├── index.redb
├── keys/
│   └── recipient.pgp
└── secrets/
    └── <item-id>.gpg
```

- Store, `keys`, and `secrets` directories: mode `0700`.
- Config, recipient certificate, and ciphertext files: mode `0600`.
- `config.toml`: format version, expected primary fingerprint, store-relative certificate path.
- `index.redb`: collection records, item metadata, aliases.
- Item metadata: id, collection id, label, attributes, content type, ciphertext SHA-256,
  created/modified timestamps.
- `secrets/<id>.gpg`: binary OpenPGP message for one item.
- Default collection id and alias: `default`.
- Generated collection/item ids: 16 random bytes encoded as 32 lowercase hex characters.

redb table key is authoritative identity. Embedded record id must match table key. Canonically
validate item ids before filename path construction.

Metadata stays plaintext, enabling Secret Service attribute search without candidate decryption.
Labels, attributes, collection names, timestamps, relationships have store-directory confidentiality,
not OpenPGP confidentiality.

## Configuration and Recipient Lifecycle

`noirpass init` accepts armored or binary public certificate from file or stdin. Initialization:

1. Parses certificate and requires current usable encryption key.
2. For non-empty store, verifies existing recipient and rejects fingerprint change.
3. Writes binary certificate atomically and durably.
4. Writes versioned config atomically and durably.
5. Restores previous certificate if config write fails.
6. Creates redb store and default collection.

Configured certificate path: relative, non-empty, only normal components; cannot escape store root.

Startup and `status` validate config version, certificate presence, configured/actual fingerprint
equality, usable encryption key, corresponding secret-key availability through `gpg-agent`.

Recipient rotation not implemented. Recipient change with ciphertext would strand old values; reject
instead of partial migration.

## Secret Boundaries

- Secret values never enter redb.
- Secret values never appear in logs or errors.
- Plaintext exists only in `zeroize::Zeroizing` buffers, only long enough to convert between session
  transport and OpenPGP.
- Session symmetric keys are zeroized on drop.
- Private OpenPGP key material remains in GnuPG/agent boundary.
- Daemon and startup paths never spawn `gpg`; they communicate with existing `gpg-agent`.
- Test support may spawn `gpg` only inside ephemeral `GNUPGHOME`.

Encryption uses every current, live, non-revoked certificate key flagged for storage or transport
encryption. Sequoia uses `crypto-openssl` backend. Decryption runs blocking Sequoia/agent work through
`spawn_blocking`.

## Persistence and Recovery

Store combines transactional metadata with filesystem ciphertext; multi-resource mutations require
explicit ordering and recovery.

Core rules:

- Every store method uses short-lived redb transaction.
- `transaction_gate` coordinates readers and multi-step writers in-process.
- Ciphertext SHA-256 in metadata identifies expected file version.
- Secret file replacement uses private temporary/backup files, restrictive modes, rename, file sync,
  and parent-directory sync.
- Startup maintenance recovers recognized interrupted-operation artifacts before serving.
- Unknown, corrupt, mismatched, or ambiguous state is reported and retained rather than guessed
  away.
- Indeterminate redb commit poisons Store. All later operations fail; daemon must not continue with
  uncertain state.
- Startup `ensure_safe_to_serve` blocks D-Bus service when integrity defects could expose
  inconsistent objects or values.

Deletion and replacement must preserve recoverability across filesystem/database commit failures.
Never split into independent “write file then update DB” operations without proving crash-state
behavior.

`check_integrity` reports:

- corrupt/mismatched collection records;
- missing ciphertext for indexed item;
- malformed/mismatched item records;
- ciphertext digest mismatch;
- item with missing/corrupt collection;
- alias targeting missing/corrupt collection;
- orphan ciphertext;
- recoverable backup/quarantine artifacts.

Offline `check` may offer stale metadata deletion where ciphertext is absent. Preserve orphan or
mismatched ciphertext; automatic ownership inference risks data loss.

## D-Bus Object Model

```text
/org/freedesktop/secrets                                  Service
/org/freedesktop/secrets/collection/<id>                  Collection
/org/freedesktop/secrets/collection/<id>/<item-id>        Item
/org/freedesktop/secrets/session/s<n>                     Session
/org/freedesktop/secrets/aliases/<name>                   Collection alias
```

One `Collection` implementation serves canonical and alias paths. Alias-backed object resolves alias
through store per call; repointing becomes immediately visible. Alias names invalid as D-Bus path
elements remain storable/readable through alias methods but lack served alias object.

Noirpass logically always unlocked. `Locked` is false; `Lock` and `Unlock` complete immediately;
actual access gate is `gpg-agent`.

No Prompt objects. Any prompt out-argument is root path `/`. Unknown alias from `ReadAlias` also
returns `/`.

## Object Lifecycle and Signals

Change persistent state and object server as one serialized lifecycle operation.
`ServiceState::object_lifecycle` prevents registration/removal interleaving around mutations.

Required synchronization:

- Register collection and item objects when created.
- Remove item object when deleted.
- Remove collection plus contained item objects when collection deleted.
- Register alias object on `SetAlias` when alias has valid object path.
- Remove alias object when alias cleared or target collection deleted.
- Alias registration state must match redb alias table.
- Register complete persisted tree before claiming service name.

Emit `PropertiesChanged` whenever cached aggregate properties change:

- Service `Collections` after collection create/delete.
- Collection `Items` after item create/delete.

Clients cache these properties; may never refresh without signal.

Every D-Bus method and property handler must call `state.touch()` before other work. Handler lacking
touch is invisible to idle tracking.

Session access owner-bound. Sender unique bus name must match session-opening owner. Session and
object registration/removal must remain daemon-atomic. `NameOwnerChanged` reaps all vanished-client
sessions because many clients omit `Session.Close`.

## Session Transport

Supported algorithms match Secret Service specification:

- `plain`: no additional transport encryption; relies on D-Bus socket protections.
- `dh-ietf1024-sha256-aes128-cbc-pkcs7`: RFC 2409 1024-bit MODP group, fixed-width 128-byte
  public/shared values, HKDF-SHA256 with no salt and empty info, AES-128-CBC with PKCS#7 padding.

DH peer public value requires valid size and range. Follow mandated wire algorithm exactly; no modern
replacement because interoperability depends on identifier and format.

At-rest OpenPGP and D-Bus session transport are independent layers.

## Idle and Shutdown

Every D-Bus handler updates activity clock. Idle exit requires both:

- elapsed inactivity reaches configured threshold;
- session table is empty.

Timeout `0` disables idle exit. Vanished-client reaping prevents leaked sessions pinning daemon
forever. SIGINT/SIGTERM trigger graceful name release and process exit.

## CLI Maintenance Contracts

- `init`: imports recipient; probes existing store before modifying initialized data.
- `status`: validates config, certificate, recipient key, and `gpg-agent` secret-key access; exits
  nonzero when unusable.
- `list`: reads metadata only and marks missing ciphertext.
- `delete`: removes one indexed item and ciphertext after terminal confirmation unless `--yes`.
- `check`: reports all integrity categories; repairs only approved stale metadata; exits nonzero
  while unresolved findings remain.

Maintenance commands open existing redb store and recover interrupted operations. Stop daemon first;
redb writer access is process-exclusive. Non-interactive destructive operation requires `--yes`.

## Systemd and Activation

D-Bus activation file maps `org.freedesktop.secrets` to `noirpass.service`. Unit uses `Type=dbus`,
matching `BusName`, restart-on-failure.

Hardening: `NoNewPrivileges`, strict system protection, read-only home with explicit writable data
parent, private temporary directory, W^X protection, namespace/kernel/control-group restrictions,
`AF_UNIX` only, system-service syscall filter, empty capability set.

Default unit assumes store under `%h/.local/share` and binary at `/usr/bin/noirpass`. Configurable
store path changes may require matching `ReadWritePaths` update.

## Implementation Guidelines

### D-Bus Changes

1. Touch activity first.
2. Validate sender/session ownership where secret transport is involved.
3. Hold object lifecycle guard across persistent/object-server transition.
4. Keep aliases and object registration synchronized.
5. Emit required aggregate property signal after mutation.
6. Return `/` for no-prompt results and unknown aliases.
7. Add integration coverage through real object server/client path.

### Storage Changes

1. Treat redb key as authority; validate identifiers before filesystem use.
2. Keep plaintext out of Store API.
3. Define crash states before choosing write/rename/commit order.
4. Sync file and containing directory when durability matters.
5. Preserve recoverable artifacts until authoritative state selects version.
6. Poison on indeterminate commit.
7. Extend integrity report, recovery, startup safety check, CLI reporting, and tests together.
8. Preserve backward deserialization defaults for additive metadata fields when feasible.

### Crypto Changes

1. Follow protocol byte format exactly.
2. Validate attacker-controlled lengths/ranges before expensive arithmetic or allocation.
3. Keep private/session/plaintext material zeroized.
4. Keep blocking agent operations off async executor.
5. Use stable standard crates and existing backends; no experimental crypto.
6. Check latest stable dependency with Cargo tooling before adding/updating.

### Documentation Changes

- User-visible behavior → `README.md`.
- AI workflow or repository execution policy → `AGENTS.md`.
- Design, contracts, or implementation rationale → `ARCHITECTURE.md` and affected module docs.

## Validation Architecture

Preferred environment and gates: `AGENTS.md`.

Unit tests cover pure crypto, config validation/rollback, store transactions/recovery/integrity,
path handling, interface-local behavior. Integration tests run real Noirpass binary against private
`dbus-daemon` and ephemeral `GNUPGHOME`; exercise oo7 clients, both session transports, aliases,
persistence, signals, disconnect cleanup, startup checks, idle exit, optional `secret-tool`.

Test constraints:

- Never use ambient session bus or `~/.gnupg`.
- Spawn daemon using `CARGO_BIN_EXE_noirpass` for coverage instrumentation.
- Graceful SIGTERM required before test process exit to flush coverage.
- Environment variables are process-global; dependent scenarios remain serialized.
- Assert child `ExitStatus` directly; shell pipelines can mask failures.
- Reaper process patterns must avoid matching themselves (`'[-]-store-dir'`).
