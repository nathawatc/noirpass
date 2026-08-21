# Store Ownership

Own `redb` metadata, ciphertext files, durability, recovery, integrity checks, aliases persisted in
store, and poisoned-store behavior under `src/store/`.

Store is a persistence implementation boundary, not a password-manager feature API. Keep Rust Store
methods at smallest visibility required by production callers and in-crate tests; do not add public
methods solely for integration-test convenience.

## Storage Model and Path Safety

The selected store is structured as:

```text
noirpass/
├── config.toml
├── index.redb
├── keys/recipient.pgp
└── secrets/<canonical-item-id>.gpg
```

- Store, `keys`, and `secrets` directories are `0700`; config, recipient certificate, temporary
  state, and ciphertext files are `0600` where the layer creates them.
- `index.redb` holds collection records, item metadata, and aliases. Searchable metadata is
  intentionally plaintext within the protected store directory; secret values never enter redb or
  the Store API.
- Table keys are authoritative identity. Embedded record IDs must match their keys. Validate
  canonical collection/item IDs before constructing filesystem paths; never permit traversal,
  inferred paths, or symlink following.
- Default collection and alias are `default`; generated item/collection IDs are 16 random bytes
  rendered as 32 lowercase hexadecimal characters.

## Transaction and Filesystem Durability

- Keep redb transactions short and coordinate multi-step readers/writers through the existing
  `transaction_gate`.
- Ciphertext replacement/deletion uses private temporary or backup files, restrictive modes,
  ordered rename, file sync, parent-directory sync, rollback, and recognized recovery artifacts.
  Define crash states before changing file/database ordering.
- Preserve the three persistence outcomes:

```text
definitely failed
→ definitely committed
→ commit state uncertain
```

A commit whose outcome is uncertain poisons the Store. Every later operation must fail closed; do not
continue serving or invent a metadata result from an uncertain database state.

## Recognized Recovery Artifacts

Store recovery, deinitialization, and integrity maintenance may recognize only these artifact
families, with the implementation's canonical item-id/token validation and proven ownership/state:

```text
.noirpass-create-...
.noirpass-update-...
.noirpass-quarantine-...
.noirpass-backup-...
```

Recognized artifacts may be recovered, retained, or removed only according to their proven transaction
state and the owning store operation. Unknown or unrecognized artifacts—including lookalikes with
invalid IDs/tokens—remain conservative and must not be deleted by guesswork. Orphan, ambiguous, or
ownership-unproven files stay reported and retained.

## Integrity and Repair Policy

`check_integrity` covers corrupt/mismatched collections, malformed or mismatched item records, missing
ciphertext, digest mismatch, invalid collection ownership, corrupt aliases, orphan ciphertext, and
recognized recovery files.

- For canonical item metadata whose authoritative redb key is valid but whose record is malformed or
  invalid, `check` treats the item as corrupt as a whole. After confirmation—or with `check --yes`—it
  may delete metadata and the associated canonical ciphertext. It does not reconstruct metadata from
  ciphertext.
- For a non-canonical item key, repair is metadata-only; never use an invalid key to infer a
  ciphertext path.
- Unknown, unowned, orphan, non-canonical, ambiguous, or transaction-state-unproven artifacts remain
  reported and retained. Do not guess ownership or delete unrelated ciphertext.
- `ensure_safe_to_serve` blocks daemon startup when integrity defects could expose inconsistent
  objects or values. Preserve that admission boundary.

On-disk compatibility and recovery behavior must remain stable unless an explicit migration/design
change defines both. Store tests use unique fixture roots and verify unrelated-file preservation,
symlink safety, recovery ordering, repair confirmation, and uncertain-state poisoning.

CLI command confirmation and process-exclusivity orchestration belong to
[`../cli/AGENTS.md`](../cli/AGENTS.md); test resource isolation belongs to
[`../../tests/AGENTS.md`](../../tests/AGENTS.md).
