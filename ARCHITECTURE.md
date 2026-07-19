# Architecture

## Storage Layout

```text
~/.local/share/noirpass/
├── config.toml         # recipient fingerprint and certificate path
├── index.redb          # redb DB: collections, labels, attrs, aliases (plaintext)
├── keys/
│   └── recipient.pgp   # imported public recipient certificate
└── secrets/
    └── <id>.gpg        # GPG-encrypted secret (one per item)
```

- Store dir + `secrets/`: mode `0700`. Each `.gpg`: mode `0600`.
- `SearchItems` scans plaintext index. Fast, no decrypt per hit.

### Encryption / Decryption

- Encryption in-process via Sequoia (`crypto-openssl` backend).
- Recipient cert imported once by `noirpass init` and loaded directly at startup.
- Decryption delegates PKESK unlock to running `gpg-agent` (`sequoia-gpg-agent`).
- Secret bytes never touch redb. Never logged.
- Plaintext only in `zeroize::Zeroizing` buffers. Wiped on drop.

## D-Bus Object Paths

```text
/org/freedesktop/secrets                                  Service
/org/freedesktop/secrets/collection/<id>                  Collection
/org/freedesktop/secrets/collection/<id>/<item-id>        Item
/org/freedesktop/secrets/session/s<n>                     Session
/org/freedesktop/secrets/aliases/<name>                   Collection (alias)
```

Alias-backed instances re-resolve alias on every call.
Prompts always return `/` — no real Prompt objects.

## Session Transports

Two modes per spec:

- `plain`: no transport encryption. Relies on D-Bus socket.
- `dh-ietf1024-sha256-aes128-cbc-pkcs7`: DH-1024 → HKDF-SHA256 → AES-128-CBC/PKCS7.

Session keys zeroized on drop. Sessions reaped via `NameOwnerChanged` when client disappears.

## Idle Exit

- `state.touch()` called at start of every D-Bus handler.
- Timer fires after idle period (no activity + no open sessions).
- Session count prevents exit while client holds open session.

## Systemd Hardening

Shipped unit applies: `NoNewPrivileges`, `ProtectSystem=strict`,
`ProtectHome=read-only` with `ReadWritePaths` exception for XDG data dir,
`PrivateTmp`, `MemoryDenyWriteExecute`, `RestrictRealtime`,
`RestrictNamespaces`, `LockPersonality`, `ProtectKernelTunables`,
`ProtectKernelModules`, `ProtectControlGroups`,
`RestrictAddressFamilies=AF_UNIX`, `@system-service` syscall filter,
empty `CapabilityBoundingSet`.

## Design Decisions

- **One Collection type, two paths**: `Target::Alias` re-resolves alias on each call.
  Keeps bindings live without extra sync.
- **Plaintext metadata**: required for fast `SearchItems`. Acceptable since metadata
  less sensitive than secret values.
- **No own lock/unlock**: `gpg-agent` handles everything (pinentry, passphrase caching, hardware tokens).
- **No daemon `gpg` subprocess**: encryption uses Sequoia in-process; decryption talks to `gpg-agent`.

## Offline Maintenance

- `noirpass list` lists indexed metadata without decrypting values.
- `noirpass delete <ITEM-ID>` removes one item after confirmation.
- `noirpass check` cross-checks redb item records and `.gpg` files. Missing
  ciphertext can be repaired by deleting stale metadata; orphan ciphertext is
  reported but retained to avoid destructive recovery guesses.
- Maintenance commands open redb exclusively. Stop daemon first.
