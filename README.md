# Noirpass

Password manager daemon that speaks standard `org.freedesktop.secrets`.
Secrets stored as GPG-encrypted files. Unlock via `gpg-agent`.
A minimal, on-demand implementation of the freedesktop [Secret Service][spec]
D-Bus API (`org.freedesktop.secrets`), backed by OpenPGP instead of a
keyring's own crypto. Each secret is a single GPG-encrypted file; unlocking
is delegated entirely to `gpg-agent`, so noirpass behaves like `pass` wearing
a D-Bus API — same pinentry prompts, same passphrase caching, same trust
model.

[spec]: https://specifications.freedesktop.org/secret-service-spec/latest/

Features:

- Drop-in replacement for `org.freedesktop.secrets` — works with any
  libsecret or [oo7](https://crates.io/crates/oo7) client (`secret-tool`,
  browsers, password managers) without modification.
- Secrets are encrypted at rest to your own OpenPGP key; no separate
  keyring master password.
- No `gpg` subprocess at daemon startup/runtime: import an exported public
  recipient cert once with `noirpass init`, then encryption happens
  in-process (Sequoia) and decryption goes through your already-running
  `gpg-agent`.
- On-demand: starts on D-Bus activation, exits after an idle timeout.
  Nothing runs when you aren't using it.
- Both Secret Service session transports (`plain` and the encrypted
  Diffie-Hellman mode) are implemented, matching what real clients use.

## How It Works

```text
~/.local/share/noirpass/
├── config.toml         # selected recipient fingerprint and cert path
├── index.redb          # collections, item labels & attributes, aliases
├── keys/
│   └── recipient.pgp   # binary OpenPGP public recipient certificate
└── secrets/
    ├── <item-id>.gpg    # one OpenPGP-encrypted file per secret value
    └── ...
```

- **Metadata index** (`index.redb`, a [redb](https://github.com/cberner/redb)
  single-file database): collection records, item labels and lookup
  attributes, and alias mappings. This is what `SearchItems` scans. It is
  **not encrypted** — see Security notes below.
- **Secret values** (`secrets/<item-id>.gpg`): each secret is its own
  OpenPGP message, encrypted to every valid encryption subkey of your
  certificate. The store never sees plaintext; it only ever writes and
  reads ciphertext bytes.
- **Recipient config** (`config.toml` plus `keys/recipient.pgp`): `noirpass
  init` stores the exported public certificate and its primary fingerprint.
  The daemon loads this copy directly; it does not list keys or export
  certificates from GnuPG.
- **The store directory** and the `secrets/` subdirectory are created mode
  `0700`; each `.gpg` file is written mode `0600`.
- **Trust model**: encrypting is a local, keyless operation (only the
  public certificate is needed). Decrypting requires `gpg-agent` to unlock
  your secret key, which means it inherits whatever policy you already
  have configured there — passphrase caching timeout, pinentry program,
  hardware token, etc. noirpass itself never holds your private key
  material and never implements its own lock/unlock logic; `gpg-agent` is
  the real gate.

## Nix

Flake supports `x86_64-linux` and `aarch64-linux`. Build, run, enter development
shell, or execute sandboxed checks directly:

```sh
nix build
./result/bin/noirpass --help

nix run . -- --help
nix develop
nix flake check
```

Install package into current user profile from checkout:

```sh
nix profile install .#noirpass
```

Install directly from Codeberg:

```sh
nix profile install git+https://codeberg.org/koharu/noirpass.git#noirpass
```

Package includes D-Bus activation and systemd user service files with
store-qualified executable paths. Run `systemctl --user daemon-reload` after
profile installation; do not enable service because D-Bus starts it on demand.
See [NixOS Flake Guide](docs/NIXOS-FLAKE.md) for setup and Secret Service
conflict handling.

## Build without Nix

Install Rust 1.85 or newer plus GnuPG, OpenSSL, Clang, Cap'n Proto, and
`pkg-config`, then run:

```sh
cargo build --release
```

Resulting binary is `target/release/noirpass`. Shipped activation files expect
`/usr/bin/noirpass`; adjust both files when installing elsewhere.

## Initialize and use

Initialize once with full fingerprint of existing GPG key:

```sh
gpg --armor --export <FINGERPRINT> | noirpass init --recipient -
noirpass status
```

Any Secret Service client works unmodified. Using `secret-tool`:

```sh
secret-tool store --label='My login' service myservice username myuser
secret-tool lookup service myservice username myuser
```

First call activates daemon. `gpg-agent` handles pinentry and passphrase cache.
Only one process can own `org.freedesktop.secrets`; disable any competing
Secret Service provider before using noirpass.

## Configuration Reference

| Flag | Env var | Default | Description |
| --- | --- | --- | --- |
| `--store-dir <path>` | `NOIRPASS_STORE` | `$XDG_DATA_HOME/noirpass` (falls back to `~/.local/share/noirpass`) | Directory holding `config.toml`, `keys/`, `index.redb`, and `secrets/`. |
| `--idle-exit <secs>` | — | `300` | Exit after this many seconds with no D-Bus activity *and* no open sessions. `0` disables idle-exit. |

Commands:

```sh
noirpass init --recipient <FILE|->
noirpass status
```

`--bus-name` also exists but is hidden from `--help`; it lets tests point
the daemon at a non-default well-known name and is not meant for normal use.

## Security Notes

- **Item labels and attributes are stored in plaintext** in `index.redb`.
  This is a deliberate trade-off for making `SearchItems` a fast local
  lookup instead of requiring a decrypt per candidate. If your attribute
  values or labels are themselves sensitive (not just the secret value),
  be aware they are readable by anything that can read your store
  directory, without needing `gpg-agent` at all. Only the secret *value*
  of each item is encrypted.
- **Secret values only ever exist as plaintext in memory**, held in
  `zeroize::Zeroizing` buffers that are wiped when dropped. They are never
  written to disk unencrypted and never logged.
- **On the wire**, a Secret Service session negotiates its own transport
  encryption independent of at-rest encryption: `plain` (no transport
  encryption, relies on the D-Bus socket's own protection) or
  `dh-ietf1024-sha256-aes128-cbc-pkcs7` (Diffie-Hellman over the 1024-bit
  MODP group → HKDF-SHA256 → AES-128-CBC/PKCS7), matching what real
  clients negotiate. Session keys are zeroized on drop, and sessions of
  clients that disconnect without calling `Close` are cleaned up when
  D-Bus reports the client's unique name has no owner.
- **The shipped systemd unit is hardened**: `NoNewPrivileges`,
  `ProtectSystem=strict`, `ProtectHome=read-only` with an explicit
  `ReadWritePaths` exception for the XDG data directory parent, `PrivateTmp`,
  `MemoryDenyWriteExecute`, `RestrictRealtime`, `RestrictNamespaces`,
  `LockPersonality`, `ProtectKernelTunables`, `ProtectKernelModules`,
  `ProtectControlGroups`, `RestrictAddressFamilies=AF_UNIX`, an
  `@system-service` syscall filter, and an empty
  `CapabilityBoundingSet`.

## Development

Development shell provides Rust toolchain, coverage tools, and native test
dependencies. Run all repository gates through flake:

```sh
nix develop -c cargo fmt --check
nix develop -c cargo clippy --all-targets --all-features -- -D warnings
nix develop -c cargo test
nix develop -c cargo llvm-cov --all-targets --fail-under-lines 80
```

Optional real `secret-tool` smoke test remains feature-gated:

```sh
nix develop -c cargo test --features secret-tool-smoke
```
