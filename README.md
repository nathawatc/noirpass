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

## Build

With the provided Nix flake (recommended — pins a matching toolchain and all
native dependencies):

```sh
nix develop -c cargo build --release
```

The resulting binary is at `target/release/noirpass`.

NixOS users: see [NixOS Flake Guide](docs/NIXOS-FLAKE.md) for flake setup,
per-user installation, D-Bus activation, and Secret Service conflict handling.

On a generic Linux system without Nix, install a recent Rust toolchain
(edition 2024, so rustc ≥ 1.85) plus the native dependencies the
dependency tree needs to build: GnuPG (`gnupg`, for user key management and
`gpg-agent`), OpenSSL (`openssl`, Sequoia's crypto backend), Clang
(`clang`, for OpenSSL bindgen), and `capnproto` (Sequoia's IPC layer build
script). Then:

```sh
cargo build --release
```

## Install & Activation

1. Build the binary (above) and copy it somewhere on your `PATH` that
   systemd user units can reference with an absolute path:

Drop-in for gnome-keyring Secret Service. Works with browsers,
`secret-tool`, password managers — no client changes needed.

## Features

- **Encrypted at rest** — decryptable only by your GPG key
- **On-demand** — starts when needed, exits after idle timeout
- **No master password** — uses existing GPG key and agent
- **Familiar pinentry** — same passphrase prompts as `gpg`/`pass`

## Quick Start

Service files expect binary at `/usr/bin/noirpass`. Adjust `ExecStart=` in both files if installing
elsewhere.

Build:
3. Initialize noirpass with an exported public recipient certificate:

   ```sh
   gpg --armor --export <FINGERPRINT> | noirpass init --recipient -
   # or:
   noirpass init --recipient ./recipient.asc
   noirpass status
   ```

4. Nothing needs to be started by hand. The next time any client (a
   browser, `secret-tool`, etc.) calls a method on `org.freedesktop.secrets`,
   the session D-Bus daemon activates `noirpass.service` automatically. The
   daemon exits again after `--idle-exit` seconds of inactivity with no
   open sessions, and is re-activated on the next request.

### Switching from Gnome-Keyring on NixOS

Only one process can own the `org.freedesktop.secrets` bus name at a time.
On most NixOS/GNOME setups that owner is gnome-keyring's Secret Service
component. Check who currently owns it:

```sh
nix develop -c cargo build --release
```

Install (generic Linux):

```sh
sudo cp target/release/noirpass /usr/bin/
cp systemd/noirpass.service ~/.config/systemd/user/
cp systemd/org.freedesktop.secrets.service ~/.local/share/dbus-1/services/
systemctl --user daemon-reload
```

Done. Daemon activates on first use. No manual start needed.

**NixOS**: flake provides devShell only (no package output yet). Build via devShell, copy binary
e.g. `~/.local/bin/noirpass`, then <u>edit `ExecStart=` in both service files to match</u>.

## Usage

Any Secret Service client works. With `secret-tool`:

```sh
# Store a secret
secret-tool store --label='Email password' service email user alice
Initialize once after creating/selecting your GPG key:

```sh
gpg --armor --export <FINGERPRINT> | noirpass init --recipient -
noirpass status
```

Any Secret Service client works unmodified. Using `libsecret`'s
`secret-tool`:

```sh
secret-tool store --label='My login' service myservice username myuser
# prompts for the secret value on stdin, then stores it

secret-tool lookup service myservice username myuser
# prints the secret value
```

The first call to either command activates the daemon if it isn't already
running; `gpg-agent`'s normal pinentry/passphrase-cache behavior applies on
first decrypt. Any other Secret Service client library — `oo7` (Rust),
`libsecret` (C/GLib bindings), or gnome-keyring-compatible tooling — talks
to noirpass the same way, since it implements the same D-Bus interface.

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

All commands run inside the Nix devShell, which provides a matching
rustc/cargo/clippy/rustfmt plus `cargo-llvm-cov` and every native
dependency (openssl, clang, capnproto, dbus, libsecret, gnupg, pkg-config):

# Retrieve it
secret-tool lookup service email user alice
```

First call activates daemon. `gpg-agent` handles passphrase prompts.

## Options

| Flag | Default | Purpose |
| --- | --- | --- |
| `--store-dir` | `~/.local/share/noirpass` | Data directory |
| `--key <fp>` | First secret key | GPG fingerprint for encryption |
| `--idle-exit <s>` | 300 | Idle timeout (sec). `0` = never exit |

## Security

- Secret values encrypted at rest. Only your GPG key decrypts.
- Labels and attributes stored in plaintext (needed for fast search).
- noirpass never holds your private key — `gpg-agent` handles all auth.
- Systemd service runs with restricted privileges.
