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
- **Recipient config** (`config.toml` plus `keys/recipient.pgp`): `noirpass init`
  stores the exported public certificate and its primary fingerprint.
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

On a generic Linux system without Nix, install Rust 1.89 or newer plus the
native dependencies the
dependency tree needs to build: GnuPG (`gnupg`, for user key management and
`gpg-agent`), OpenSSL (`openssl`, Sequoia's crypto backend), Clang
(`clang`, for OpenSSL bindgen), and `capnproto` (Sequoia's IPC layer build
script). The locked development/test graph currently requires Rust 1.92 or
newer. Then:

```sh
cargo build --release
```

## Install & Activation

Service files expect the binary at `/usr/bin/noirpass`. Adjust `ExecStart=` in
both files if installing elsewhere.

1. Build the release binary as described above.
2. Install the binary and service files:

   ```sh
   sudo cp target/release/noirpass /usr/bin/
   mkdir -p ~/.config/systemd/user ~/.local/share/dbus-1/services
   cp systemd/noirpass.service ~/.config/systemd/user/
   cp systemd/org.freedesktop.secrets.service ~/.local/share/dbus-1/services/
   systemctl --user daemon-reload
   ```

3. Initialize noirpass with an exported public recipient certificate:

   ```sh
   gpg --armor --export <FINGERPRINT> | noirpass init --recipient -
   # or:
   noirpass init --recipient ./recipient.asc
   noirpass status
   ```

4. Nothing needs to be started by hand. The next time a client calls
   `org.freedesktop.secrets`, the session D-Bus daemon activates noirpass.

**NixOS**: the flake provides a devShell only. Build through the devShell, copy
the binary (for example to `~/.local/bin/noirpass`), then edit `ExecStart=` in
both service files to use that absolute path.

### Switching from Gnome-Keyring

Only one process can own `org.freedesktop.secrets`. Disable the existing Secret
Service provider before activating noirpass.

## Usage

Any Secret Service client works unmodified. Using `libsecret`'s `secret-tool`:

```sh
secret-tool store --label='My login' service myservice username myuser
# prompts for the secret value on stdin, then stores it

secret-tool lookup service myservice username myuser
# prints the secret value
```

The first call activates the daemon if needed. `gpg-agent` handles normal
pinentry and passphrase caching.

## Configuration Reference

| Flag                 | Env var          | Default                                                             | Description                                                                                         |
| -------------------- | ---------------- | ------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `--store-dir <path>` | `NOIRPASS_STORE` | `$XDG_DATA_HOME/noirpass` (falls back to `~/.local/share/noirpass`) | Directory holding `config.toml`, `keys/`, `index.redb`, and `secrets/`.                             |
| `--idle-exit <secs>` | —                | `300`                                                               | Exit after this many seconds with no D-Bus activity _and_ no open sessions. `0` disables idle-exit. |

Commands:

```sh
noirpass init --recipient <FILE|->
noirpass status
noirpass list
noirpass delete <ITEM-ID>
noirpass check
```

`list`, `delete`, and `check` are offline maintenance commands. Stop the
daemon first because redb permits one writable process. `list` reads metadata
only and never decrypts secret values. `delete` removes one indexed item and
its ciphertext after confirmation. `check` compares redb item records with
`secrets/*.gpg`, offers to remove stale records whose ciphertext is missing,
and reports orphan ciphertext without deleting it. Pass `--yes` to `delete` or
`check` for unattended maintenance.

Monthly maintenance baseline:

```sh
systemctl --user stop noirpass.service
noirpass status
noirpass check
systemctl --user start noirpass.service
```

Review dependency and security updates before release; do not update blindly.
Back up the complete store directory before repair or dependency migration.

`--bus-name` also exists but is hidden from `--help`; it lets tests point
the daemon at a non-default well-known name and is not meant for normal use.

## Security Notes

- **Item labels and attributes are stored in plaintext** in `index.redb`.
  This is a deliberate trade-off for making `SearchItems` a fast local
  lookup instead of requiring a decrypt per candidate. If your attribute
  values or labels are themselves sensitive (not just the secret value),
  be aware they are readable by anything that can read your store
  directory, without needing `gpg-agent` at all. Only the secret _value_
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

All commands run inside the Nix devShell, which provides matching
rustc/cargo/clippy/rustfmt plus `cargo-llvm-cov` and native dependencies
(OpenSSL, Clang, Cap'n Proto, D-Bus, libsecret, GnuPG, and pkg-config):

```sh
nix develop -c cargo fmt --check
nix develop -c cargo clippy --all-targets -- -D warnings
nix develop -c cargo test
nix develop -c cargo llvm-cov --all-targets --fail-under-lines 80
```
