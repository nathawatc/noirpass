# noirpass

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
- No `gpg` subprocess per operation: the recipient certificate is loaded
  once at startup, encryption happens in-process (Sequoia), and decryption
  goes through your already-running `gpg-agent`.
- On-demand: starts on D-Bus activation, exits after an idle timeout.
  Nothing runs when you aren't using it.
- Both Secret Service session transports (`plain` and the encrypted
  Diffie-Hellman mode) are implemented, matching what real clients use.

## How it works

```
~/.local/share/noirpass/
├── index.redb          # collections, item labels & attributes, aliases
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

```
nix develop -c cargo build --release
```

The resulting binary is at `target/release/noirpass`.

On a generic Linux system without Nix, install a recent Rust toolchain
(edition 2024, so rustc ≥ 1.85) plus the native dependencies the
dependency tree needs to build: GnuPG (`gnupg`, for the `gpg` binary used
once at startup and by `gpg-agent`), Nettle (`nettle`, Sequoia's crypto
backend), and `capnproto` (Sequoia's IPC layer build script). Then:

```
cargo build --release
```

## Install & activation

1. Build the binary (above) and copy it somewhere on your `PATH` that
   systemd user units can reference with an absolute path:

   ```
   mkdir -p ~/.local/bin
   cp target/release/noirpass ~/.local/bin/noirpass
   ```

2. Install the systemd user unit and the D-Bus activation file:

   ```
   mkdir -p ~/.config/systemd/user ~/.local/share/dbus-1/services
   cp systemd/noirpass.service ~/.config/systemd/user/
   cp systemd/org.freedesktop.secrets.service ~/.local/share/dbus-1/services/
   systemctl --user daemon-reload
   ```

   Both shipped unit files already point at `%h/.local/bin/noirpass`
   (`$HOME/.local/bin/noirpass`); edit `ExecStart=`/`Exec=` in both files
   first if you installed the binary elsewhere — systemd and D-Bus
   activation both require an absolute path.

3. Nothing needs to be started by hand. The next time any client (a
   browser, `secret-tool`, etc.) calls a method on `org.freedesktop.secrets`,
   the session D-Bus daemon activates `noirpass.service` automatically. The
   daemon exits again after `--idle-exit` seconds of inactivity with no
   open sessions, and is re-activated on the next request.

### Switching from gnome-keyring on NixOS

Only one process can own the `org.freedesktop.secrets` bus name at a time.
On most NixOS/GNOME setups that owner is gnome-keyring's Secret Service
component. Check who currently owns it:

```
busctl --user list | grep secrets
```

If gnome-keyring owns it, disable its Secret Service component in your
NixOS or home-manager configuration:

```nix
# NixOS system configuration:
services.gnome.gnome-keyring.enable = false;
```

If you still want gnome-keyring for other components (e.g. SSH agent) and
only want to drop its Secret Service piece, mask the D-Bus activation file
instead of disabling the whole service — the exact option depends on how
your setup packages gnome-keyring's `.service` files; check
`~/.local/share/dbus-1/services/` and `/run/current-system/sw/share/dbus-1/services/`
for `org.freedesktop.secrets.service` entries pointing at gnome-keyring and
override or remove the one with lower precedence.

Be aware: **D-Bus activation files are read once when the session bus
starts**, and gnome-keyring itself is typically started once per session by
your desktop environment. Simply flipping the Nix option is usually not
enough to take effect immediately — log out and back in (or otherwise
restart your graphical session / session bus) so the D-Bus activation
directory is rescanned without a stale gnome-keyring instance already
holding the name.

## Usage

Any Secret Service client works unmodified. Using `libsecret`'s
`secret-tool`:

```
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

## Configuration reference

| Flag | Env var | Default | Description |
| --- | --- | --- | --- |
| `--store-dir <path>` | `NOIRPASS_STORE` | `$XDG_DATA_HOME/noirpass` (falls back to `~/.local/share/noirpass`) | Directory holding `index.redb` and `secrets/`. |
| `--key <fingerprint>` | — | First available secret key (`gpg --list-secret-keys`) | OpenPGP fingerprint to encrypt new secrets to. |
| `--idle-exit <secs>` | — | `300` | Exit after this many seconds with no D-Bus activity *and* no open sessions. `0` disables idle-exit. |

`--bus-name` also exists but is hidden from `--help`; it lets tests point
the daemon at a non-default well-known name and is not meant for normal use.

## Security notes

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
  `ReadWritePaths` exception for the store directory, `PrivateTmp`,
  `MemoryDenyWriteExecute`, `RestrictRealtime`, `RestrictNamespaces`,
  `LockPersonality`, `ProtectKernelTunables`, `ProtectKernelModules`,
  `ProtectControlGroups`, `RestrictAddressFamilies=AF_UNIX`, an
  `@system-service` syscall filter, and an empty
  `CapabilityBoundingSet`.

## Development

All commands run inside the Nix devShell, which provides a matching
rustc/cargo/clippy/rustfmt plus `cargo-llvm-cov` and every native
dependency (nettle, capnproto, clang, dbus, libsecret, gnupg,
pkg-config):

```
nix develop -c cargo fmt --check
nix develop -c cargo clippy --all-targets -- -D warnings
nix develop -c cargo test
nix develop -c cargo llvm-cov --all-targets --fail-under-lines 80
```

All four gates are expected to pass clean (zero warnings) before any
change is considered done; current coverage is 91.95% lines.

Integration tests (`tests/integration.rs`) need no real GPG key or access
to your session bus: they generate a fresh empty-passphrase key in an
ephemeral `GNUPGHOME`, spawn a private `dbus-daemon --session`, and run the
real `noirpass` binary against that private bus, exercising both session
transports plus real `secret-tool`/libsecret and `oo7` clients.

## License

Apache-2.0 — see [LICENSE](LICENSE).
