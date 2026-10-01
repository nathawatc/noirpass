# Noirpass

Minimal on-demand GPG-backed freedesktop Secret Service

Noirpass is a minimal freedesktop Secret Service backend. Persistent secrets use redb metadata and
OpenPGP-encrypted values on disk, with `gpg-agent` for private-key operations. The standard
`session` collection is temporary: its secret values stay only in daemon memory and disappear when
the daemon/login session ends.

Applications interact with Noirpass through the standard Secret Service D-Bus API. The Noirpass CLI
is limited to initialization, inspection, deletion, integrity maintenance, and deinitialization.
Noirpass intentionally does not provide password-manager UI, secret editing workflows, keyring
management UI, recipient migration, sync, backup management, or other manager features.

## Before You Start

Requirements:

- Linux with user D-Bus session
- GnuPG and personal OpenPGP key capable of encryption
- Working `gpg-agent` and pinentry setup
- Noirpass binary and included service files

Only one Secret Service provider can run per session. Disable GNOME Keyring, KWallet, or another
provider for `org.freedesktop.secrets` before using Noirpass.

## Install

Do not enable `noirpass.service`. Session D-Bus starts it on demand.

<details>
<summary><h3>NixOS</h3></summary>

### Install from Flake

Flake supports `x86_64-linux` and `aarch64-linux`. Enable `nix-command` and `flakes`, then install
directly from Codeberg:

```sh
nix profile install git+https://codeberg.org/koharu/noirpass.git#noirpass
systemctl --user daemon-reload
```

From an existing checkout, use `nix profile install .#noirpass` instead. Package includes executable,
D-Bus activation file, and systemd user unit with immutable Nix store paths.

For declarative flake-input installation, updates, and Secret Service conflict handling, see
[NixOS Flake Guide](docs/NIXOS-FLAKE.md).

<details>
<summary><h4>Manual Installation</h4></summary>

Build inside provided development environment:

```sh
nix develop -c cargo build --release
```

Install executable and activation files for current user, replacing `/usr/bin/noirpass` with NixOS
user-local path:

```sh
install -Dm755 target/release/noirpass "$HOME/.local/bin/noirpass"
install -Dm644 systemd/noirpass.service \
  "$HOME/.config/systemd/user/noirpass.service"
install -Dm644 systemd/org.freedesktop.secrets.service \
  "$HOME/.local/share/dbus-1/services/org.freedesktop.secrets.service"

sed -i "s|/usr/bin/noirpass|$HOME/.local/bin/noirpass|g" \
  "$HOME/.config/systemd/user/noirpass.service" \
  "$HOME/.local/share/dbus-1/services/org.freedesktop.secrets.service"

systemctl --user daemon-reload
```

Rebuild and replace executable manually after each update.

</details>

</details>

<details>
<summary><h3>Arch Linux</h3></summary>

### Install from AUR

Example:

```sh
paru -S noirpass
```

</details>

### Build from Source

Install Rust 1.95 or newer plus GnuPG, OpenSSL, Clang, Cap'n Proto, and `pkg-config`, then build from
repository root:

```sh
cargo build --locked --release
```

Install executable and activation files:

```sh
sudo install -Dm755 target/release/noirpass /usr/bin/noirpass
install -Dm644 systemd/noirpass.service \
  "$HOME/.config/systemd/user/noirpass.service"
install -Dm644 systemd/org.freedesktop.secrets.service \
  "$HOME/.local/share/dbus-1/services/org.freedesktop.secrets.service"
systemctl --user daemon-reload
```

If executable is installed elsewhere, replace `/usr/bin/noirpass` in both copied activation files
with its absolute path.

## Set Up

Find full key fingerprint:

```sh
gpg --list-secret-keys --keyid-format long
```

Initialize Noirpass with public certificate:

```sh
gpg --armor --export <FINGERPRINT> | noirpass init --recipient -
noirpass status
```

`noirpass status` should report `initialized: yes`; it also confirms matching secret-key access
through `gpg-agent`.

Primary OpenPGP fingerprint is Noirpass recipient identity. Reinitializing with a refreshed
certificate for same primary is allowed. Recipient rotation/migration is unsupported, and Noirpass
rejects different primary even when store has no secrets. To change primary, explicitly run:

```sh
noirpass deinit
noirpass init --recipient <FILE|->
```

`init` never deletes data or invokes `deinit`.

## Commands

| Command                               | Description                                              |
| ------------------------------------- | -------------------------------------------------------- |
| `noirpass init --recipient <FILE\|->` | Set up recipient from file or standard input             |
| `noirpass deinit`                     | Permanently delete Noirpass data after two confirmations |
| `noirpass status`                     | Check setup and secret-key availability                  |
| `noirpass list`                       | List saved entries without showing secret values         |
| `noirpass delete <ITEM-ID>`           | Delete one entry after confirmation                      |
| `noirpass check`                      | Check store and offer integrity repairs                  |

Use `--yes` with `delete` or `check` to skip confirmation. `deinit` deliberately has no `--yes`,
force flag, non-interactive bypass, or piped-input authorization: it requires a real interactive TTY
and two separate explicit `y`/`yes` confirmations. It permanently destroys Noirpass configuration,
recipient information, metadata, encrypted secrets, and recognized recovery/transaction artifacts.
Unknown or unowned files remain untouched; an unrelated file under `secrets/` does not block later
fresh initialization, while possible `.gpg` ciphertext remains fail-closed.

### Data Location

Default data directory:

```text
$XDG_DATA_HOME/noirpass
```

When `XDG_DATA_HOME` is unset, default:

```text
~/.local/share/noirpass
```

Choose another location with either:

```sh
noirpass --store-dir /path/to/store <COMMAND>
NOIRPASS_STORE=/path/to/store noirpass <COMMAND>
```

Use same location in daemon service configuration and maintenance commands. The included user systemd
unit grants write access under `%h/.local/share` only. If `XDG_DATA_HOME`, `NOIRPASS_STORE`, or
`--store-dir` places daemon state outside that tree, add a user service override extending
`ReadWritePaths` to the selected store's parent rather than weakening systemd hardening globally.

### Configuration

By default, the daemon exits after five inactive minutes when there is no open transport session and
no temporary secret in the `session` collection. A temporary secret keeps the daemon alive so
“remember for this session” clients do not lose it to the idle timer. See
[Configuration Guide](docs/CONFIG.md) for config location, idle-exit behavior, and overrides.

### Temporary Session Secrets

Noirpass exposes the standard Secret Service `session` alias at
`/org/freedesktop/secrets/collection/session`. Items created there stay only in daemon memory. This
is the collection used by libsecret clients for “remember for this session”; GVfs-backed mount
flows, including encrypted-volume mounts opened from file managers such as Thunar, can use it when
the user chooses the session-only password option.

Temporary items keep the daemon alive past `idle_exit`. Deleting the item, stopping Noirpass, or
ending the graphical login session clears the secret.

Temporary storage accepts at most 256 items and 16 MiB of combined secret and metadata payload.
Each secret is limited to 1 MiB; each item accepts at most 64 attributes, 4 KiB per metadata string,
and 64 KiB of total metadata. Updates exceeding a limit leave the existing item unchanged.
The packaged systemd service sets `LimitCORE=0`; host swap and other memory access policies still apply.

## Maintenance

Stop daemon before `list`, `delete`, `check`, or `deinit`; maintenance needs exclusive store access:

```sh
systemctl --user stop noirpass.service
noirpass status
noirpass check
systemctl --user start noirpass.service
```

Back up complete Noirpass data directory before repairs or upgrades. Keep original OpenPGP secret key
available; loss makes saved secret values unrecoverable.

`noirpass check` reports integrity findings and asks before applying repairs. A corrupt item with a
valid canonical item ID is treated as corrupt as a whole: confirmation deletes its metadata and
associated ciphertext.

> [!NOTE]
> Security Expectations
>
> - Persistent secret values are OpenPGP-encrypted on disk.
> - Secrets stored in the standard `session` collection are not written to the Noirpass store; they
>   remain as zeroizing process memory and disappear when Noirpass stops. Process memory can still
>   be exposed by mechanisms such as core dumps or swap unless the host blocks them.
> - Entry names and search fields are not encrypted. Avoid sensitive information in labels and
>   attributes.
> - Access depends on GnuPG key, `gpg-agent`, pinentry, and passphrase policy.
> - Anyone controlling unlocked desktop session may ask Secret Service clients to access secrets.
>   Lock session when unattended.

<details>
<summary><h3>Troubleshooting</h3></summary>

### Service Does Not Start

Run:

```sh
noirpass status
systemctl --user status noirpass.service
journalctl --user -u noirpass.service
```

Check Noirpass path in both installed service files.

#### Another Keyring Answers Requests

Another provider owns `org.freedesktop.secrets`. Disable its Secret Service component, sign out,
then sign in again.

#### Secret Key Is Unavailable

Confirm key exists and `gpg-agent` can use it:

```sh
gpg --list-secret-keys
noirpass status
```

For hardware-backed keys, connect token and verify normal GnuPG decryption works.

#### Maintenance Says Store Is in Use

Stop daemon and manually started Noirpass processes, then rerun command.

</details>
