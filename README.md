# Noirpass

Noirpass lets Linux applications save passwords through standard Secret Service support while
protecting secret values with existing OpenPGP key and `gpg-agent`.

Works with desktop keyring applications, including browsers, password managers, and
`secret-tool`. Noirpass starts on demand and exits after inactivity.

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

Install Arch build tools, clone repository, then build included [`archlinux/PKGBUILD`](archlinux/PKGBUILD):

```sh
sudo pacman -S --needed base-devel git
git clone https://codeberg.org/koharu/noirpass.git
cd noirpass/arch
makepkg -si
systemctl --user daemon-reload
```

PKGBUILD installs executable to `/usr/bin`, D-Bus activation file to `/usr/share/dbus-1/services`,
and systemd user unit to `/usr/lib/systemd/user`.

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

Do not replace recipient key after storing secrets. Existing secrets remain encrypted for original
key. Noirpass rejects unsafe recipient changes in non-empty store.

## Commands

| Command                               | Description                                      |
| ------------------------------------- | ------------------------------------------------ |
| `noirpass init --recipient <FILE\|->` | Set up recipient from file or standard input     |
| `noirpass status`                     | Check setup and secret-key availability          |
| `noirpass list`                       | List saved entries without showing secret values |
| `noirpass delete <ITEM-ID>`           | Delete one entry after confirmation              |
| `noirpass check`                      | Check store and offer safe repairs               |

Use `--yes` with `delete` or `check` to skip confirmation.

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

Use same location in daemon service configuration and maintenance commands.

### Configuration

By default, the daemon exits after five inactive minutes with no client session. See
[Configuration Guide](docs/CONFIG.md) for config location, idle-exit behavior, and overrides.

## Maintenance

Stop daemon before `list`, `delete`, or `check`; maintenance needs exclusive store access:

```sh
systemctl --user stop noirpass.service
noirpass status
noirpass check
systemctl --user start noirpass.service
```

Back up complete Noirpass data directory before repairs, upgrades, or key migration. Keep original
OpenPGP secret key available; loss makes saved secret values unrecoverable.

`noirpass check` removes only stale entries after confirmation. Unmatched encrypted files remain
reported and preserved.

> [!NOTE]
> Security Expectations
>
> - Secret values are OpenPGP-encrypted on disk.
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
