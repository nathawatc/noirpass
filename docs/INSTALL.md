# Installation

Do not enable `noirpass.service`. Session D-Bus starts it on demand.

<details>
<summary><h3>NixOS</h3></summary>

## Install from Flake

Flake supports `x86_64-linux` and `aarch64-linux`. Enable `nix-command` and `flakes`, then install
directly from Codeberg:

```sh
nix profile install git+https://codeberg.org/koharu/noirpass.git#noirpass
systemctl --user daemon-reload
```

From an existing checkout, use `nix profile install .#noirpass` instead. Package includes executable,
D-Bus activation file, and systemd user unit with immutable Nix store paths.

For declarative flake-input installation, updates, and Secret Service conflict handling, see
[NixOS Flake Guide](NIXOS-FLAKE.md).

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
