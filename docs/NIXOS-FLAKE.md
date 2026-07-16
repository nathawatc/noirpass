# NixOS Flake Guide

Noirpass flake provides reproducible development shell for
`x86_64-linux` and `aarch64-linux`. It currently does not provide package or
NixOS module outputs. `nix build`, `nix profile install`, and adding this
repository to `environment.systemPackages` will not work yet.

Use flake shell to build release binary, then install binary and activation
files for current user.

## Enable flakes

Add following to NixOS configuration:

```nix
{
  nix.settings.experimental-features = [ "nix-command" "flakes" ];
}
```

Apply configuration:

```sh
sudo nixos-rebuild switch
```

For one command without system-wide setting:

```sh
nix --extra-experimental-features 'nix-command flakes' develop
```

## Build

From repository root:

```sh
nix develop -c cargo build --release
```

Binary appears at `target/release/noirpass`. `flake.lock` pins nixpkgs, so
same checkout uses same Rust toolchain and native build dependencies.

Open interactive shell when running several development commands:

```sh
nix develop
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo llvm-cov --all-targets --fail-under-lines 80
```

Otherwise prefix each command with `nix develop -c`. Do not use bare
`cargo`, `rustc`, `gpg`, or related tools on NixOS for this repository.

## Install for current user

Shipped activation files expect `/usr/bin/noirpass`. NixOS does not use that
path for locally built software, so copy files and replace path with absolute
home-directory path:

```sh
mkdir -p "$HOME/.local/bin"
mkdir -p "$HOME/.config/systemd/user"
mkdir -p "$HOME/.local/share/dbus-1/services"

install -m755 target/release/noirpass "$HOME/.local/bin/noirpass"
install -m644 systemd/noirpass.service \
  "$HOME/.config/systemd/user/noirpass.service"
install -m644 systemd/org.freedesktop.secrets.service \
  "$HOME/.local/share/dbus-1/services/org.freedesktop.secrets.service"

sed -i "s|/usr/bin/noirpass|$HOME/.local/bin/noirpass|g" \
  "$HOME/.config/systemd/user/noirpass.service" \
  "$HOME/.local/share/dbus-1/services/org.freedesktop.secrets.service"

systemctl --user daemon-reload
```

Do not enable service. Session D-Bus starts it on demand when client requests
`org.freedesktop.secrets`; noirpass exits after idle timeout.

Installed unit writes default store under `~/.local/share/noirpass`. For
custom `NOIRPASS_STORE`, create systemd user override containing both
`Environment=NOIRPASS_STORE=...` and matching `ReadWritePaths=...`; unit
hardening otherwise blocks writes outside `~/.local/share`.

## Initialize recipient

List secret keys and choose full fingerprint:

```sh
nix develop -c gpg --list-secret-keys --keyid-format long
```

Export public certificate into noirpass:

```sh
nix develop -c bash -c \
  'gpg --armor --export FINGERPRINT | "$HOME/.local/bin/noirpass" init --recipient -'

"$HOME/.local/bin/noirpass" status
```

Replace `FINGERPRINT` with chosen key fingerprint. Secret key remains in
GnuPG; noirpass stores only exported public certificate. Decryption uses
running `gpg-agent` and normal pinentry configuration.

## Resolve Secret Service conflict

Only one process can own `org.freedesktop.secrets`. GNOME Keyring or another
password manager may already own it. Inspect current owner:

```sh
busctl --user status org.freedesktop.secrets
```

Disable competing Secret Service component in desktop configuration before
using noirpass. Exact option depends on desktop and NixOS configuration.
Stopping only current process is temporary; desktop may start it again.

After removing conflict, activate noirpass with test client:

```sh
nix develop -c secret-tool store --label='Noirpass test' service noirpass-test
nix develop -c secret-tool lookup service noirpass-test
```

First command reads secret value from standard input. Second command may open
pinentry through `gpg-agent`.

Check activation and logs:

```sh
systemctl --user status noirpass.service
journalctl --user-unit noirpass.service
```

## Update

After pulling new source, rebuild and replace installed binary:

```sh
git pull --ff-only
nix develop -c cargo build --release
install -m755 target/release/noirpass "$HOME/.local/bin/noirpass"
systemctl --user try-restart noirpass.service
```

`try-restart` replaces running daemon without starting inactive daemon.
D-Bus starts inactive daemon on next request.

Maintainers can update pinned nixpkgs input with:

```sh
nix flake update
```

Review and commit `flake.lock` change. Users seeking reproducible build should
not update lock file implicitly.

## Remove user installation

```sh
systemctl --user stop noirpass.service
rm "$HOME/.config/systemd/user/noirpass.service"
rm "$HOME/.local/share/dbus-1/services/org.freedesktop.secrets.service"
rm "$HOME/.local/bin/noirpass"
systemctl --user daemon-reload
```

This leaves encrypted store at `~/.local/share/noirpass`. Remove or archive it
separately only when stored secrets are no longer needed.
