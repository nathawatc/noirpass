# Noirpass

Minimal, on-demand GPG-backed freedesktop Secret Service for Linux. Applications use the standard
Secret Service D-Bus API. Persistent values are OpenPGP-encrypted on disk; labels and search
attributes remain plaintext. Private-key operations use `gpg-agent` and its pinentry policy.

The temporary `session` collection keeps secrets in zeroizing memory until deletion or daemon exit.
Temporary secrets keep the daemon alive past its idle timeout. Disconnecting a client does not delete
its temporary items. Host memory, swap, and desktop-session security still apply.

Noirpass provides a maintenance CLI only. It has no password-manager UI, secret editing, recipient
migration, or sync.

## Install

Requires Linux 5.6+, mounted `/proc`, a user D-Bus session, GnuPG, an encryption-capable OpenPGP key,
and working `gpg-agent`/pinentry. Disable any competing `org.freedesktop.secrets` provider (such as
GNOME Keyring or KWallet) first.

Nix:

```sh
nix profile install github:nathawatc/noirpass#noirpass
systemctl --user daemon-reload
```

Arch Linux: install `noirpass` from AUR. For source builds and activation-file setup, see the
[Installation](https://github.com/nathawatc/noirpass/wiki/Installation) wiki page. For declarative
NixOS setup, see [NixOS Flake](https://github.com/nathawatc/noirpass/wiki/NixOS-Flake).

D-Bus starts Noirpass on demand. Do not enable `noirpass.service`.

## Quick Start

Initialize with your primary OpenPGP key's public certificate:

```sh
gpg --list-secret-keys --keyid-format long
gpg --armor --export <FINGERPRINT> | noirpass init --recipient -
noirpass status
```

## Documentation

- **CLI reference:** `man noirpass`
  ([`man/noirpass.1`](https://github.com/nathawatc/noirpass/blob/main/man/noirpass.1))
- **Config reference:** `man noirpass.toml`
  ([`man/noirpass.toml.5`](https://github.com/nathawatc/noirpass/blob/main/man/noirpass.toml.5))
- **Guides (Wiki):** [Home](https://github.com/nathawatc/noirpass/wiki),
  [Installation](https://github.com/nathawatc/noirpass/wiki/Installation),
  [Configuration](https://github.com/nathawatc/noirpass/wiki/Configuration),
  [NixOS Flake](https://github.com/nathawatc/noirpass/wiki/NixOS-Flake),
  [Troubleshooting](https://github.com/nathawatc/noirpass/wiki/Troubleshooting)

Lock your desktop when unattended: applications in an unlocked session can request secrets.
