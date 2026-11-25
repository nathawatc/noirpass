# Noirpass

Minimal, on-demand GPG-backed freedesktop Secret Service for Linux. Applications use the standard
Secret Service D-Bus API. Persistent values are OpenPGP-encrypted on disk; labels and search
attributes remain plaintext. Private-key operations use `gpg-agent` and its pinentry policy.

The temporary `session` collection keeps secrets in zeroizing memory until deletion or daemon exit.
Temporary secrets keep the daemon alive past its idle timeout. Disconnecting a client does not delete
its temporary items. Host memory, swap, and desktop-session security still apply.

Noirpass provides a maintenance CLI. It has no password-manager UI, secret editing, recipient
migration, or sync.

## Install

Requires Linux 5.6+, mounted `/proc`, a user D-Bus session, GnuPG, an encryption-capable OpenPGP key,
and working `gpg-agent`/pinentry. Only one provider may own `org.freedesktop.secrets`; disable the
Secret Service component of GNOME Keyring, KWallet, or another provider first.

Nix:

```sh
nix profile install github:nathawatc/noirpass#noirpass
systemctl --user daemon-reload
```

Arch Linux: install `noirpass` from AUR. For source builds and manual activation-file installation,
see [Installation](docs/INSTALL.md). Declarative NixOS setup is in the
[NixOS Flake Guide](docs/NIXOS-FLAKE.md).

D-Bus starts Noirpass on demand. Do not enable `noirpass.service`.

## Set Up

Find your full primary fingerprint and initialize with its public certificate:

```sh
gpg --list-secret-keys --keyid-format long
gpg --armor --export <FINGERPRINT> | noirpass init --recipient -
noirpass status
```

Status should show `initialized: yes` and available secret-key access. Refreshing the certificate
for the same primary key is supported. Changing primary keys requires `deinit` and a fresh `init`;
`deinit` permanently deletes saved data.

## Commands

| Command                               | Purpose                                                  |
| ------------------------------------- | -------------------------------------------------------- |
| `noirpass init --recipient <FILE\|->` | Initialize from a public certificate                     |
| `noirpass deinit`                     | Permanently delete Noirpass data after two confirmations |
| `noirpass status`                     | Check initialization and secret-key availability         |
| `noirpass list`                       | List entries without revealing values                    |
| `noirpass delete <ITEM-ID>`           | Delete one entry after confirmation                      |
| `noirpass check`                      | Inspect integrity and offer repairs                      |

`delete` and `check` accept `--yes`. `deinit` requires an interactive TTY and two explicit
confirmations; it has no non-interactive bypass. Unknown or unowned files remain untouched.

Stop Noirpass before maintenance requiring exclusive store access:

```sh
systemctl --user stop noirpass.service
noirpass check
```

D-Bus reactivates it when an application next requests secrets. Back up the complete data directory
before repairs or upgrades. Keep the original OpenPGP secret key; losing it makes persistent values
unrecoverable. Integrity repair may delete corrupt entries and their ciphertext after confirmation.
A client timeout does not cancel an admitted write; check its result before retrying.

## Configuration

Data defaults to `$XDG_DATA_HOME/noirpass`, or `~/.local/share/noirpass` when unset. Select another
store with `--store-dir /path/to/store` or `NOIRPASS_STORE=/path/to/store`. Use the same location for
the daemon and maintenance commands. Stores outside `%h/.local/share` require a systemd override
adding the selected store's parent to `ReadWritePaths`.

Default idle exit is five minutes without activity, transport sessions, or temporary items. See
[Configuration](docs/CONFIG.md) for `config.toml` and overrides.

Temporary storage is bounded to 256 items and 16 MiB, with at most 1 MiB per secret. Applications
receiving `org.freedesktop.DBus.Error.LimitsExceeded` should close unused sessions, wait for work to
finish, or retrieve fewer secrets per bulk call. Individual `GetSecret` can retrieve persistent
items too large for a bulk reply.

## Troubleshooting

```sh
noirpass status
systemctl --user status noirpass.service
journalctl --user -u noirpass.service
```

Check installed activation-file paths if startup fails. If another keyring answers, disable its
Secret Service component and sign out/in. If a key is unavailable, check GnuPG and connect any
required hardware token. If maintenance reports a busy store, stop Noirpass and any manually
started instances.

Lock your desktop when unattended: applications in an unlocked session can request secrets.
