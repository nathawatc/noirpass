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

Build release binary with provided Nix environment:

```sh
nix develop -c cargo build --release
```

Install binary and service files:

```sh
sudo cp target/release/noirpass /usr/bin/
mkdir -p ~/.config/systemd/user ~/.local/share/dbus-1/services
cp systemd/noirpass.service ~/.config/systemd/user/
cp systemd/org.freedesktop.secrets.service ~/.local/share/dbus-1/services/
systemctl --user daemon-reload
```

Service files expect Noirpass at `/usr/bin/noirpass`. If installed elsewhere, update `ExecStart` and
`Exec` in copied service files with its absolute path.

## Set Up

Find key fingerprint:

```sh
gpg --list-secret-keys --keyid-format long
```

Initialize Noirpass with public certificate:

```sh
gpg --armor --export <FINGERPRINT> | noirpass init --recipient -
noirpass status
```

`noirpass status` should report `initialized: yes`; also confirms matching secret-key access
through `gpg-agent`.

Do not replace recipient key after storing secrets. Existing secrets remain encrypted for original
key. Noirpass rejects unsafe recipient changes in non-empty store.

## Use

No manual daemon start needed. Compatible applications activate Noirpass when accessing Secret
Service.

Example with `secret-tool`:

```sh
secret-tool store --label='My login' service myservice username myuser
secret-tool lookup service myservice username myuser
```

GnuPG displays pinentry when key needs unlocking and applies configured passphrase cache policy.

## Commands

```text
noirpass init --recipient <FILE|->   Set up recipient from file or standard input
noirpass status                     Check setup and secret-key availability
noirpass list                       List saved entries without showing secret values
noirpass delete <ITEM-ID>           Delete one entry after confirmation
noirpass check                      Check store and offer safe repairs
```

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

### Idle Exit

Daemon exits after five inactive minutes with no client session. Change timeout with:

```sh
noirpass --idle-exit 600
```

Use `--idle-exit 0` to keep daemon running.

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

## Security Expectations

- Secret values are OpenPGP-encrypted on disk.
- Entry names and search fields are not encrypted. Avoid sensitive information in labels and
  attributes.
- Access depends on GnuPG key, `gpg-agent`, pinentry, and passphrase policy.
- Anyone controlling unlocked desktop session may ask Secret Service clients to access secrets.
  Lock session when unattended.

## Troubleshooting

### Service Does Not Start

Run:

```sh
noirpass status
systemctl --user status noirpass.service
journalctl --user -u noirpass.service
```

Check Noirpass path in both installed service files.

### Another Keyring Answers Requests

Another provider owns `org.freedesktop.secrets`. Disable its Secret Service component, sign out,
then sign in again.

### Secret Key Is Unavailable

Confirm key exists and `gpg-agent` can use it:

```sh
gpg --list-secret-keys
noirpass status
```

For hardware-backed keys, connect token and verify normal GnuPG decryption works.

### Maintenance Says Store Is in Use

Stop daemon and manually started Noirpass processes, then rerun command.

## License

Apache-2.0. See `LICENSE`.
