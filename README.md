# Noirpass

Password manager daemon that speaks standard `org.freedesktop.secrets`.
Secrets stored as GPG-encrypted files. Unlock via `gpg-agent`.

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
