# NixOS Flake Guide

Noirpass flake provides packages, apps, checks, and development shells for
`x86_64-linux` and `aarch64-linux`. Darwin is not declared supported.

## Enable flakes

Add to NixOS configuration:

```nix
{
  nix.settings.experimental-features = [ "nix-command" "flakes" ];
}
```

Apply configuration with `sudo nixos-rebuild switch`. For one command without
system-wide setting, add
`--extra-experimental-features 'nix-command flakes'` to `nix` command.

## Use as flake input

Another NixOS flake can consume noirpass directly. The package output is
system-specific, so use `noirpass.packages.${system}.noirpass` (or
`noirpass.packages.${system}.default`) for the host system:

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    noirpass = {
      url = "git+https://codeberg.org/koharu/noirpass.git";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = inputs@{ self, nixpkgs, noirpass, ... }:
    let
      system = "x86_64-linux";
    in
    {
      nixosConfigurations.example = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          ({ ... }: {
            environment.systemPackages = [
              noirpass.packages.${system}.noirpass
            ];
          })
        ];
      };
    };
}
```

This installs the noirpass executable and its D-Bus and systemd user
activation files through `environment.systemPackages`.

Update only the noirpass input with:

```sh
nix flake update noirpass
```

## Build, run, and check

From repository root:

```sh
nix build
./result/bin/noirpass --help

nix run . -- --help
nix develop
nix flake check
```

`flake.lock` pins nixpkgs, Rust toolchain, and native dependencies. Package
uses `Cargo.lock` and Cargo's offline mode during build.

Default check builds release package, runs Rust tests with private D-Bus and
ephemeral `GNUPGHOME` fixtures, and checks formatting. It never uses real
session bus, GPG keyring, pinentry, secrets, or home-directory state. Optional
`secret-tool` smoke feature is not enabled by flake check.

## Install into user profile

Install from current checkout:

```sh
nix profile install .#noirpass
systemctl --user daemon-reload
```

Install directly from Codeberg:

```sh
nix profile install git+https://codeberg.org/koharu/noirpass.git#noirpass
systemctl --user daemon-reload
```

Package installs:

```text
bin/noirpass
share/dbus-1/services/org.freedesktop.secrets.service
share/systemd/user/noirpass.service
```

Activation files reference immutable packaged binary path. NixOS includes user
profile `share` directory in D-Bus and systemd search paths. Do not enable
service: session D-Bus starts it on demand, and daemon exits after idle timeout.

## Initialize recipient

Ensure GnuPG and `gpg-agent` are configured for user. List secret keys and use
full fingerprint:

```sh
gpg --list-secret-keys --keyid-format long
gpg --armor --export <FINGERPRINT> | noirpass init --recipient -
noirpass status
```

Noirpass stores exported public certificate only. Decryption communicates with
running `gpg-agent` through its socket and follows normal pinentry policy.

## Resolve Secret Service conflict

Only one process can own `org.freedesktop.secrets`. Inspect current owner:

```sh
busctl --user status org.freedesktop.secrets
```

Disable competing Secret Service component in desktop or NixOS configuration
before using noirpass. Exact option depends on desktop. Flake does not disable
or replace another provider automatically.

Test activation after removing conflict:

```sh
secret-tool store --label='Noirpass test' service noirpass-test
secret-tool lookup service noirpass-test
```

Inspect service and logs:

```sh
systemctl --user status noirpass.service
journalctl --user-unit noirpass.service
```

## Custom store or idle timeout

Create systemd user override:

```sh
systemctl --user edit noirpass.service
```

Example:

```ini
[Service]
ExecStart=
ExecStart=%h/.nix-profile/bin/noirpass --store-dir %h/.local/share/noirpass --idle-exit 600
```

Default hardened unit permits writes under `~/.local/share`. Store elsewhere
also requires matching `ReadWritePaths=` override.

## Update or remove

Update installation from checkout:

```sh
nix profile upgrade noirpass
systemctl --user daemon-reload
systemctl --user try-restart noirpass.service
```

Remove installation:

```sh
systemctl --user stop noirpass.service
nix profile remove noirpass
systemctl --user daemon-reload
```

Encrypted store remains at `~/.local/share/noirpass`.

## NixOS module status

No NixOS module is included yet. Provider ownership and desktop conflict policy
need explicit design before declarative replacement is safe. Package and user
activation files remain usable without module.
