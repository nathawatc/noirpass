# Systemd Ownership

Own the user systemd service and D-Bus activation integration in `systemd/noirpass.service` and
`systemd/org.freedesktop.secrets.service`. Keep these files consistent with CLI startup/shutdown
contracts in [`../src/cli/AGENTS.md`](../src/cli/AGENTS.md) and packaged paths from [`../flake.nix`](../flake.nix).

## D-Bus Activation Contract

- The activation file must advertise `Name=org.freedesktop.secrets`.
- `SystemdService=noirpass.service` must route activation to the matching user unit.
- The unit must use `Type=dbus` and `BusName=org.freedesktop.secrets`; these values must match the
  activation name and the daemon's requested well-known name.
- Do not add a second provider, eager startup path, or alternate well-known name. D-Bus activation
  must start one service instance and let daemon startup claim the name only after its object tree is
  ready.
- Source service files use `/usr/bin/noirpass`. Nix packaging substitutes both installed activation
  files to the packaged `$out/bin/noirpass`; any packaging change must preserve that substitution.

## Unit Behavior and Filesystem Access

- Preserve `Restart=on-failure` so failed daemon instances can be reactivated without masking normal
  clean shutdown behavior.
- The default unit permits the default store under `%h/.local/share/noirpass` by granting
  `ReadWritePaths=%h/.local/share`; retain the writable parent because Noirpass creates the leaf.
- A custom `--store-dir` or `NOIRPASS_STORE` path is not automatically covered. Installation/config
  changes must add the selected store's parent to `ReadWritePaths` and ensure it is compatible with
  `ProtectHome=read-only` and other path restrictions. Do not document custom paths as supported by
  the unit without matching filesystem access rules.
- Keep `PartOf=graphical-session.target` and the user-unit installation target unless an activation
  design change updates both service and D-Bus integration together.

## Sandbox and Hardening

Preserve the current least-privilege directives and review any relaxation as a security change:

```text
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
CapabilityBoundingSet=
```

The service must remain a user service with only Unix-socket networking, no ambient capabilities, and
read-only access outside explicitly writable store paths. Keep comments explaining non-obvious path
choices, especially why `ReadWritePaths` names the data parent rather than the store leaf.

## Packaging and Validation

Package version follows `Cargo.toml`; do not duplicate the release version in `flake.nix`.
Package and formatting checks use repository-owned dependencies and fixtures and remain hermetic.

`flake.nix` installs both service files, substitutes the packaged executable path in both, runs
hermetic package checks, and exposes package/app/check/dev-shell outputs. Changes to unit names,
activation keys, executable paths, writable paths, or hardening directives require inspecting the
Nix `postInstall` substitution and validating the installed-file result without using a user's real
Secret Service bus or store.
