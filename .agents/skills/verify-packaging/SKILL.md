---
name: verify-packaging
description: >-
  Verify Cargo crate contents, flake.nix packaging, activation substitutions, and installed man
  pages. Use after changing Cargo.toml, flake.nix, systemd/, or man/.
---

# Verify Packaging

Validate crate archive and Nix/systemd packaging against isolated outputs. Packaging, activation,
and hardening invariants live in
[systemd/AGENTS.md](../../../systemd/AGENTS.md#packaging-and-validation).

## Steps

1. Inspect the Cargo crate file list:

   ```sh
   cargo package --list --allow-dirty
   ```

2. Verify `flake.nix` `postInstall` installs and substitutes every unit and man page required by
   [systemd/AGENTS.md](../../../systemd/AGENTS.md#packaging-and-validation).

3. When `nix` is available, run hermetic Nix checks and build:

   ```sh
   nix flake check
   nix build
   ```

4. Confirm installed activation files under `./result/share/` substitute `/usr/bin/noirpass`:

   ```sh
   grep -rn '/usr/bin/noirpass' result/share/
   ```

## Completion Criteria

- `cargo package --list --allow-dirty` includes `man/` and `systemd/` runtime files and omits
  excluded repo-only files.
- When `nix` is available, `nix flake check` and `nix build` exit `0`, `./result/share/` contains
  the installed units and man pages, and `grep` finds zero `/usr/bin/noirpass` matches.
- When `nix` is unavailable (`exit 127`), report that Nix verification was skipped.
