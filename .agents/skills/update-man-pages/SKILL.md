---
name: update-man-pages
description: >-
  Regenerate and lint man/noirpass.1 and man/noirpass.toml.5. Use after changing CLI flags or
  subcommands, config keys or defaults, store paths, or src/cli/man.rs.
---

# Update Man Pages

Regenerate checked-in man pages from code. CLI and configuration invariants live in
[src/cli/AGENTS.md](../../../src/cli/AGENTS.md#man-pages) and
[src/config/AGENTS.md](../../../src/config/AGENTS.md).

## Steps

1. Regenerate `man/noirpass.1` and `man/noirpass.toml.5` (also runs `mandoc -Tlint` when
   installed):

   ```sh
   UPDATE_MAN_PAGES=1 cargo test --bin noirpass man_pages_match_source_of_truth
   ```

2. Preview rendered output for layout and wrapping:

   ```sh
   MANWIDTH=80 man -l man/noirpass.1 | col -b
   MANWIDTH=80 man -l man/noirpass.toml.5 | col -b
   ```

3. Re-run binary unit tests without `UPDATE_MAN_PAGES` to verify drift and lint checks pass:

   ```sh
   cargo test --bin noirpass
   ```

## Completion Criteria

- `cargo test --bin noirpass` exits `0` without `UPDATE_MAN_PAGES`.
- `man -l` preview shows clean wrapping, valid roff formatting, and current CLI/config values.
