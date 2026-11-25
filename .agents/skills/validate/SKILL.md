---
name: validate
description: >-
  Validate repository changes (build, formatting, lint, tests, coverage, docs, diff). Use before
  finishing any code, doc, or packaging change.
---

# Validate Noirpass

Run repository validation gates. Rules and test-isolation invariants live in
[AGENTS.md](../../../AGENTS.md#environment-and-validation) and
[tests/AGENTS.md](../../../tests/AGENTS.md).

## Steps

1. Check Rust formatting:

   ```sh
   cargo fmt --check
   ```

2. Run Clippy with warnings denied across all targets:

   ```sh
   cargo clippy --all-targets -- -D warnings
   ```

3. Run the full test suite (includes man-page drift and `mandoc -Tlint` checks):

   ```sh
   cargo test
   ```

4. Build the release binary:

   ```sh
   cargo build --release
   ```

5. Check line coverage:

   ```sh
   cargo llvm-cov --all-targets --fail-under-lines 80
   ```

6. Check Markdown files when docs, `AGENTS.md`, or skills changed:

   ```sh
   rumdl check . .agents/skills/*/SKILL.md
   ```

7. Check git diff whitespace and conflict markers:

   ```sh
   git diff --check
   ```

## Completion Criteria

- Every applicable command exits `0` from observed output in the current run.
- Zero Clippy warnings, zero test failures, line coverage `>= 80%`, and zero `rumdl` or
  `git diff --check` errors.
