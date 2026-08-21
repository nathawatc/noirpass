# GPG Ownership

Own OpenPGP certificate validation and at-rest encryption/decryption in current `src/gpg.rs`,
including its test-only fixture support. The application must keep private-key material behind the
GPG-agent boundary.

## OpenPGP Boundary

- Parse and validate recipient certificates before configuration writes. Require current usable
  encryption-capable certificate keys; reject revoked, expired, unusable, or otherwise unsuitable
  encryption recipients.
- Encrypt each secret in-process with the existing Sequoia backend to every current live, non-revoked
  certificate key flagged for storage/transport encryption. Keep ciphertext independent per item.
- Decrypt through the running `gpg-agent` using the existing keygrip/key mapping design. Never
  load private key material into Noirpass, expose it through the Store API, or log secret/plaintext
  bytes.
- Blocking Sequoia and agent operations must stay off the async executor (use the established
  blocking boundary).
- The primary fingerprint is a certificate fact used by config as recipient identity. Full lifecycle
  rules—same-primary refresh, different-primary rejection, and explicit deinit—belong to
  [`../config/AGENTS.md`](../config/AGENTS.md).

## Process and Agent Rules

- Production daemon and startup paths must never spawn `gpg`, `gpg2`, `gpgconf`, or a shell. They use
  the existing agent boundary only.
- Test-only GPG subprocesses are allowed inside exact fresh temporary `GNUPGHOME` directories.
  Pass `--homedir <temp>` explicitly to every `gpg`/`gpgconf` invocation and pass the same isolated
  home to every spawned Noirpass process that needs agent access.
- Never use the user's `~/.gnupg`, import fixture keys into it, kill its agent, or depend on ambient
  keys. `gpgconf --kill gpg-agent` is permitted only with the exact fixture-owned home.
- Pinentry and passphrase interaction remain the agent boundary; fixtures may use loopback pinentry
  only inside their temporary home.

Changes to certificate selection, Sequoia backend, or agent mapping need focused encryption/agent
regression coverage. Test isolation details are authoritative in [`../../tests/AGENTS.md`](../../tests/AGENTS.md).
