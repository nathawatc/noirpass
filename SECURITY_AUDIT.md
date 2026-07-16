# Noirpass Security Audit

## Iteration: D-Bus sender identity and session ownership

- Date: 2026-07-16
- Status: complete for selected subsystem only
- Classification: **CONFIRMED — High, Medium, and Low**, fixed
- Attacker: malicious process on same user's session bus
- Scope: D-Bus sender identity, session ownership, session close, and
  disconnect cleanup
- Explicitly not reviewed: storage, filesystem, recipient handling,
  OpenPGP, session cryptography internals, logging, activation, sandboxing,
  dependencies, and other audit areas

No claim that Noirpass is completely secure.

## Safety property reviewed

Session handles and transport ciphers created by one D-Bus client must not be
usable or closable by another client. Missing sender identity must fail closed.
Sessions must disappear on close or owner disconnect. Closed, unknown, and
pre-restart paths must not regain authority. Session allocation must never
overwrite existing map state or leave map/object-server registration divergent.

Specification basis: [Secret Service sessions][sessions-spec] are bound to
calling application's D-Bus connection, close automatically on disconnect, and
drop all session-specific negotiation state. Invalid session arguments use
[`org.freedesktop.Secret.Error.NoSession`][errors-spec]. Calls to removed object
paths are rejected by D-Bus as `org.freedesktop.DBus.Error.UnknownObject`.

[sessions-spec]: https://specifications.freedesktop.org/secret-service/latest/sessions.html
[errors-spec]: https://specifications.freedesktop.org/secret-service/latest/errors.html

## Files and execution paths inspected

- `src/service.rs`: `OpenSession` records `Header::sender`; session registry;
  random path allocation; `GetSecrets`; incoming and outgoing secret/session
  conversion.
- `src/collection.rs`: `Collection.CreateItem` to incoming session lookup.
- `src/item.rs`: `Item.GetSecret` and `Item.SetSecret` to session lookup.
- `src/session.rs`: `Session.Close` to session removal.
- `src/main.rs`: `NameOwnerChanged` watcher to
  `remove_sessions_owned_by` and object unregistration.
- `tests/integration.rs`: private D-Bus, ephemeral store, generated test
  certificate, isolated agent, existing plain/DH/restart/disconnect scenarios.

Complete vulnerable paths:

```text
OpenSession
  -> Header::sender stored in SessionEntry.owner

attacker Item.GetSecret / Service.GetSecrets
  -> ServiceState::ciphertext_to_secret
  -> ServiceState::session_cipher(path)
  -> cipher returned without checking SessionEntry.owner

attacker Item.SetSecret / Collection.CreateItem
  -> ServiceState::secret_to_ciphertext
  -> ServiceState::session_cipher(path)
  -> cipher returned without checking SessionEntry.owner

attacker Session.Close
  -> ServiceState::remove_session(path)
  -> session removed without checking SessionEntry.owner
```

Disconnect cleanup path was already ownership-aware:

```text
NameOwnerChanged(unique name loses owner)
  -> remove_sessions_owned_by(unique name)
  -> remove matching registry entries
  -> unregister matching Session objects
```

## Hypothesis and verification

Hypothesis: second connection can reuse or close first connection's sequential
session path because owner is recorded but never checked after creation.

Second hypothesis: daemon-local counter restarts at zero, so same live bus
connection can retain `/session/s1` across daemon restart and have stale handle
revived when replacement daemon allocates its first session.

Third hypothesis: random candidate generation outside session lock followed by
unconditional `HashMap::insert` can overwrite existing entry. Ignoring
`ObjectServer::at`'s `false` result and not rolling back its `Err` result can
leave session map and D-Bus registry inconsistent.

Expected safe behavior: exact bus-assigned unique-name match on every session
lookup and removal; absent identity rejected; unknown and foreign handles both
fail as `NoSession` where session arguments are used.

Verification used live daemon on private D-Bus with two distinct connections,
temporary store, generated certificate, isolated GnuPG home, and dummy secret.
Before production fixes, first regression reached `Item.GetSecret` and failed
because second connection successfully reused first connection's plain session.
Earlier isolated reproduction also proved second connection could close first
connection's session. Restart regression then proved old and replacement paths
were both `/session/s1`. Deterministic allocation regression then proved second
registration returned occupied `/session/s41` and replaced first entry. No
dummy plaintext appeared in assertion output.

## Confirmed issue

**High: cross-client session-handle authorization bypass.** Same-user malicious
D-Bus client could use another client's plain session to receive secret
plaintext, use another client's DH session state, submit secret data through a
foreign session, or close that session. This violates documented client/session
isolation. Severity accounts for same-user attacker already having broad desktop
access, but direct Secret Service cross-client disclosure remains authorization
bypass.

**Medium: stale session-handle revival after daemon restart.** Session IDs came
from a per-process counter. A client connection surviving daemon restart could
retain old path and gain access to replacement session created by same bus
sender when counter reused that path. Exploit requires restart plus same owner
connection, but violates close/restart invalidation.

**Low: session-path collision overwrote registry state.** Random allocation did
not check map occupancy under lock. Collision replaced existing owner/cipher
before D-Bus registration, and `ObjectServer::at` failure left orphan map state.
128-bit collision probability is negligible, but invariant failure was real and
could also be forced by future deterministic generators or concurrent callers.

## Fix applied

- Session owner is now mandatory, not optional.
- `OpenSession` rejects missing D-Bus sender identity.
- Session cipher lookup requires exact owner match.
- `GetSecrets`, `Item.GetSecret`, `Item.SetSecret`, and
  `Collection.CreateItem` pass current message sender into authoritative lookup.
- Session removal requires exact owner match; foreign `Close` leaves owner
  session intact.
- Foreign and nonexistent handles share `NoSession` behavior, avoiding a new
  session-existence distinction.
- Existing `NameOwnerChanged` cleanup remains keyed by stored unique name.
- Peer-to-peer unit test now verifies missing sender fails closed for plain and
  DH session creation.
- Session object paths now contain random 128-bit numeric IDs instead of a
  restart-reset counter, preventing practical stale-path reissue while retaining
  existing opaque object-path shape.
- Candidate generation, occupancy check, and insertion now occur under one
  session-map lock using `Entry::Vacant`; collisions retry without overwrite.
- Allocation stops after 128 collisions instead of looping forever.
- Synchronous map lock is released before `ObjectServer::at().await`.
- `ObjectServer::at` returning `false` or `Err` rolls back reserved map entry;
  `Err` also triggers best-effort D-Bus object removal because zbus can insert
  interface before later signal emission fails.
- Successful object registration rechecks owner reservation. Disconnect during
  registration removes newly registered object and fails opening call.

No storage format, cryptographic protocol, ciphertext, recipient, or filesystem
behavior changed.

## Regression tests

- `s6b_cross_client_session_rejected` creates distinct bus senders and verifies:
  owner can use session; attacker cannot use it through `Item.GetSecret`,
  `Item.SetSecret`, `Collection.CreateItem`, or `Service.GetSecrets`; attacker
  cannot close it; owner can still use and close it afterward; second close
  returns `UnknownObject`; closed path used as method argument returns
  `NoSession`.
- `disconnect_unregisters_owned_session` drops opening connection without
  calling `Close` and verifies another connection observes exact
  `UnknownObject` after `NameOwnerChanged` cleanup unregisters session object.
- `stale_session_path_is_not_reissued_after_restart` keeps one client connection
  across daemon restart and verifies stale path remains `NoSession` before and
  after opening replacement session; direct close on absent stale object returns
  `UnknownObject`; replacement path differs.
- Unknown path checks distinguish absent D-Bus object (`UnknownObject`) from
  invalid session method argument (`NoSession`) by exact error name.
- Session-registry unit checks verify foreign lookup and removal fail.
- Missing-sender peer-to-peer unit checks verify fail-closed session creation.
- Existing idle-exit integration test verifies disconnect cleanup still reaps
  abandoned sessions.
- Deterministic unit test forces occupied first ID, verifies retry, unchanged
  original plain cipher/owner, distinct replacement DH cipher/owner, and two
  live entries.
- Concurrent unit test starts two registrations with same first ID and verifies
  distinct paths and owner-preserving entries.
- Bounded-collision unit test verifies exactly 128 attempts, failure, and no
  mutation of occupied entry.
- Object-server tests force both `at() == false` and actual `at()` error after
  partial interface insertion; map rollback and D-Bus cleanup are verified.

## Commands run

- `nix develop -c cargo test --test integration end_to_end -- --nocapture`
  before fix: **failed as intended** at unauthorized `Item.GetSecret`.
- Same targeted command after fix: **passed**, 1 passed.
- `nix develop -c cargo check --tests`: **passed**.
- First `nix develop -c cargo test` after fix: **failed**, 52 passed and 1
  failed; existing sender-less peer-to-peer test expected session creation.
  Test was corrected to assert required fail-closed behavior.
- Stale-path targeted test before fix: **failed as intended**; old and new paths
  were both `/session/s1`.
- Stale-path targeted test after fix: **passed**, 1 passed.
- Collision regression before allocation fix: **failed as intended**; second
  registration returned occupied `/session/s41` instead of `/session/s42`.
- Five targeted allocation/rollback tests after fix: **passed**.
- Final `nix develop -c cargo test`: **passed**, 58 unit tests, 9 integration
  tests, and 0 doc tests failed.
- `nix develop -c cargo fmt --check`: initially reported formatting differences;
  `nix develop -c cargo fmt` applied them. Final check: **passed**.
- `nix develop -c cargo clippy --all-targets --all-features -- -D warnings`:
  **passed**, zero warnings.
- `nix develop -c cargo build --release`: **passed**.
- `nix develop -c cargo test` with two separate positional filters:
  **failed before tests ran** because Cargo accepts one filter; replaced with
  valid scoped command below.
- `nix develop -c cargo test service::tests::`: **passed**, 4 passed.
- `git diff --check`: **passed**.

## Adversarial diff review

- Every changed production line traces to sender authorization, path non-reuse,
  atomic allocation, or rollback.
- All session-consuming D-Bus paths use same owner-checking registry methods.
- Owner comparison uses bus-assigned unique names, not caller-controlled method
  arguments or well-known names.
- Unauthorized close check and removal occur under one registry lock.
- Missing sender cannot create or access client-owned session state.
- No secret value was added to logs, errors, panic text, filenames, metadata,
  or test failure output.
- No persistence, crypto, agent, filesystem, or activation behavior changed.
- Existing disconnect reaping remains intact. Restart invalidation now has
  direct regression coverage.
- Working tree contains only intended files for this finding and audit record.

## Remaining uncertainty

This iteration did not review unrelated subsystems. Session algorithms were
exercised for compatibility, but cryptographic construction and payload
validation were outside scope. Random 128-bit collisions now retry; 128
consecutive occupied candidates fail `OpenSession` without mutation. Correctness
assumes pinned zbus `ObjectServer::remove` keeps removing local interface before
reporting signal-delivery failure; regression test exercises that ordering.
Same-user process may observe or manipulate other desktop-session state outside
Noirpass's guarantees.
