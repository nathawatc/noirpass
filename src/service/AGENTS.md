# Service Ownership

Own Secret Service D-Bus behavior under `src/service/`, including service state, object
registration, collections, items, and sessions.

Standard Secret Service D-Bus compatibility is core product scope, not manager functionality. Keep
collections, aliases, sessions, item properties, and required signals as protocol surface even when
no Noirpass CLI command manages them. Rust module paths remain implementation details unless
explicitly documented otherwise.

## Object Model and D-Bus Boundary

Serve the Secret Service tree at:

```text
/org/freedesktop/secrets                                  Service
/org/freedesktop/secrets/collection/<id>                  Collection
/org/freedesktop/secrets/collection/<id>/<item-id>        Item
/org/freedesktop/secrets/session/s<n>                     Session
/org/freedesktop/secrets/aliases/<name>                   Collection alias
```

- Treat every caller, sender identity, object path, variant, algorithm, length, and object lookup as
  hostile. Validate at the D-Bus boundary before touching persistent state or secret transport.
- Bind sessions to the caller's unique bus sender name. Never substitute PID, executable name, or
  another reusable identity. Foreign sessions fail closed for secret access, item creation/update,
  secret retrieval, and close operations.
- Subscribe to `NameOwnerChanged` and remove all sessions owned by vanished unique senders; clients
  often do not call `Session.Close`. Complete the subscription before publishing the well-known
  service name. Session registration runs as an owned task; after object registration, check
  `NameHasOwner` on message-bus connections to catch disconnects processed before map insertion.
  A false result or failed presence query removes both the session map entry and D-Bus object.
- Service, Collection, Item, Session, and alias objects must expose only state authorized by their
  owning store/session boundary. Alias-backed collections resolve their persisted target per call;
  valid alias paths are registered and invalid-path aliases remain usable through alias methods but
  do not receive an object path.
- D-Bus errors are the public boundary: map internal failures without leaking secret bytes or
  treating malformed client data as an internal panic.

## Lifecycle, Registration, and Signals

Serialize each mutation across persistent state, object-server registration/removal, and signals.
The lifecycle guard must prevent clients observing half-applied state:

Item mutations and collection relabeling hold a collection mutex plus a shared namespace guard
through commit, registration/removal, and signals. Collection creation/deletion and alias changes
hold the exclusive namespace guard and reserve worker capacity before acquiring it. Acquire
persistent worker capacity before collection guards;
acquire the collection mutex before the shared namespace guard. Never upgrade a shared guard to
exclusive or acquire a collection guard while holding the exclusive namespace guard. Re-resolve
alias-backed targets under the guard and reject a changed target before mutation. Reclaim unused
collection lock entries rather than retaining every historical item/collection identifier.

- Register collections/items on creation and remove them on deletion.
- Remove contained item objects with a deleted collection.
- Register an alias object when `SetAlias` creates a valid path; remove it when cleared or when its
  target collection is deleted. Registration must match the persisted alias table.
- Register the complete persisted object tree before requesting `org.freedesktop.secrets`; activation
  clients must not see a partial tree.
- Emit `PropertiesChanged` for aggregate `Service.Collections` and `Collection.Items` whenever their
  cached values change, plus the required created/deleted signals. Clients may cache these values.

Every Noirpass application method and property handler holds the activity guard for its complete
lifetime. Admission, active-call count, completion time, and shutdown selection share one activity
state. Once idle shutdown is selected, new application handlers fail instead of entering a closing
service. Idle shutdown requires no sessions, no temporary items, and no active application handler.

Encryption, persistent reads/writes (including namespace metadata), and agent decryption share four
blocking worker slots.
Reserve persistent capacity before acquiring an owned lifecycle guard; temporary mutations reserve
no worker capacity. The worker retains capacity, activity, and any mutation guard after caller
cancellation. Never wrap an untracked nested `spawn_blocking`
operation inside this boundary. Recheck session ownership after queue admission and before agent
decryption, then again when encoding the result. Bulk retrieval admits at most four item tasks per
request and preserves input order when merging repeated paths.
All admitted item, collection, and alias mutations run as owned tasks so cancellation cannot separate
a completed commit from object publication or required signals.

## Temporary Collection

The reserved `session` alias resolves to `/org/freedesktop/secrets/collection/session` before any
persisted alias. Temporary item metadata, aliases, and zeroizing secret values remain process-local;
they never enter redb or ciphertext files. Temporary items prevent idle shutdown and disappear on
deletion or daemon exit. Enforce item, attribute, string, and aggregate payload limits before mutation;
rejected replacements retain the existing item. Runtime aliases must also remain bounded.

## Always-Unlocked Contract

Noirpass exposes no independent lock state; access control remains GPG-agent policy.

```text
Locked properties are always false.
Unlock returns requested objects as already unlocked.
Lock returns no successfully locked objects.
No Prompt objects are exposed; prompt path is /.
```

`Lock` and `Unlock` return `/` as their prompt path, and unknown `ReadAlias` also returns `/`. Keep
these semantics internally consistent across Service, Collection, and Item implementations.

Changes to object lifecycle, sender ownership, signals, admission, or errors require real object-
server/client integration coverage on a private test bus. Test isolation is owned by
[`../../tests/AGENTS.md`](../../tests/AGENTS.md); at-rest durability is owned by
[`../store/AGENTS.md`](../store/AGENTS.md).
