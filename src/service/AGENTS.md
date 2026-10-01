# Service Ownership

Own Secret Service D-Bus behavior under `src/service/`, including service state, object
registration, collections, items, and sessions.

Before changing handler admission, shutdown, mutation locking, workers, transport encoding, or
temporary storage, read [`state/AGENTS.md`](state/AGENTS.md). It owns shared-state invariants for
all service handlers, including the child collection/item modules.

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
- Limit transport sessions to 64 per unique sender and 1024 in total. Check both limits atomically
  with map insertion and return `org.freedesktop.DBus.Error.LimitsExceeded` without publishing an
  object. Closing sessions or reaping a disconnected owner releases capacity.
- Service, Collection, Item, Session, and alias objects must expose only state authorized by their
  owning store/session boundary. Alias-backed collections resolve their persisted target per call;
  valid alias paths are registered and invalid-path aliases remain usable through alias methods but
  do not receive an object path.
- D-Bus errors are the public boundary: map internal failures without leaking secret bytes or
  treating malformed client data as an internal panic.

## Lifecycle, Registration, and Signals

- Register collections/items on creation and remove them on deletion.
- Remove contained item objects with a deleted collection.
- Register an alias object when `SetAlias` creates a valid path; remove it when cleared or when its
  target collection is deleted. Registration must match the persisted alias table.
- Register the complete persisted object tree before requesting `org.freedesktop.secrets`; activation
  clients must not see a partial tree.
- Emit `PropertiesChanged` for aggregate `Service.Collections` and `Collection.Items` whenever their
  cached values change, plus the required created/deleted signals. Clients may cache these values.

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
