# Shared Service State

Own request admission, activity/shutdown, lifecycle guards, worker reservations, transport cipher
registry, secret encoding, and temporary storage under `src/service/state/`. Public D-Bus object
registration, sender-disconnect cleanup, and signals remain in [`../AGENTS.md`](../AGENTS.md).

## Mutation Ordering

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

## Admission and Workers

Every Noirpass application method and property handler holds the activity guard for its complete
lifetime. Admission, active-call count, completion time, and shutdown selection share one activity
state. Once shutdown is selected, new application handlers fail. Admitted owned tasks carry
their request scope into internal workers and signal property reads so draining can finish. Only a
request belonging to the same ServiceState may bypass closed internal admission. Idle shutdown
requires no sessions, no temporary items, and no active application handler.

Session negotiation, searches, secret retrieval, and mutations additionally reserve nonblocking
request capacity: 64 active or queued requests and 32 MiB of combined D-Bus-encoded input payload.
Check capacity before copying arguments or spawning owned work; reject exhaustion with
`org.freedesktop.DBus.Error.LimitsExceeded`. Owned tasks retain both reservations through
publication after caller cancellation. A started blocking worker retains request count and byte
reservations until completion even when its async waiter is cancelled. Property reads and internal
worker/publication activity do not reserve request capacity, so saturation cannot interrupt an
admitted mutation's required signals.

Encryption, persistent reads/writes (including namespace metadata), and agent decryption share four
blocking worker slots.
Reserve persistent capacity before acquiring an owned lifecycle guard; temporary mutations reserve
no worker capacity. The worker retains capacity, activity, and any mutation guard after caller
cancellation. Never wrap an untracked nested `spawn_blocking`
operation inside this boundary. Recheck session ownership after queue admission and before agent
decryption, then again when encoding the result. Bulk retrieval admits at most four item tasks per
request and preserves input order when merging repeated paths.
Persistent retrieval keeps the filesystem read, agent decryption, and transport encoding inside
one worker reservation. Waiting tasks retain identifiers only; never queue already-read ciphertext
between separate read and decrypt workers. Reject a persistent bulk item's plaintext exceeding the
response limit before allocating its transport value; individual `GetSecret` remains available.
Bound retained bulk responses to 8 MiB of encoded dictionary entries, including the array header
and conservative alignment padding. Measure without copying plaintext, refund the previous entry
when a repeated path is replaced, and reject excess with `org.freedesktop.DBus.Error.LimitsExceeded`.
Return no partial response; clients may retry with fewer items.
All admitted item, collection, and alias mutations run as owned tasks so cancellation cannot separate
a completed commit from object publication or required signals.

## Temporary Collection

The reserved `session` alias resolves to `/org/freedesktop/secrets/collection/session` before any
persisted alias. Temporary item metadata, aliases, and zeroizing secret values remain process-local;
they never enter redb or ciphertext files. Temporary items prevent idle shutdown and disappear on
deletion or daemon exit. Enforce item, attribute, string, and aggregate payload limits before mutation;
rejected replacements retain the existing item. Runtime aliases must also remain bounded.
