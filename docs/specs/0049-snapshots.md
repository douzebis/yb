<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0049 — Snapshots

**Status:** draft
**App:** libyubiblob (yb-core underneath)
**Implemented in:** <!-- YYYY-MM-DD, fill after implementation -->

## Problem

Every libyubiblob call reads and sanitizes the whole store: about 0.95 s
on a YubiKey 5 with 32 objects, whatever the question.  PIV reads an
object only whole, and sanitization needs every object (the newer of two
copies, complete chains, invariants 0001 and 0003), so a call cannot
read less.  But a client asking several questions pays for each one:

- KeePassYB opening a vault (spec 0047's log): the listing, the store
  kind and the read are three whole-store reads (2.9 s); unlocking
  checks the listing again (0.96 s).
- Saving: a listing, the store, and a listing after it: three
  whole-store reads.

And no client can tell that a blob changed on the YubiKey since it read
it: the last writer wins silently.

## Goals

- **A session can keep a snapshot:** the store as its last whole read
  under the lock (spec 0048) found it, updated by its own writes.
  Questions are answered from it with no card access.  The client
  decides when to refresh it.
- **A snapshot never plans a write:** every write still locks, reads the
  whole store and plans from that read (spec 0048), and refreshes the
  snapshot on the way, at no extra cost.
- **Conflicts can be detected:** a store or a removal can ask to fail
  if the blob changed since the snapshot.
- **General, additive API:** a session opened without the new flag
  behaves as in libyubiblob 0.3.
- A new invariant, 0021, with regression tests.

## Non-goals

- **A cache shared between sessions or processes,** or kept on disk.
  The snapshot belongs to one session, in that process's memory.
- **Fresher answers than the snapshot:** another program's later write
  is seen at the next refresh or write.
- **Reading part of the store:** sanitization needs all of it.
- **Writes that check only the objects they touch** (an optimistic
  write planned from the snapshot).  Studied and set aside: after
  another program's interrupted replacement of the same blob, such a
  write can produce a second copy of the blob with the same age as the
  other program's, and which copy survives then depends on object order,
  not on which write came last (see "Set aside").  A save already waits
  for a touch; the whole read costs about 0.8 s more than the check
  would.
- **A change to the store's format.**
- **KeePassYB's use of it:** spec 0050.
- **The yb CLI:** a command reads the store once already; unchanged.

## Specification

### S1. Snapshot sessions

- **`YUBIBLOB_OPEN_SNAPSHOT`,** a new `yubiblob_open` flag: the session
  reads and sanitizes the whole store at open, under the lock (this
  read replaces today's separate probe, and fails as the probe does),
  and keeps it.
- **What the session keeps:** the sanitized store.  It is owned by the
  session, opaque to the client, and overwritten (zeroized) when
  replaced or when the session closes; at most the store's size (32
  objects of about 3 KB).
- **`yubiblob_refresh(session)`,** a new call: a whole read under the
  lock, replacing the snapshot.  In a session opened without the flag,
  it does nothing and succeeds.
- **The serial:** the session is bound to its YubiKey's serial, as
  today; a refresh or a write that finds another YubiKey fails with
  `YUBIBLOB_ERR_NO_DEVICE` and keeps the snapshot.

### S2. Questions in a snapshot session

`yubiblob_list`, `yubiblob_stat`, `yubiblob_store_info` and
`yubiblob_fetch_unencrypted` send nothing to the card: they answer from
the snapshot, as of its last refresh or write.

`yubiblob_fetch` (the full check) takes the blob's stored bytes from the
snapshot; the PIN, the touch and the management-key check against the
card (invariant 0015) happen as today.

### S3. Writes in a snapshot session

`yubiblob_store` and `yubiblob_remove` follow spec 0048 S2, with two
additions:

1. **Before anything else,** the snapshot answers whether the blob can
   fit; if not, the write fails with `YUBIBLOB_ERR_STORE_FULL` and no PIN
   or touch is asked.  (The whole read under the lock decides; this only
   avoids asking for a touch in vain.)
2. **The whole read under the lock replaces the snapshot,** whatever the
   outcome; after a successful write, the snapshot is updated with what
   was written.

So a save from a snapshot session costs one whole read and the writes,
where a client of 0.3 pays a listing, the store's read, and a listing
after it.

### S4. Detecting a conflict

- **`YUBIBLOB_STORE_IF_UNCHANGED`,** a new `yubiblob_store` flag, and
  the same for `yubiblob_remove` (Q1): the write fails with
  **`YUBIBLOB_ERR_CHANGED`** (21), having written nothing, if the blob
  in the whole read under the lock differs from the blob in the snapshot
  before that read: rewritten, removed, or created since.  "Differs"
  compares the blob's head objects, bytes and age.  The snapshot is
  refreshed, so the client can fetch the current version and decide
  (merge, overwrite, give up).
- **Exact,** because both sides are whole reads made under the lock:
  `CHANGED` means another write of this blob took the lock between this
  session's last refresh or write and this write.
- Without the flag, the last writer wins, as today; nothing else is
  ever lost (invariant 0020).
- In a session opened without `YUBIBLOB_OPEN_SNAPSHOT`, there is no
  snapshot to compare with: `YUBIBLOB_ERR_INVALID_ARGUMENT`.

### S5. The API and the release

- `yubiblob.h`: the flags, `yubiblob_refresh`, `YUBIBLOB_ERR_CHANGED`,
  with their documentation; `yubiblob_last_error` names the change.
- Released with spec 0048 as libyubiblob **0.4.0**; the C example and
  the C API tests (spec 0039) cover a snapshot session.
- `yubiblob_abi_version` is bumped if Q1 changes `yubiblob_remove`.

### Set aside: writes that check only what they touch

For a later spec, the reasoning so far:

- **The idea:** plan a write from the snapshot; under the lock, read
  only object 0, the objects to be written, the old copy and the
  cleanup; write if they are as in the snapshot, else fall back to a
  whole read.  About 0.15 s instead of 0.95 s for a small blob.
- **What it catches:** another write of the same blob that completed
  (it freed the old copy); another blob in an object to be written or
  freed; a reformat (object 0).
- **What it misses:** program A replaces blob X and is interrupted after
  writing its new head, before freeing the old copy; the store then
  holds two complete copies, and every reader keeps A's, the newer.
  Session B, whose snapshot predates A's write, plans its write of X
  with an age from that snapshot, into an object A did not use; the
  check passes (the old copy is still there).  B's copy and A's may
  then have the same age, and two copies of a blob with the same age
  break the rule that the later write is the newer copy (invariant 0020,
  G6): which one survives depends on object order.  If anyone read A's
  version before B's write, either outcome contradicts a serial order
  (B's confirmed save lost, or A's observed change overwritten despite
  `IF_UNCHANGED`).
- **Not a fix:** an age on empty objects (age 0 is what marks an object
  empty: a format change; and B never reads the object A used); a
  store-wide counter (an extra write on every store, and older yb
  versions would not keep it).
- A solution must ensure that a write's copy is newer than every copy
  of the blob on the card without reading the whole card.

## Invariants

- **0021 — A Snapshot Never Plans a Write**
  (`docs/invariants/0021-a-snapshot-never-plans-a-write.md`): a write in
  a snapshot session plans from a whole read made under its lock, never
  from the snapshot; and `YUBIBLOB_ERR_CHANGED` is returned exactly when
  another write of the blob took the lock since the session's last
  refresh or write.
  - Regression tests (emulated backend), between a snapshot and a
    write, another session:
    - stores a blob into an object the snapshot shows free: the write
      lands elsewhere, the other blob is intact;
    - replaces the same blob: with `IF_UNCHANGED`, `CHANGED` and nothing
      written; without, the write lands and is the blob's content;
    - removes the same blob; creates a blob of the same name; reformats
      the store; fills it (`STORE_FULL`, nothing written);
    - each fails if the write plans from the snapshot.
  - A snapshot session's questions send no command to the card (the
    emulated backend counts them).
  - **Spec 0048's concurrency fuzzer, extended:** clients mix snapshot
    sessions and plain ones; snapshot clients refresh at random, and
    store or remove with or without `IF_UNCHANGED`; the log records, for
    each snapshot operation, the lock position of the snapshot it used.
    The oracle: a snapshot question returns the model's state at that
    position; `CHANGED` is returned exactly when the model's blob
    changed between that position and the write's; the final contents
    equal the model's.

## Open questions

- **Q1: `yubiblob_remove` has no `flags` argument** (name and PIN only).
  Add one (an ABI break: `yubiblob_abi_version` bumped), or a new
  `yubiblob_remove_ext`?  Proposal: break it now, while KeePassYB is the
  only known client.

## References

- [spec 0048](0048-one-writer-at-a-time.md): the lock, serializable
  operations, the guarantees of every operation.
- [spec 0039](0039-c-api.md): libyubiblob.
- [spec 0044](0044-reading-unencrypted-blobs-without-the-pin.md):
  `yubiblob_fetch_unencrypted`.
- [spec 0047](0047-keepassyb-and-a-slow-yubikey.md): the measurements.
- [spec 0050](0050-keepassyb-snapshots-and-automatic-saves.md): the first
  client.
