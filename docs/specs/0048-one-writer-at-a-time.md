<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0048 — One Writer at a Time

**Status:** implemented
**App:** yb (yb-core, yb, libyubiblob)
**Implemented in:** 2026-10-18

## Problem

A write reads the store, plans where the new copy goes, then writes
objects one by one.  Each PIV operation opens its own PC/SC connection,
in shared mode (`PcscSession::open`, `piv/session/transport.rs`;
`HardwarePiv::write_object`, `piv/hardware.rs`), and nothing keeps other
programs away from the card between the read and the last write.

Another program writing in that window (a second `yb`, KeePassYB, any
libyubiblob client) can make the plan wrong:

- **The free objects:** yb writes its new copy into objects its read saw
  free; another writer may have put its blob there meanwhile, and yb
  overwrites it.  Nothing reports it.
- **The old copy:** yb frees the objects of the old copy after writing
  the new one; another writer may have reused them meanwhile, and yb
  erases its data.
- **The cleanup:** yb first resets the objects its read found
  unreachable (leftovers, spec 0038); one of them may be another
  writer's chain in the middle of being written.

A read alone is not safe either: it reads the objects one by one.  A
reader may see an object free, then a writer puts a blob's new copy
there and frees the old copy, then the reader reaches the old copy's
objects and finds them free too: the blob, present all along, is missing
from what it read ("not found").

The window lasts from the read to the last write: about a second for a
small blob, several for a large one.  No spec or invariant mentions
concurrent writers, and invariant 0001 (interrupted writes lose nothing)
assumes a single writer.

## Goals

- From its read of the store to its last object write, a yb write has
  the YubiKey to itself: another PC/SC client's commands wait until it is
  done.
- A read of the whole store holds the lock too, so it sees the store as
  it was between two writes.
- So yb's operations are **serializable:** their outcome is that of
  running them one at a time, in the order they took the lock.
- Every command that writes store objects does so: `yb store`, `yb rm`,
  `yb format`, the repairs done after a write, the management-key
  commands (spec 0027), and libyubiblob's `yubiblob_store` and
  `yubiblob_remove`.  The implementation lists every caller of
  `PivBackend::write_object`.
- Nothing inside the lock waits for the user: PIN entry, the signature
  and the post-quantum touch come before it.
- The store's format, the write order and invariant 0001 are unchanged.
- A new invariant, 0020, with regression tests.

## Non-goals

- **Snapshots:** spec 0049.
- **Detecting a lost update** (another program replaced the same blob
  between my read and my write): the last writer still wins; spec 0049
  adds the detection.
- **Programs that write the store without yb** (S5), and older yb
  versions, which do not take the lock.
- **FIDO2 traffic** (USB HID): it cannot be locked, and needs no lock;
  it does not write store objects.

## Specification

### S1. The lock

PC/SC's card lock: `SCardBeginTransaction` on a connection, then every
command of the write on that connection, then `SCardEndTransaction`
(leave the card powered).  While it is held, other connections' commands
wait; they are not refused.

- **One connection for the whole write.**  The lock belongs to a
  connection, so the read, the management-key authentication and every
  object write use it.  `PivBackend` gains a scoped exclusive mode, e.g.
  `fn exclusive(&self, reader: &str) -> Result<ExclusiveGuard>`; while
  the guard lives, the backend's PIV calls for that reader, from the
  thread holding it, go through the locked connection.
- **The management key is authenticated once** per locked connection,
  not once per object as today.
- **The emulated and virtual backends** implement the same mode with a
  per-reader lock, so that tests exercise it.
- **Release:** dropping the guard ends the transaction, on success and on
  error.  A crash, or the YubiKey pulled out, ends it too (PC/SC releases
  a dead connection's lock).
- **Waiting:** a write that finds the card locked waits, as other PC/SC
  clients do (see Open questions).

### S2. The order of a write

1. **Look first:** lock, read and sanitize the store, unlock (a
   snapshot session uses its snapshot instead, spec 0049); learn the
   store's kind (which PIN to ask) and check that the blob fits.  A blob
   that does not fit fails here with nothing written and no PIN asked
   (invariant 0004).
2. **Protect, without the lock:** the signature (legacy store: PIN and
   ECDSA in the slot) or the seal (post-quantum store: FIDO2 PIN and
   touch, which also gives the management key).  Neither depends on
   where the blob lands: the signature covers the metadata and the
   content (`signed_digest_v2`), the seal the name, sizes, mtime, salt
   and content (`meta_bytes`, `checksum`).
3. **Lock.**
4. **Read and sanitize the whole store again**, and plan from that
   read: the cleanup, the free objects, the ages, the old copy.  If the
   blob no longer fits, fail with nothing written (the protection is
   discarded).
5. **Check the management key** (invariant 0015), then **write** in
   today's order: the cleanup, the new copy's continuation chunks, its
   head, then the old copy freed.
6. **Unlock.**

`yb rm` and the other writing commands follow the same pattern: what
needs the user first, then lock, read, write, unlock.

**A read of the whole store** (every command's load, libyubiblob's
calls) takes the lock for the read, and releases it before anything
that waits for the user (the PIN and touch of a full-check fetch).

**Cost:** a CLI write reads the whole store twice (steps 1 and 4, about
0.95 s each on a YubiKey 5 with 32 objects); a snapshot session's write
once (spec 0049).  Step 4 is the one that counts: the write is planned
from a read made under its own lock, never from an earlier one.

### S3. Platforms

- **Linux (pcsc-lite) and macOS (CryptoTokenKit's PC/SC):**
  transactions are supported.
- **Windows:** a transaction with no command for about 5 seconds resets
  the card.  A write sends commands continuously, and nothing in the
  locked part waits for the user (S2), so this does not happen.  A test
  on Windows waits for a Windows YubiKey (spec 0043 has none).

### S4. Concurrency fuzzing

A seeded test that runs random concurrent operations and checks the
outcome against a serial model.

- **Clients:** several sessions on the emulated backend (the lock in
  force), each running a random sequence: store (sizes from a few bytes
  to the largest blob that fits, about 50 KB), replace, remove, list,
  fetch.  Names come from a small set, so that clients collide.
- **Reproducible interleaving:** the emulated backend calls a scheduler
  before each card command; a scheduler seeded by the test chooses which
  client goes on.  A failing seed replays the same interleaving.
  Pauses are also injected at the points where yb waits (between
  planning and locking, between object writes).
- **Interruptions:** at random, a write is cut off (the card "pulled
  out" between two object writes).
- **The log:** each operation records, under the lock, its position in
  the lock order and its outcome.
- **The oracle:** a model (name → content) replays the operations in
  lock order:
  - a store or remove that succeeded applies; one that failed (store
    full) has no effect, and the model agrees it did not fit;
  - an interrupted write leaves the blob with its old or its new
    content (invariant 0001): either is accepted, and the model follows
    what the next read shows;
  - every list and fetch returns the model's state at its position;
  - at the end, the store's blobs equal the model's.
- **Runs:** a fixed set of seeds in `cargo test` (seconds); a long run
  with random seeds in a scheduled CI job, printing the seed of a
  failure.
- **Without the lock** (a test-only switch), the fuzzer finds a
  violation within its fixed seeds: this shows the test can fail.

### S5. What every operation guarantees, concurrent or not

Three rules make the whole argument:

1. **Every whole-store read is made under the lock,** so it sees the
   store as it was between two writes, never in the middle of one.
2. **Every write locks, reads the whole store, plans from that read,
   writes, and unlocks.**  Writes happen one at a time, each planned from
   the store as it really is.
3. **A snapshot (spec 0049) answers questions; it never plans a write.**

From them, every operation, even with several programs at once,
guarantees:

- **G1. Serializable** (invariant 0020): the outcome of concurrent
  operations is that of running them one at a time, in the order they
  took the lock.  An operation that did not complete (a crash, the
  YubiKey pulled out) either took effect or did not, as if it had run
  alone (G2).
- **G2. Interrupted writes lose nothing** (invariant 0001): a write is
  never interleaved with another, so an interruption leaves the state
  invariant 0001 describes (each blob old or new, the others
  unchanged); every later read resolves it by sanitization, and the next
  write, planning from a whole read, frees the leftovers.
- **G3. Only complete blobs are visible** (invariant 0003): reads see
  the store between writes (rule 1), and sanitization keeps only
  complete chains.
- **G4. Reading never writes** (invariant 0002): reads take the lock,
  and only read.
- **G5. A write that does not fit writes nothing** (invariant 0004):
  decided from the whole read under the lock, before any object write.
- **G6. The later write is the newer copy:** a write's copy gets an
  age above every age on the card (the store's age counts every object
  read, leftovers included), because it is taken from a whole read under
  its lock.  So two copies of a blob never share an age, and when an
  interrupted replacement leaves two copies, the one sanitization keeps
  is the later write's.  (A write planned from a snapshot could break
  this; spec 0049 "Set aside".)
- **G7. The last writer wins, unless it asked otherwise:** without
  spec 0049's `IF_UNCHANGED`, a store replaces whatever copy is there;
  with it, it fails if another write of the blob came since its
  snapshot.

**Who must go through yb.**  These guarantees hold when every program
that writes the store's objects does it through yb-core of this version
or later: the yb command, libyubiblob 0.4 or later (and so KeePassYB
built on it), or a Rust program using yb-core.  They do not hold when:

- an older yb or libyubiblob writes the store: it takes no lock;
- a program writes the store's PIV objects itself (e.g. `ykman piv
  objects import`, `yubico-piv-tool -a write-object`): it knows neither
  the lock nor the write order.

Programs that only read, or that use other PIV objects and keys (the
certificates and keys outside the store), do not harm the store.

### S6. Release notes and commit message

The implementation's commit message and the release notes say plainly:
- **before:** yb did not support concurrent access: two programs using
  the same YubiKey at once (two `yb` commands, `yb` and KeePassYB) could
  lose a blob or read a store in the middle of a write;
- **now:** yb supports it: operations are serializable (G1–G7), for
  programs going through yb of this version or later; older versions
  must not write a store that newer ones use at the same time.

## Invariants

- **0020 — yb's Operations Are Serializable**
  (`docs/invariants/0020-operations-are-serializable.md`): from its
  read of the store to its last object write, a yb write is the only
  PC/SC client whose commands reach the YubiKey; a whole-store read is
  also made under the lock; every write plans from a whole read under
  its own lock.  The outcome of concurrent operations is that of running
  them one at a time, in lock order (S5, G1–G7).
  - Limits: S5's "Who must go through yb".
  - Limits: clients that bypass PC/SC; FIDO2 traffic.
  - Regression tests (emulated backend, the lock in force):
    - two threads storing different blobs, with a pause injected between
      the read and the writes: both blobs are readable afterwards, or
      one fails with "store full" having written nothing;
    - a thread replacing a blob while another fills the free objects:
      no blob is lost or damaged;
    - random concurrent stores and removals: every blob is either
      complete with the content last stored, or absent because removed;
    - a reader and a writer replacing a blob: the reader never misses
      the blob;
    - the concurrency fuzzer (S4);
    - each fails with the lock disabled.
  - A tier-2 test with two `yb store` processes on the virtual PIV card
    (spec 0004).

## Implementation notes (2026-10-18)

- **What the real YubiKey showed** (a YubiKey 5, pcsc-lite):
  - before this spec, six `yb` processes in parallel failed 59 of 60
    commands (no YubiKey found, objects unreadable): concurrent access
    did not work at all;
  - `pcsc::Card` resets the card when dropped, and a reset makes every
    other connection fail (`SCARD_W_RESET_CARD`).  A connection now
    resets the card on closing only after a command that may change its
    security state (anything but SELECT, GET DATA, GET RESPONSE, GET
    METADATA, GET SERIAL, GET VERSION), so that no program inherits a
    verified PIN or an authenticated management key; a read-only one
    leaves it.  A connection that finds the card reset reconnects and
    tries again, for up to 30 s;
  - pcsc-lite's `SCardConnect` also waits while another program holds
    the card: the wait notice covers the connection and the lock;
  - with both, six processes in parallel: 360 commands, no failure;
  - a whole-store read on one connection takes about 65 ms, against
    about 0.95 s with a connection per object.
- The lock is `PivBackend::exclusive` (re-entrant); `HardwarePiv` keeps
  the held connection per thread and refuses a second connection from a
  thread holding the card (it would wait for itself).
- The CLI prints "yb: waiting for another program using the YubiKey…"
  after a second's wait (`piv::set_wait_notice`), unless `--quiet`.
- The fuzzer (S4): `rust/yb-core/tests/concurrency_tests.rs`; the long
  run in `.github/workflows/fuzz.yaml`.  Checked by breaking the code:
  without the lock, without the whole read under the lock, or with
  unlocked whole reads, it fails at its first seeds.

## Open questions

None.  (Decided 2026-10-18: Q1, a wait says so after a second, on
stderr, the library staying quiet; Q2, the touch comes before the lock.)

## References

- [spec 0031](0031-rip-safe-replace.md): new copy first, old copy freed
  after (invariant 0001).
- [spec 0038](0038-writes-that-run-out-of-card-memory.md): the cleanup
  before a write.
- [spec 0028](0028-post-quantum-protection.md): the seal and the
  management key behind the touch.
- [spec 0049](0049-snapshots.md): snapshots; conflicts detected.
- PC/SC: `SCardBeginTransaction`, `SCardEndTransaction` (PC/SC Workgroup
  specification, part 5; pcsc-lite; Microsoft's documentation of the
  5-second rule).
