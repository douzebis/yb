<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0031 — Rip-Safe Replace

**Status:** implemented
**App:** yb
**Implemented in:** 2026-10-13

## Problem

yb was designed so that replacing a blob never risks the stored copy: the
new copy is written into free objects, and the old copy is removed only
afterwards.  A YubiKey pulled out of the computer during the write
("ripped") then leaves the old copy intact, or both copies, of which the
newer wins.  That is why `yb store` requires room for a full second copy.

The original Python implementation did this: `store_blob` allocated the
new chunks from free objects only, and left the old copy to `sanitize()`,
which keeps the newer of two blobs with the same name.

**The Rust port broke it** ("Port yb CLI to Rust", 2026-03): `store_blob`
(`yb-core/src/orchestrator/mod.rs`) now frees the old copy's objects in
memory *before* allocating the new chunks, and the allocator takes the
lowest free objects, i.e. the old copy's.  A probe on the simulated card
(2-chunk blob, replaced):

```
old chain [0, 1], new chain [0, 1], objects reused: [0, 1]
```

The new copy overwrites the old one in place; a rip between the two
object writes leaves a head pointing to a chunk that still holds old
data: both copies are lost.  The space check still requires room for two
copies, but the room is not used.

Two weaknesses also predate the port:

- **Write order.**  `Store::sync` writes changed objects in index order,
  so a new head can reach the card before its continuation chunks.
- **`sanitize()` trusts heads.**  It keeps the newest head per name
  without checking that its chain is complete, so a rip after the new
  head but before its last chunk would discard the complete old copy in
  favour of the incomplete new one.  Its chain walk also has no cycle
  guard: a corrupted next-pointer could make it loop forever.

The read commands (`fetch`, `ls`, shell completion) load the store
without sanitizing it, so after an interrupted write they could see two
copies, and `fetch` takes whichever comes first.

Found while fixing (see `docs/reviews/2026-10-python-design-audit.md`):

- **`yb store`'s capacity check** counts the old copy as "freed before new
  ones are allocated", while `store_blob` requires room for both copies:
  near capacity, `yb store` passes its check, then fails with "store is
  full while writing … — this should not happen", and a multi-file store
  can be left half-written.  Neither check counts the chunk the signature
  trailer (spec 0017) may need.
- **`yb rm` bypasses `remove_blob`**: it resets the chains itself and writes
  in index order.
- **`yb fsck` can panic**: the chain walk does not range-check `next_chunk`,
  and fsck walks raw stores.

The Python implementation's design document described all this
("Write Operation Resilience": safe allocation, body-first writes, chain
validation by consecutive ages and positions, sanitize before every
operation); it was deleted with the Python tree (`4eb307a`) and its
interruption test (`test_with_ejection_simulation`) never ported.

## Goals

- **G1 — Never overwrite the stored copy.**  A replace writes the new
  copy only into objects that were free before it started, including the
  signature spill chunk (spec 0017).
- **G2 — Write order.**  A store writes, in this order: the new
  continuation chunks, the new head, then the old copy's objects (freed).
  A remove writes the heads first, then the continuation chunks; `yb rm`
  goes through the same code.
- **G3 — Complete chains only.**  A head counts as a blob only if its
  chain is complete (definition below).  Among complete heads with the
  same name, the newest (highest age) wins.  Incomplete heads, older
  duplicates and unreachable objects are leftovers.
- **G4 — Consistent reads.**  Loading a store discards leftovers in
  memory, so every command sees the blobs a later write would keep.
  Reading still writes nothing to the YubiKey: leftovers are removed from
  the card by the next write (`store`, `remove`), as today.  `yb fsck` is
  the exception: it loads the raw store, to report the leftovers, and its
  chain walks are bounded.
- **G4b — One capacity rule.**  A store needs free objects for the new
  copy, signature trailer included, with the old copy still counted as
  occupied; the library and `yb store` apply the same rule, and a
  multi-file store either fits entirely or stores nothing.
- **G5 — The rip property.**  For any blob store (new or replace) and any
  remove, interrupted after any number of object writes, the store as
  loaded afterwards holds, for the blob concerned, either its old content
  or its new content (or, for a remove, the old content or nothing), and
  every other blob unchanged.
- **G6 — Regression test.**  A test proves G5 by interrupting writes at
  every possible point, on the simulated card, for: a first store, a
  replace with the same number of chunks, a replace with more chunks, a
  replace with fewer chunks, and a remove; with several other blobs
  present.  A second test checks G1 directly: the new chain shares no
  object with the old one.

## Non-goals

- **Atomicity across several blobs** (`yb store a b c` is three
  independent stores).
- **Tearing within one object write.**  yb relies on the YubiKey writing
  one PIV data object atomically (PUT DATA); this spec orders whole-object
  writes.
- **Changing the space rule.**  A replace still needs room for both
  copies; that was already the library's rule (G4b aligns `yb store` with
  it).
- **Changing `fsck`'s output.**  It reports leftovers as before (G4).

## Specification

### Complete chain

A head at index `h` has a complete chain if, following `next_chunk` from
`h`:

- every object reached is within the store and not empty;
- every object after the head is a continuation (`chunk_pos != 0`), with
  `chunk_pos` equal to the previous one plus 1;
- the continuation at position `p` has age `head age + p`: a blob's
  objects get consecutive ages when it is written (Python: `store_age + 1`
  per chunk, raised after each; Rust: `next_age()` per object, the
  signature spill chunk included);
- the walk ends on an object whose `next_chunk` is itself, within
  `object_count` steps (no cycle).

### `Store::sanitize`

1. For each name, among heads with a complete chain, keep the one with
   the highest age.
2. Reset every other head (incomplete, or older duplicate).
3. Reset every non-empty object not reachable from a kept head.
4. Return the number of objects reset.

All chain walks are bounded by `object_count` and stop on a revisited
object.

### `Store::from_device`, `Store::from_device_raw`

`from_device_raw` reads the objects as they are (for `yb fsck`).
`from_device` calls it, then `sanitize()`.  Objects reset are marked
dirty, as today; only a later `sync` writes them.

`chunk_chain` stops at a revisited object or a pointer beyond the store.

### `store_blob`

1. Validate, compress and encrypt as today.
2. Check `free_count() >= objects_needed` (the chunks for the data plus
   the 65-byte signature trailer), with the old copy still counted as
   occupied.
3. Allocate the new chunks from free objects; the old copy's objects are
   not free.  Build the head and continuation objects, then the signature
   trailer (whose spill chunk, if any, is also allocated from free
   objects).
4. Write the new copy's objects: continuation chunks (including a spill
   chunk) first, the head last (`Store::sync_ordered`).
5. Reset the old copy's objects (its chain as found before step 3), and
   `sync`.

If step 4 fails, the old copy is intact on the card; if step 5 fails, the
new copy is complete and newer, and the leftovers are cleaned at the next
load (G4) and written by the next write.

### `remove_blobs`, `remove_blob`

`remove_blobs(names)` resets the chains of the blobs found and writes, in
one pass, all their heads first, then the other objects.  `remove_blob` is
the one-name case; `yb rm` calls `remove_blobs`.

### `yb store` capacity check

Replays the stores in order: each needs `objects_needed` free objects at
that point; a replaced copy is freed only after its replacement is
written.  If any does not fit, nothing is stored, and a replace says that
it needs room for the new copy before the old one is removed.

### `Store::sync_ordered(piv, management_key, order)`

Writes the dirty objects listed in `order`, in that order, then any other
dirty objects in index order.  `sync` is `sync_ordered` with an empty
order.

### Tests (G6)

A test backend wraps the simulated card and fails `write_object` after a
given number of successful writes (`FailingPiv`).  For each scenario and
each `n` from 0 to the number of writes the operation makes:

1. set up the store on a fresh simulated card (other blobs included);
2. run the operation with writes failing after `n`;
3. reload the store from the card (`Store::from_device`) and fetch every
   blob;
4. assert G5: the blob concerned has its old or new content (or, for a
   remove, old content or absence), every other blob is unchanged.

Plus:

- the replace probe above as a test (no shared object between old and new
  chains), and loading a store with leftovers writes nothing;
- a multi-blob remove (`remove_blobs`, the `yb rm` path) and an encrypted
  replace whose signature trailer spills into an extra chunk, both
  interrupted at every write;
- random operation sequences with random interruptions (3 seeds × 400
  operations), reloading the store from the card after each operation and
  checking every blob against a model: the Python-era ejection test,
  ported, and checking the old content too;
- `sanitize` and chain unit tests: empty object in a chain, wrong
  position, non-consecutive age, pointer beyond the store, cycle, newer
  incomplete copy against older complete one;
- `yb store` capacity: a replace without room for both copies is refused
  before writing; a multi-file store that does not fit stores nothing.

All tests in `rust/yb-core/tests/rip_safety_tests.rs`,
`rust/yb-core/src/store/tests.rs` (T7) and `rust/yb/tests/cli_tests.rs`
(`store_capacity_tests`); with the old `store_blob`, the interruption
tests fail ("neither its old nor its new content").

## Open questions

None.

## References

- Spec 0010 — store layout and empty-slot sentinel.
- Spec 0017 — blob integrity signature (spill chunk).
- Spec 0025 — partial-update messages of `sync`.
- Spec 0030 — KeePassXC integration, which depends on this one.
