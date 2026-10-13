<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0038 — Writes That Run Out of Card Memory

**Status:** implemented
**App:** yb
**Implemented in:** 2026-10-13

## Problem

Measured on a YubiKey 5 (firmware 5.7.1, 2026-10-13), replacing a 22 KB
blob in a 32-object store already holding about 12 KB:

1. `yb store` checked the room in **objects** (26 free, enough for a
   second copy) and started writing.  The card's PIV memory (about
   51 KB, shared with certificates and other objects) ran out midway.
2. The card refused the next object write (`SW 6A84`) and **deleted that
   object**: a write refused for lack of memory removes the object it
   targets (measured already in spec 0022, M2; modeled by
   `Fault::StorageFull`).  The object was a free object of the store.
3. Every later command failed: `Store::from_device_raw` reads every
   object of the store and treats an absent one (`SW 6A82`) as fatal.
   `ls`, `fetch`, `rm` and `fsck` all stopped there, before `sanitize`
   could discard the leftovers of the interrupted write.

The blobs were intact (the new copy's head is written last, spec 0031),
but unreachable.  Invariant 0001 assumed a failed write leaves an object
as it was; the tests interrupted writes with a fault that deletes
nothing, and never let the card's memory run out.  Invariant 0004
promised a refusal before any write, which yb cannot keep for memory:
the card does not report its free memory, the only measure is to fill
it, and other objects share it.

## Goals

- **G1 — An absent object is an empty one.**  A store object (other than
  object 0, which identifies the store) that the card reports absent is
  read as empty and marked to be rewritten; the store stays readable,
  and `sanitize` then sorts live blobs from leftovers as designed.
- **G2 — Clean up first.**  A write (`store`, `rm`) first writes the
  clean-ups that loading found (leftovers reset, absent objects
  recreated as empty), before any new data, so that the memory they held
  is free for it.
- **G3 — Reported.**  `yb fsck` reports absent objects, as a warning:
  the next write recreates them.
- **G4 — Honest invariants.**  Invariant 0001 covers a write that runs
  out of card memory; invariant 0004 promises the refusal for objects
  and the age counter only, and says why memory in bytes is not counted.
- **G5 — Messages.**  A write that runs out of card memory says that the
  previous content is intact and the next yb command cleans up.

## Non-goals

- Counting the card's free memory before writing (not reported by the
  card; measuring it means filling it).
- Object 0 absent: the store is then not recognized (as today).

## Specification

- `Store::from_device_raw`: for objects 1 to N-1, a read failing with
  `SW 6A82` yields an empty object (`Object::reset` of a copy of object
  0's common header, so dirty), and its index is recorded in
  `Store::missing`.  Any other read error stays fatal.
- `store_blob` and `remove_blobs`: before allocating or resetting
  anything, `store.sync()` writes the objects already dirty (the
  clean-ups of loading).
- `yb fsck`: "warning: object 0x5F00NN is absent from the card (a write
  ran out of card memory); the next write recreates it", per object; the
  exit status is unchanged.
- The error for `SW 6A84` during a store: the previous content of the
  blobs is intact; the next yb command frees the space the interrupted
  write used.
- Simulated card: `VirtualPiv::set_memory_limit(bytes)`: a write that
  would take the objects' total size beyond it fails with `SW 6A84` and
  deletes the object, as the card does.

## Invariants

- 0001 extended: a write that runs out of card memory loses nothing, and
  the store stays readable.
- 0004 narrowed: objects and age counter only.

## Tests

- yb-core, with a memory limit on the simulated card: the measured
  scenario (store 2, 10 and 22 KB, replace the 22 KB one): the replace
  fails, the store loads, every blob reads back with its previous
  content, and `rm` of the 22 KB blob succeeds and leaves no leftover.
- A replace interrupted by `Fault::StorageFull` at every write: the store
  loads, the old copy and the other blobs are intact.
- Clean-up first: after such an interruption, the next store on a card
  with just enough memory succeeds.
- `fsck` reports an absent object.
- In `rust/yb-core/tests/rip_safety_tests.rs`:
  `out_of_memory_during_replace_with_more_chunks`,
  `out_of_memory_during_remove`, `replace_that_runs_out_of_card_memory`,
  `next_store_after_out_of_memory_frees_the_leftovers_first`; in
  `rust/yb/tests/cli_tests.rs`:
  `absent_object_is_reported_and_the_store_readable`.  Reading an absent
  object as fatal again fails four of them; skipping the clean-up first
  fails the last rip-safety one.

## Open questions

None.

## References

- Spec 0022 (M2: a refused write deletes the object), spec 0031.
- Invariants 0001, 0004.
