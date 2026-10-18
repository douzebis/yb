<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0020 — yb's Operations Are Serializable

**Sources:** spec 0048

## Invariant

Several programs using one YubiKey through yb at once get the outcome of
running their operations one at a time, in the order they took the card
lock.  In particular:

- a whole-store read sees the store between two writes, never in the
  middle of one: it never misses a blob that exists, never sees half of
  one;
- a write plans from a whole read made under its own lock, so it never
  overwrites, frees or cleans up another program's objects, and its copy
  of a blob is newer than any other copy (spec 0048, G6);
- an interrupted operation (a crash, the YubiKey pulled out) took effect
  or did not, as if it had run alone (invariant 0001).

## Why

Before spec 0048, yb did not support concurrent access: each PIV command
had its own connection, and nothing kept other programs away between a
write's read and its last object write.  Two programs at once (two `yb`
commands, `yb` and KeePassYB) could lose a blob or read a store in the
middle of a write.

## Where the code keeps it

- The card lock: PC/SC's transaction, taken by every connection yb opens
  (`connect_reader_mode`); `PivBackend::exclusive` keeps one connection,
  and so the lock, across a sequence (`HardwarePiv`); the simulated
  backends do the same (`piv::lock::SimulatedLock`).
- `Store::from_device_raw` reads under the lock, and so does the memory
  scan (`scan_nvm`, `scan_store_memory`: the store's objects and their
  sizes under one lock); `store_blob_with_checked`
  and `remove_blobs_checked` lock, read the whole store again
  (`reload_for_write`), and plan from that read; the formats, the
  descriptor rewrap, the management-key switch and its repairs run under
  the lock.
- A connection resets the card when it closes only after a command that
  changed the card's security state (`PcscSession`'s `Drop`); a
  connection that finds the card reset by another program reconnects.

## Limits

- Programs that write the store's objects without yb (e.g. `ykman piv
  objects import`), and versions of yb or libyubiblob before spec 0048,
  take no lock: with them, nothing is guaranteed.
- FIDO2 traffic (USB HID) is not locked; it writes no store object.

## Regression tests

- `rust/yb-core/tests/concurrency_tests.rs`: `concurrent_operations_are_serializable`, `a_reader_never_misses_a_blob_being_replaced`, `without_the_lock_the_fuzzer_finds_a_violation`, `the_memory_scan_sees_one_state`
- `rust/yb-piv-harness/src/bin/hardware_piv_tests.rs`: `t2_exclusive_makes_others_wait`, `t2_exclusive_is_reentrant`, `t2_concurrent_connections`
