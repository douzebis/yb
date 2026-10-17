<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0004 — A Store Refused for Room Writes Nothing

**Sources:** spec 0031, spec 0032, spec 0034 G6, spec 0038

## Invariant

`yb store` checks, before its first write, that every blob fits in the
store's free **objects** (each new copy with its signature trailer,
while the old copies still occupy theirs) and in the 24-bit age counter.
If not, it writes nothing, for a multi-file store too, and exits with
status 3 when the store is full.

## Why

A failure discovered midway would leave some blobs stored and others
not, or end with "store is full while writing … this should not happen".
An age that wrapped to 0 would make an object look empty.

## Where the code keeps it

- The replayed capacity check in `yb store` (`objects_for`); the same
  count in `store_blob`; `Store::ensure_age_room`.

## Limits

- The count uses the size before compression (an upper bound).
- **Card memory is not counted.**  The card does not report its free
  memory (measuring it means filling it, and certificates and other
  objects share it), so a store can still run out of memory while
  writing; invariant 0001 covers that case (spec 0038).

## Post-quantum stores (spec 0028)

The same check, with their overheads.  Also: a blob is protected (the
FIDO2 PIN, a touch) before anything is written, so a refused protection
(wrong PIN, no touch) writes nothing for that blob, not even cleanup;
legacy stores too, for a refused signature.

## Regression tests

- `rust/yb-core/tests/protection_tests.rs`: `refused_protection_writes_nothing`
- `rust/yb-fido2-emulator/tests/post_quantum_protection_tests.rs`: `refusals_write_nothing`
- `rust/yb-piv-harness/src/bin/yb_cli_tests.rs`: `pq_refused_touch`
- `rust/yb/tests/cli_tests.rs`: `replace_without_room_for_both_copies_is_refused_cleanly`, `replace_with_room_for_both_copies_succeeds`, `multi_file_store_that_does_not_fit_stores_nothing`, `store_refused_when_ages_run_out`
- `rust/yb/tests/exit_status_tests.rs`: `store_full_is_status_3_and_other_errors_1`
