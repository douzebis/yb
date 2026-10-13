<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0003 — Only Complete Blobs of the Store Are Visible

**Sources:** spec 0031, spec 0034 G7

## Invariant

A blob is visible only if its chain is complete: every chunk present,
positions consecutive, ages equal to the head's age plus the position.
When two complete copies share a name, the newer one wins.  Objects that
record another object count than object 0 do not belong to the store and
are ignored.

## Why

This is what makes interrupted writes invisible (invariant 0001), and
what keeps a stray or foreign object from being adopted into a blob.

## Where the code keeps it

- `Store::chain_is_complete`, `Store::sanitize`.

## Limits

- `yb fsck` reads the store raw and reports what `sanitize` discards.

## Regression tests

- `rust/yb-core/src/store/tests.rs`: `complete_chain_is_kept`, `chain_with_an_empty_object_is_incomplete`, `chain_with_a_wrong_position_is_incomplete`, `chain_with_non_consecutive_ages_is_incomplete`, `chain_pointing_beyond_the_store_is_incomplete`, `chain_with_a_cycle_is_incomplete`, `older_complete_copy_beats_newer_incomplete_one`, `newer_complete_copy_wins_and_old_chain_is_freed`, `sanitize_keeps_newer_duplicate`, `sanitize_resets_orphaned_continuation`
- `rust/yb/tests/cli_tests.rs`: `foreign_object_is_ignored_and_reported`
