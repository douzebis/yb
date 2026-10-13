<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0001 — Interrupted Writes Lose Nothing

**Sources:** spec 0031

## Invariant

An interrupted `yb store`, replace or `yb rm` (YubiKey pulled out, PC/SC
error, crash) leaves each blob it touched with either its old or its new
content, and every other blob unchanged.

## Why

A YubiKey is removed at any time; PIV has no transactions.  Before spec
0031, a replace wrote the new copy over the old one, and an interruption
could lose both.

## Where the code keeps it

- A new copy goes into free objects, continuation chunks first, head
  last; the old copy is freed only afterwards (`store_blob`,
  `Store::sync_ordered`).
- Removal writes heads first (`remove_blobs`).
- Readers keep only complete chains (invariant 0003), so a half-written
  copy is invisible.

## Limits

- Needs room for both copies during a replace; a replace without it is
  refused before writing (invariant 0004).

## Regression tests

- `rust/yb-core/tests/rip_safety_tests.rs`: `rip_during_first_store`, `rip_during_replace_single_chunk`, `rip_during_replace_same_chunk_count`, `rip_during_replace_with_more_chunks`, `rip_during_replace_with_fewer_chunks`, `rip_during_remove`, `rip_during_multi_blob_remove`, `rip_during_encrypted_replace_with_signature_spill`, `replace_never_reuses_the_old_copys_objects`, `random_operations_with_interruptions`
