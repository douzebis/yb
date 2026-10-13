<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0008 — Format Never Strands Blobs

**Sources:** spec 0022

## Invariant

No failure during `yb format` leaves blobs encrypted for a key that is
no longer on the card, nor a key that does not match its certificate
while a store accepts writes.  `yb store` refuses to write when the slot
key does not match its certificate.

## Why

A key/certificate mismatch makes every later blob undecryptable, and
was once reached by a failed `--protect` (spec 0022).

## Where the code keeps it

- The checks-first, then ordered changes of `yb format`; the
  key/certificate check in `yb store`.

## Regression tests

- `rust/yb/tests/cli_tests.rs`: `format_safety_tests::invariants_hold_for_every_fault`, `failed_certificate_leaves_an_empty_store_that_refuses_writes`, `mismatched_slot_key_is_rejected_before_any_write`
