<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0009 — The Management Key Is Never Lost

**Sources:** spec 0022, spec 0027

## Invariant

No failure while replacing the management key (`yb format --protect`,
`yb rotate-management-key`) leaves the card with a key that is stored
nowhere: the key the card accepts is always in PRINTED or held by the
caller, and an interrupted switch is completed or undone by the next
write.

## Why

A lost management key makes the store read-only until a PIV reset.

## Where the code keeps it

- `enable_pin_protected_management_key` (new key saved before the
  switch, old key kept in tag `8A`); the repairs in `Context`.

## Regression tests

- `rust/yb/tests/cli_tests.rs`: `rejected_switch_changes_nothing`, `lost_reply_completes_the_switch`, `interrupted_switch_is_recovered_by_the_next_write`, `rotates_a_stored_key`, `rejected_switch_keeps_a_stored_explicit_key`, `rejected_switch_keeps_a_key_only_in_8a`
