<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0002 — Reading Never Writes

**Sources:** spec 0031

## Invariant

`yb fetch`, `yb ls`, `yb fsck` and shell completion never write to the
YubiKey, even when the store holds leftovers of an interrupted write.

## Why

Reads run often, without the PIN, from scripts and completion; a write
needs the management key and can itself be interrupted.  Leftovers are
discarded in memory; the next write clears them on the card.

## Where the code keeps it

- `Store::from_device` sanitizes in memory only; read commands never
  call `sync`.

## Limits

- `yb fsck --nvm` writes temporary objects to measure free memory, and
  removes them (spec 0032 G2); `self-test` writes by design.

## Regression tests

- `rust/yb/tests/cli_tests.rs`: `reads_never_write`
- `rust/yb-core/tests/rip_safety_tests.rs`: `loading_a_store_with_leftovers_writes_nothing`
- `rust/yb/tests/completion_tests.rs`: `paths_blob_names_and_serial_numbers`
