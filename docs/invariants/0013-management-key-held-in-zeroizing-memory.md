<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0013 — The Management Key Is Held in Zeroizing Memory

**Sources:** spec 0034 G1

## Invariant

yb holds the management key only in `Zeroizing` buffers, overwritten
when dropped: from `YB_MANAGEMENT_KEY` or `--key`, from PRINTED, when
generated, and when decoded for authentication.

## Why

PIV authenticates the management key on the host, so the key must be in
memory; it should stay there as briefly, and in as few copies, as
possible.

## Where the code keeps it

- The types: `Context::management_key`, `management_key_for_write`,
  `PrintedKeys`, `generate_random_management_key`.

## Limits

- No `mlock`, no core-dump suppression (spec 0034 non-goals).

## Regression tests

- `rust/yb/tests/cli_tests.rs`: `management_key_is_held_in_zeroizing_memory`
