<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0016 — A Post-Quantum Store Exists Only Once Its Descriptor Is Written

**Sources:** spec 0028 (D13)

## Invariant

Formatting a post-quantum store writes the empty chunks, deletes the yb
objects beyond them, and writes the descriptor in `0x5F_0000` last.
Interrupted at any write, it never leaves a post-quantum store; a store
still readable afterwards is the previous one, intact.  A new format
succeeds.

## Why

A half-written descriptor, or chunks without one, must not be taken for
a store into which blobs could be written and lost.

## Where the code keeps it

- `Store::format_post_quantum`; `Store::from_device`, which reads object
  0 first and refuses chunks whose magic does not match.

## Regression tests

- `rust/yb-core/tests/post_quantum_store_tests.rs`: `interrupted_format_leaves_no_store`
