<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0014 — Older yb Never Writes to a Post-Quantum Store

**Sources:** spec 0028 (D12, D13)

## Invariant

Every object of a post-quantum store, its descriptor in `0x5F_0000` and
its chunks, starts with the magic `0xF2EDF0B2`.  yb 0.6 and older, which
refuse any object without the legacy magic `0xF2ED5F0B`, stop at the
first object they read, before any write: `yb ls`, `fetch`, `store`,
`rm` and `fsck` fail with "bad magic".

## Why

Older yb cannot read a post-quantum store, and must not damage it: its
`yb store` writes cleanup and signs, its `yb rm` deletes, with any
management key it finds (a ykman copy in PRINTED).

## Where the code keeps it

- `PQ_MAGIC` in `Store::make_object` (through `StoreKind::magic`) and in
  `Descriptor::to_bytes`; the legacy `Object::from_bytes` accepts only
  `YBLOB_MAGIC`, as in yb 0.6.

## Limits

- `yb format` of an older yb can still overwrite the store, as it can
  any data, after asking.
- The messages of older yb say "bad magic", not "made by a newer yb"
  (a next-release improvement, spec 0028).

## Regression tests

- `rust/yb-core/tests/post_quantum_store_tests.rs`: `legacy_parser_refuses_every_object`
