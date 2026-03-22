<!--
SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
SPDX-FileCopyrightText: 2025 - 2026 Thales Cloud Sécurisé

SPDX-License-Identifier: MIT
-->

# 0010 — Dynamic PIV Object Sizing

**Status:** abandoned
**App:** yb
**Implemented in:** 2026-03-21
**Abandoned:** 2026-03-22 — superseded by [spec 0016](0016-pre-allocated-tiered-store.md)

## Problem

The current store format writes every PIV object at a fixed size chosen at
`yb format` time (default 2,048 bytes).  The last chunk of every blob is
partially filled: the unused suffix is zero-padded to `object_size`, wasting
NVM on the YubiKey.  With an average waste of `object_size / 2` bytes per
blob, a 10-blob store at the default size wastes ~10 KB — roughly 25% of
the gross store capacity.

Additionally, `object_size` is an opaque tuning parameter that users should
not need to reason about.  The right value depends on the expected blob size
distribution, which is not known at format time.

## Goals

- Eliminate last-chunk NVM waste: every PIV object is written at exactly the
  size required for its content.
- Remove `--object-size` from `yb format`; the only remaining format
  parameter is `--object-count`.
- `yb fsck` reports free capacity as a conservative byte estimate:
  `min(free_slots × MAX_OBJECT_SIZE, nvm_remaining)`.
- Full backward compatibility: a future `yb` implementing this spec can read
  and write existing uniform-size stores without modification.

## Non-goals

- Changing the chunk linking structure or any field offsets.
- Reclaiming NVM from standard PIV certificate slots (9A, 9C, 9D, 9E).
- Guaranteeing a fixed NVM reservation at format time (see Open questions).

## Specification

### 3.1 Object sizing at write time

Each PIV object is written at the minimum size that holds its content:

- **Head chunk:** `0x17 + BLOB_NAME_LEN + payload_len` bytes
- **Continuation chunk:** `0x0B + payload_len` bytes
- **Empty (reserved) slot:** 9 bytes — the common header through `OBJECT_AGE`
  inclusive, with `OBJECT_AGE = 0`

The maximum object size is capped at `MAX_OBJECT_SIZE = 3052` bytes (the PIV
slot maximum).  This constant replaces the per-store `object_size` parameter
and requires no configuration.

### 3.2 Object sizing at read time

`from_device` infers each object's size from the byte length returned by the
PIV `GET DATA` command, exactly as today.  No header change is required.
Objects of any size from 9 bytes to `MAX_OBJECT_SIZE` bytes are valid.

Backward compatibility follows directly: a uniform-size store is a special
case where all `GET DATA` responses happen to be the same length.

### 3.3 Empty slot sentinel

At `yb format` time, each reserved slot is written as a 9-byte record:

```
0x00  4  u32 LE  MAGIC = 0xF2ED5F0B
0x04  1  u8      OBJECT_COUNT
0x05  1  u8      STORE_KEY_SLOT
0x06  3  u24 LE  OBJECT_AGE = 0
```

This is the minimum content needed for `from_device` to identify the slot as
belonging to the store and classify it as empty.

When a blob is removed, its chunks are reset to this 9-byte sentinel (a single
`PUT DATA` write per chunk).

### 3.4 `yb format` CLI change

`--object-size` / `-s` is removed.  `yb format` accepts only:

```
--object-count / -c   (default: 20)
--key-slot / -k       (default: 0x82)
--generate / -g
--subject / -n
```

### 3.5 `yb fsck` free capacity reporting

`fsck` reports free capacity as:

```
free_bytes = min(free_slots × MAX_OBJECT_SIZE, nvm_remaining)
```

where:

- `free_slots` = count of empty objects in the store.
- `nvm_remaining` = `51200 − sum of GET DATA response lengths for all PIV
  object IDs known to yb`.  This approximation is exact for the objects yb
  manages; it does not account for NVM consumed by standard-slot certificates
  or other PIV users.  It is therefore a slight overestimate, making the
  `min()` the conservative bound.

Example output:

```
Store: 20 objects, key slot 0x82, age 14
Blobs: 6 stored, 11 objects free (~33,572 bytes available)
Status: OK
```

### 3.6 `YBLOB_FORMAT.md` update

The format specification document (`docs/YBLOB_FORMAT.md`) must be updated to:

- Remove the uniform-size assumption from section 2.
- State that `object_size` is inferred per-object from `GET DATA` response length.
- Add the 9-byte empty-slot sentinel layout.
- Update section 7 (invariants) to reflect the new size range (9–3,052 bytes).

## Why this approach was abandoned — NVM fragmentation

This spec was implemented and then reversed after empirical testing revealed a
fundamental problem with dynamic object sizing on the YubiKey 5 PIV applet.

### The fragmentation problem

The YubiKey 5 PIV applet uses **dynamic NVM allocation** for data objects.
When a `PUT DATA` command writes an object of size S, the firmware allocates
exactly S bytes of NVM for that object.  When the same object is later
overwritten at a smaller size S' < S, the firmware allocates a new S'-byte
region and marks the original S-byte region as dead.  **The dead region cannot
be reclaimed** without a full PIV application reset (`ykman piv reset`).

This means that every time `yb` writes a blob that is smaller than the
previous version of that blob's chunk, the freed NVM is permanently wasted
for the lifetime of the store.  Repeated blob updates — which are the normal
`yb set` use case — cause the store to accumulate dead regions that
progressively reduce the available capacity.

### Experimental evidence

An NVM fragmentation test program was written and run on a YubiKey 5.4.3:

- **`rust/yb-core/src/bin/nvm_frag_test.rs`** — standalone binary that
  measures capacity and applies a fragmentation stress test.

**Experiment 1 — NVM capacity probe** confirmed:
- Total NVM available for data objects: **50,225 bytes** (PIV applet overhead:
  975 bytes; gross NVM per Yubico spec: 51,200 bytes).
- The 975-byte overhead is consumed by the PIV applet's own state: management
  key (24 bytes 3DES), PIN/PUK with retry counters, default CHUID and CCC
  objects pre-written at reset, key-type metadata for certificate slots
  9A/9C/9D/9E, and the internal object directory.

**Experiment 2 — random-size fragmentation stress** confirmed permanent
fragmentation:
- After 100 random-size writes across 20 slots (random sizes 1–3052 bytes,
  failures ignored), the store could only hold **36,624 bytes** of
  MAX_OBJECT_SIZE objects — a permanent loss of **13,601 bytes (27%)** of
  total capacity.
- Fragmentation is monotonically increasing: every large→small→large cycle
  on a slot consumes additional NVM.

### Conclusion

Dynamic object sizing (writing each object at its minimum required size) is
unsafe for a long-lived `yb` store.  The correct approach is to **pre-allocate
each slot at a fixed size at `yb format` time** and always overwrite at
exactly that size, so the firmware's NVM allocator sees each slot as a
fixed-size region and can reuse it in-place.

This is the approach specified in **[spec 0016](0016-pre-allocated-tiered-store.md)**.

### Disposition of the implementation

The code changes from this spec (dynamic `to_bytes`, 9-byte sentinel, payload
trimming in `from_bytes`, removal of `--object-size`) remain in place as
infrastructure.  Spec 0016 builds on them: it reintroduces fixed-size writes
per slot, but the size is now per-slot (set at format time from a tiered table)
rather than a single global `object_size` parameter.

## Open questions

*(All resolved — see spec 0016.)*

## References

- [`docs/YBLOB_FORMAT.md`](../../docs/YBLOB_FORMAT.md) — binary format specification
- [`rust/docs/DESIGN.md`](../../rust/docs/DESIGN.md) section 14 — future opportunities
- [`rust/yb-core/src/store/constants.rs`](../../rust/yb-core/src/store/constants.rs) — current size constants
- [`rust/yb-core/src/store/mod.rs`](../../rust/yb-core/src/store/mod.rs) — `from_device`, `Store::format`, `Object::to_bytes`
- [`rust/yb-core/src/bin/nvm_frag_test.rs`](../../rust/yb-core/src/bin/nvm_frag_test.rs) — NVM fragmentation test program
- [spec 0016](0016-pre-allocated-tiered-store.md) — superseding spec: pre-allocated tiered store
- YubiKey 5 NVM budget: 51,200 bytes gross; 50,225 bytes available for data objects (measured)
- jemalloc size-class design: Evans 2006/2015 — 4 sub-bins per doubling, ~20% worst-case padding
