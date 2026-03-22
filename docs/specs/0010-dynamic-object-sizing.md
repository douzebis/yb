<!--
SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0010 — Dynamic PIV Object Sizing

**Status:** implemented
**App:** yb
**Implemented in:** 2026-03-22

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

The maximum object size is capped at `MAX_OBJECT_SIZE = 3063` bytes (the
YubiKey firmware APDU buffer limit of 3,072 bytes minus 9 bytes of TLV
framing overhead; empirically confirmed on firmware 5.4.3).  This constant
replaces the per-store `object_size` parameter and requires no configuration.

### 3.2 Object sizing at read time

`from_device` infers each object's size from the byte length returned by the
PIV `GET DATA` command, exactly as today.  No header change is required.
Objects of any size from 9 bytes to `MAX_OBJECT_SIZE` (3,063) bytes are valid.

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
- Update section 7 (invariants) to reflect the new size range (9–3,063 bytes).

## NVM fragmentation — investigation and conclusion

After initial implementation, concerns arose about NVM fragmentation on the
YubiKey 5.  An extensive empirical investigation was conducted using
`rust/yb-core/src/bin/nvm_frag_test.rs` on firmware 5.4.3.  The full research
notes are in `docs/yubikey-nvm-internals.md`.  Summary of findings:

### What was measured

- **NVM capacity after PIV reset:** 50,225 bytes available for data objects
  (PIV applet overhead: 975 bytes; gross NVM per Yubico spec: 51,200 bytes).
- **Maximum single object payload:** 3,063 bytes (firmware APDU buffer 3,072 −
  9 bytes TLV framing; empirically confirmed, not firmware-specific).
- **Per-object NVM overhead:** ~22 bytes per object (firmware-internal metadata
  not returned by GET DATA; undocumented, inferred from experiment).

### What was initially misread

The `frag-random` experiment (100 random-size writes across 20 slots, then
fill MAX) appeared to show a permanent loss of 13,601 bytes (27% of capacity).
This was an **accounting bug**: the residual sizes of stressed slots 14–19
were not included in the baseline calculation.  After correcting the
accounting, the unaccounted difference is zero — entirely explained by the
partial last slot in the binary-search probe.

### Correct conclusion

The YubiKey 5 PIV applet **does not fragment NVM** in practice.  All
experiments confirm this:

| Experiment | Result |
|---|---|
| `frag-random` (corrected accounting) | Zero loss |
| `frag-shrink1` (stress → shrink all to 1 byte → fill MAX) | Full capacity recovered |
| `frag-delete` (stress → delete all → fill MAX) | Full capacity recovered |
| `shrink0` + `free-nvm` | Full capacity transferred with no loss |
| `self-test` (200 ops, real YubiKey, NVM instrumented) | +0 bytes delta after cleanup |

The firmware likely uses log-structured storage or a heap with garbage
collection — it does not leave dead regions when objects are shrunk or deleted.

Dynamic object sizing is therefore safe.  Spec 0016 (pre-allocated tiered
store) was based on the false fragmentation premise and has been suspended.

## Open questions

*(Resolved — dynamic sizing is safe; spec 0016 suspended.)*

## References

- [`docs/YBLOB_FORMAT.md`](../../docs/YBLOB_FORMAT.md) — binary format specification
- [`rust/docs/DESIGN.md`](../../rust/docs/DESIGN.md) section 14 — future opportunities
- [`rust/yb-core/src/store/constants.rs`](../../rust/yb-core/src/store/constants.rs) — current size constants
- [`rust/yb-core/src/store/mod.rs`](../../rust/yb-core/src/store/mod.rs) — `from_device`, `Store::format`, `Object::to_bytes`
- [`rust/yb-core/src/bin/nvm_frag_test.rs`](../../rust/yb-core/src/bin/nvm_frag_test.rs) — NVM fragmentation test program
- [`docs/yubikey-nvm-internals.md`](../../docs/yubikey-nvm-internals.md) — full NVM research notes
- [spec 0016](0016-pre-allocated-tiered-store.md) — suspended spec (fragmentation premise was false)
- YubiKey 5 NVM budget: 51,200 bytes gross; 50,225 bytes available for data objects (measured)
