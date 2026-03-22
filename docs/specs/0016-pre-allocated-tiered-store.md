<!--
SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
SPDX-FileCopyrightText: 2025 - 2026 Thales Cloud Sécurisé

SPDX-License-Identifier: MIT
-->

# 0016 — Pre-Allocated Tiered Store

**Status:** draft
**App:** yb
**Implemented in:** <!-- YYYY-MM-DD, fill after implementation -->

## Problem

Spec 0010 introduced dynamic object sizing: each PIV object is written at the
minimum size required for its content.  After implementation and empirical
testing on a YubiKey 5.4.3, this approach was found to cause severe and
permanent NVM fragmentation (see spec 0010 — Why this approach was abandoned).

In summary: the YubiKey 5 PIV applet uses dynamic NVM allocation.  Writing a
3,052-byte object and then overwriting it with a 9-byte sentinel permanently
wastes ~3,043 bytes of NVM.  After 100 random-size writes across 20 slots,
27% of total capacity (13,601 of 50,225 bytes) was permanently lost.

The underlying constraint is: **a PIV slot's NVM footprint is fixed at the
size of its largest-ever write**.  Overwriting with a smaller value leaves
dead NVM that is only reclaimed by a full PIV application reset.

The correct approach is to pre-allocate every slot at format time at a fixed
size and always overwrite at exactly that size.  This reduces the firmware's
NVM allocator to a static map — no fragmentation is possible.

## Background — YubiKey NVM facts (measured)

| Quantity | Value |
|---|---|
| Gross NVM (Yubico spec) | 51,200 bytes |
| PIV applet overhead | 975 bytes |
| Available for data objects | **50,225 bytes** |
| Maximum single object size | 3,052 bytes (PIV APDU limit) |
| Addressable object IDs | 256 (`0x5F0000`–`0x5F00FF`) |

The PIV applet overhead (975 bytes) is consumed by: management key (24 bytes
3DES), PIN/PUK counters and values, default CHUID and CCC objects, key-type
metadata for certificate slots 9A/9C/9D/9E, and the internal object directory.
It is not reclaimable by `yb`.

These figures were measured on firmware 5.4.3 using
`rust/yb-core/src/bin/nvm_frag_test.rs`.  They may vary slightly across
firmware versions but are stable enough to use as defaults.

## Goals

- Pre-allocate every store slot at a fixed size at `yb format` time, chosen
  from a tiered size table.  All subsequent writes to a slot use exactly the
  slot's pre-allocated size (zero-padded if the compressed blob is shorter).
- Eliminate NVM fragmentation: because each slot is always written at the same
  size, the firmware sees it as a fixed-size region and reuses it in-place.
- Replace the single global `object_size` / `object_count` model with a
  tiered model: the store has N slots of varying sizes, chosen to cover the
  expected blob size distribution efficiently.
- Simplify the user-facing CLI: `yb format` takes at most `--total-size` and
  `--object-count`; `yb` computes the tier layout automatically.
- Keep user documentation honest: explain the YubiKey NVM fragmentation
  constraint and recommend formatting a fresh or reset YubiKey.

## Non-goals

- Changing the YBLOB binary wire format (magic, header fields, chunk linking).
- Dynamic resizing of slots after formatting (that requires a re-format).
- Tracking or reclaiming NVM from standard PIV certificate slots (9A–9E).
- Guaranteeing that the pre-allocated store is contiguous in the firmware's
  internal NVM heap (we cannot control the allocator).

## Specification

### 3.1 Tier table generation

At `yb format` time, `yb` computes a **tier table**: an ordered list of
`(slot_index, slot_size)` pairs that will be pre-allocated.

The algorithm follows the jemalloc size-class design: **4 sub-classes per
power-of-2 doubling**, giving a worst-case padding ratio of ~19% and an
expected ratio of ~12% under a log-uniform blob size distribution.

#### 3.1.1 Base table

Starting from `MIN_SLOT_SIZE = 64` bytes and ending at `MAX_OBJECT_SIZE =
3,052` bytes, the base set of size classes is:

```
Octave   64– 128 (spacing  16):   64,   80,   96,  112
Octave  128– 256 (spacing  32):  128,  160,  192,  224
Octave  256– 512 (spacing  64):  256,  320,  384,  448
Octave  512–1024 (spacing 128):  512,  640,  768,  896
Octave 1024–2048 (spacing 256): 1024, 1280, 1536, 1792
Octave 2048–3052 (spacing 256): 2048, 2304, 2560, 2816, 3052
```

This gives 21 distinct size classes.  All sizes are multiples of 8 bytes
(YubiKey NVM is word-aligned).

#### 3.1.2 Slot allocation against the budget

Given `--total-size T` (default: 50,225) and `--object-count N` (default: 32):

1. Start with one slot per size class (21 slots, ~18,000 bytes total).
2. While `slots_used < N` and `bytes_used < T`: add one more slot at the
   largest size class that fits within the remaining budget.  Prefer adding
   slots in the middle of the size range (1024–2048 octave) first, since
   medium-sized blobs (PEM certificates, SSH keys) are the most common `yb`
   workload.
3. If budget is exhausted before N slots are filled, stop early.  Report the
   actual count and total bytes allocated.
4. Never allocate more than T bytes total or more than N slots.

The result is a concrete list of `(slot_index, slot_size)` pairs, e.g.:

```
Slot  0:    64 bytes    slot  8:   512 bytes    slot 16:  1792 bytes
Slot  1:    80 bytes    slot  9:   640 bytes    slot 17:  2048 bytes
Slot  2:    96 bytes    slot 10:   768 bytes    slot 18:  2304 bytes
Slot  3:   112 bytes    slot 11:   896 bytes    slot 19:  2560 bytes
Slot  4:   128 bytes    slot 12:  1024 bytes    slot 20:  2816 bytes
Slot  5:   160 bytes    slot 13:  1280 bytes    slot 21:  3052 bytes
Slot  6:   192 bytes    slot 14:  1536 bytes    ...
Slot  7:   224 bytes    slot 15:  1792 bytes    (duplicates fill to N)
```

#### 3.1.3 Slot size stored in the object header

The existing `OBJECT_SIZE` field in the YBLOB head-chunk header (currently
unused after spec 0010) is restored to carry the pre-allocated slot size for
that slot.  `to_bytes()` zero-pads the serialized object to exactly
`slot_size` bytes.  `from_bytes()` reads `slot_size` from the header rather
than inferring it from the `GET DATA` response length.

This is backward compatible: old stores that wrote a uniform `object_size`
continue to round-trip correctly.

### 3.2 `yb format` CLI

```
yb format [OPTIONS]

Options:
  -T, --total-size BYTES    NVM budget (default: 50225)
  -N, --object-count N      Maximum number of slots (default: 32)
  -k, --key-slot SLOT       PIV slot for the store key (default: 0x82)
  -g, --generate            Generate a new store key
  -n, --subject NAME        Subject DN for the generated certificate
      --force               Erase existing yb objects without prompting
```

`--object-size` is permanently removed (was removed in spec 0010).

If existing yb objects are detected in the target slot range and `--force` is
not given, `yb format` prints the current store summary and prompts:

```
  Found existing yb store: 32 objects, key slot 0x82, age 47.
  Re-formatting will erase all stored blobs.
  Proceed? [y/N]
```

After a successful format, `yb format` prints the tier layout:

```
  Store formatted: 32 slots, 49,152 bytes pre-allocated.

  Slot sizes:
    4 ×    64 bytes     4 ×   512 bytes     4 ×  1792 bytes
    4 ×   128 bytes     4 ×  1024 bytes     4 ×  3052 bytes
    4 ×   256 bytes     4 ×  1536 bytes
```

### 3.3 Write path — slot selection and padding

When `yb set` writes a blob, the store assigns a free slot using **best-fit**:
the smallest free slot whose `slot_size` is ≥ the compressed blob's byte
length.  If no single slot is large enough, multi-slot chaining is used as
today.

The serialized object is zero-padded to exactly `slot_size` bytes before
`PUT DATA`.  This guarantees every write to a slot is at the same size,
eliminating fragmentation.

### 3.4 Blob size limit and multi-slot chaining

The maximum blob size is unchanged: multi-slot chaining allows blobs larger
than any single slot.  The head chunk's `blob_size` field bounds how many
bytes are read back; padding zeros are not returned to the caller.

### 3.5 `yb fsck` updates

`fsck` reports the tier layout and per-tier occupancy:

```
Store: 32 slots, key slot 0x82, age 14
  Tier   64 bytes:  4 slots,  2 used,  2 free
  Tier  128 bytes:  4 slots,  1 used,  3 free
  ...
  Tier 3052 bytes:  4 slots,  0 used,  4 free
Blobs: 6 stored
Free capacity: ~18,240 bytes (conservative estimate)
Status: OK
```

The free capacity estimate is `sum of slot_size for all free slots`.  This is
exact for the pre-allocated model (no NVM fragmentation).

### 3.6 User documentation

The README and man page for `yb format` must include a section explaining the
YubiKey NVM fragmentation constraint:

- The YubiKey PIV applet uses dynamic NVM allocation.  Writing an object at
  size S and then shrinking it to S' permanently wastes S−S' bytes until the
  next full PIV reset (`ykman piv reset`).
- `yb` avoids this by pre-allocating each slot at a fixed size and always
  writing at exactly that size.
- For best results, run `yb format` on a fresh YubiKey or after `ykman piv
  reset`.  Formatting over a fragmented store may yield less usable capacity
  than the nominal 50,225 bytes.
- `yb fsck` reports the current free capacity based on pre-allocated slot
  sizes, which is accurate as long as no external PIV application has written
  to the same object IDs since the last format.

## Open questions

- **Slot size stored in header vs. inferred from GET DATA.** The spec above
  restores the `OBJECT_SIZE` header field.  An alternative is to keep
  inferring size from GET DATA response length (always correct for pre-allocated
  objects, since the object is always written at full size).  The header field
  approach is more explicit; the GET DATA approach requires no header change.
  Resolve before implementation.

- **Duplicate slot sizes.** When N > 21 (the base class count), the algorithm
  adds duplicate slots at medium sizes.  The selection policy (prefer
  1024–2048 range) is a heuristic.  Should the user be able to override it
  with explicit counts per tier, e.g. `--tier 1024:8`?

- **`--force` vs. interactive prompt.** The interactive prompt is useful for
  CLI users but breaks scripted use.  `--force` suppresses it.  Is there a
  need for a `--yes` alias?

- **NVM probe integration.** Should `yb format` optionally run the NVM
  capacity probe (binary-search for actual available bytes) before allocating
  slots, to account for NVM already consumed by standard PIV slots or prior
  fragmentation?  This would be slow (~30 seconds) but give an accurate budget.
  Default: use 50,225 bytes; `--probe` flag triggers the measurement.

## References

- [spec 0010](0010-dynamic-object-sizing.md) — previous approach, abandoned due to fragmentation
- [`rust/yb-core/src/bin/nvm_frag_test.rs`](../../rust/yb-core/src/bin/nvm_frag_test.rs) — NVM fragmentation test program
- [`docs/YBLOB_FORMAT.md`](../../docs/YBLOB_FORMAT.md) — binary format specification
- jemalloc size-class design: Evans 2006/2015 — 4 sub-bins per doubling, ~20% worst-case internal fragmentation
- Wilson et al., "Dynamic Storage Allocation: A Survey and Critical Review", IWMM 1995
- YubiKey 5 NVM budget: 51,200 bytes gross; 50,225 bytes available (measured on firmware 5.4.3)
