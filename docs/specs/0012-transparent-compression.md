<!--
SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0012 — Transparent Compression

**Status:** draft
**App:** yb (Rust)
**Implemented in:** <!-- YYYY-MM-DD, fill after implementation -->

## Problem

Blobs stored on a YubiKey are subject to a hard NVM capacity limit (~51,200 bytes
on a YubiKey 5).  Many natural use cases — SSH keys, certificates, config files,
scripts — consist of ASCII or structured text that compresses well.  At present
`yb` stores every blob verbatim, wasting NVM that could hold additional secrets.

Beyond capacity, compression before encryption is the correct construction order:
compressing ciphertext is ineffective (ciphertext is indistinguishable from
random), while compressing plaintext before encryption reduces the amount of data
that the YubiKey's NVM must store and the amount of data that traverses the PC/SC
bus.

## Goals

- Compress every blob before encryption (or before storage, for unencrypted blobs)
  by default, using the better of **brotli level 11** and **xz preset 9**.
- Decompress transparently on fetch, using magic bytes to dispatch to the correct
  decompressor.
- Blobs that do not shrink under compression are stored uncompressed.
- Full **backward compatibility**: a new `yb` binary can read all blobs written by
  older binaries.  Old blobs are never re-compressed unless explicitly re-stored.
- Forward compatibility note for readers: an old `yb` binary that does not
  implement this spec will read a compressed blob as raw bytes (it will not
  decompress).  The user will see garbled data.  This is acceptable — old binaries
  pre-date the spec.

## Non-goals

- Supporting further compression algorithms beyond brotli and xz.
- A `--compression-level` flag.  Fixed levels are always used.
- Recompressing existing blobs in place.  The store is not walked or migrated.
- Compressing blob names.

---

## Specification

### 1. Wire-format change — compression flag bit

The existing head-chunk layout (spec YBLOB_FORMAT) has a `blob_plain_size` field
at offset `0x13` (3 bytes, u24 LE).  The maximum plaintext size that can ever be
stored is bounded by the total NVM available (~51,200 bytes), so the true range is
[0, 65535].  Bits 16–23 of the u24 are always zero in existing blobs.

**Bit 23 of `blob_plain_size` (the most significant bit of the u24) is repurposed
as the compression flag:**

```
blob_plain_size field (3 bytes, u24 LE at offset 0x13):

  byte 0x15  byte 0x14  byte 0x13
  ┌────────┐ ┌────────┐ ┌────────┐
  │C│ 0000 │ │        │ │        │
  └────────┘ └────────┘ └────────┘
   │└───────────────────────────── plain_size bits 16..22 (always 0)
   └─────────────────────────────── C = 1 if blob is compressed, 0 otherwise
```

- **C = 0**: blob payload is raw plaintext (after decryption if encrypted).
  Behavior is identical to the current implementation.
- **C = 1**: blob payload is compressed (after decryption if encrypted).
  The compression algorithm is identified by the magic bytes at the start of
  the payload (see §8).  `fetch_blob` must decompress before returning.

`blob_plain_size` (with bit 23 masked off) continues to hold the **original
uncompressed plaintext size** in bytes.  The `Object` struct gains a companion
`is_compressed: bool` field that carries the extracted C bit (see §4).

The `blob_size` field (u24 at offset `0x0F`) continues to hold the number of
bytes actually stored across the chunk chain (compressed+encrypted, or
compressed, or raw — whichever the pipeline produces).

#### Backward compatibility

Old `yb` binaries never set bit 23 (their blobs have C = 0) and read `blob_plain_size`
directly.  They will never encounter a C = 1 blob unless a new `yb` wrote one to
the same store.  In that case an old binary will see `blob_plain_size` with a large
spurious value (bit 23 set adds 8,388,608 to the decoded u24) and may display an
incorrect size in `list -l`.  It will also return raw compressed bytes from `fetch`
instead of the plaintext.  No data corruption or panic occurs.

This is acceptable: mixing old and new binaries against the same store is not a
supported configuration.

### 2. Compression pipeline

On **store**:

```
plaintext.len() > 0x7FFFFF?  →  error (plain size always stored in 23-bit field)

plaintext  →  [brotli level 11]  →  candidate_b
           →  [xz preset 9]      →  candidate_x

pick = smaller of candidate_b and candidate_x
                    │
       ┌────────────┴────────────┐
       │                         │
  pick.len() <             pick.len() >=
  plaintext.len()          plaintext.len()
  (compression helped)     (compression didn't help)
       │                         │
  C=1, candidate           C=0, candidate
  = pick                   = plaintext
       │                         │
       └──────────┬──────────────┘
                  ↓
     [encrypt if requested]
                  ↓
           stored bytes

stored bytes.len() > 0x7FFFFF?  →  error (blob_size is also a 23-bit field)
```

In prose:

1. If `plaintext.len() > 0x7FFFFF`: error — the uncompressed size is always
   written into the 23-bit `blob_plain_size` field (with C in bit 23), so this
   limit is unconditional.
2. Compress with brotli level 11 → `candidate_b`.
3. Compress with xz preset 9 → `candidate_x`.
4. Verify `candidate_b` starts with the brotli prefix `\x59\x42\x72\x01` after
   prepending (see §8) — fail hard if not (bug in compression library).
5. Verify `candidate_x` starts with xz magic `\xFD7zXZ\x00` — fail hard if not
   (bug in compression library).
6. `pick` = whichever of `candidate_b`, `candidate_x` is smaller.
7. If `pick.len() < plaintext.len()`: candidate = pick, C=1.
8. Else: candidate = plaintext, C=0.
9. Encrypt candidate if requested (adds `GCM_OVERHEAD`).
10. If `stored.len() > 0x7FFFFF`: error — `blob_size` is also a u24 field.

The compression decision is made once per `store_blob` call, before encryption.
The result (C flag and chosen bytes) is fixed at write time and never
re-evaluated on subsequent reads.

On **fetch**:

```
stored bytes  →  [decrypt if encrypted]  →  payload
                                              ↓ if C = 1
                                    inspect magic bytes
                                    ├─ xz magic     →  [xz decompress]
                                    └─ brotli magic →  [brotli decompress]
                                              ↓
                                          plaintext
```

### 3. `store_blob` API change

`store_blob` gains a `compression: Compression` parameter (analogous to the
existing `encryption: Encryption` parameter):

```rust
pub enum Compression {
    /// Try brotli and xz; use whichever is smaller, skip if result is not smaller.
    Auto,
    /// Never compress (for backward compatibility or binary blobs).
    None,
}
```

The default at all call sites (CLI and library) is `Compression::Auto`.

A `--no-compress` CLI flag (on `yb store`) allows opting out.
No `--compress` flag is needed since `Auto` is the default.

### 4. Deserialization — C-bit masking

When `Object::from_bytes` reads `blob_plain_size` from the wire, it **must mask
off bit 23** before storing the value in the in-memory `blob_plain_size: u32`
field.  The C flag is extracted separately into an `is_compressed: bool` field on
`Object`.

```rust
let raw_plain = read_u24_le(data, BLOB_PLAIN_SIZE_O);
let is_compressed = (raw_plain >> 23) & 1 == 1;
let blob_plain_size = raw_plain & 0x7F_FFFF;
```

Conversely, `Object::to_bytes` **must OR in bit 23** when writing:

```rust
write_u24_le(&mut buf, BLOB_PLAIN_SIZE_O,
    self.blob_plain_size | if self.is_compressed { 0x80_0000 } else { 0 });
```

This keeps the in-memory `blob_plain_size` equal to the true uncompressed size at
all times, so `list_blobs` and `plain_size` in `BlobInfo` are always correct
without further masking.

`BlobInfo` does **not** gain an `is_compressed` field — compression is fully
transparent and not surfaced to callers or the `list` command.

### 5. `GCM_OVERHEAD` and capacity pre-check

`cli/store.rs` pre-checks capacity before writing.  The compressed size is not
known until compression is attempted, which happens inside `store_blob`.  The
pre-check therefore uses the **uncompressed size** as a conservative upper bound
(worst case: compression makes no progress, C = 0 path is taken):

```rust
let enc_len = if encrypted {
    payload.len() + GCM_OVERHEAD
} else {
    payload.len()
};
let chunks = chunks_needed(enc_len, name.len(), store.object_size);
```

This is identical to the current behavior and remains correct because the C = 1
path can only reduce the number of chunks needed.

### 6. `chunks_needed` for the CLI pre-check

No change to `chunks_needed`.  The pre-check is already a conservative estimate.

### 7. Dependencies

Add to `yb-core/Cargo.toml`:

```toml
brotli  = "6"
lzma-rs = "0.3"
```

Both are pure Rust — no C dependency, no additional `buildInputs` in `default.nix`.

`lzma-rs` implements LZMA2 in pure Rust and produces standard xz container output.
If it proves incompatible with the system `xz` tool, switch to `xz2` (wraps
liblzma) and add `pkgs.xz` to `default.nix` `buildInputs`.

### 8. Magic bytes and algorithm dispatch

Both algorithms produce output with well-known magic bytes at offset 0:

| Algorithm | Magic bytes (hex)          |
|-----------|----------------------------|
| xz        | `FD 37 7A 58 5A 00`        |
| brotli    | no universal magic — see below |

Brotli's raw format has no mandatory magic bytes.  To enable unambiguous
dispatch, compressed brotli payloads are prefixed with a 4-byte tag before
storage:

```
\x59\x42\x72\x01   ("YBr\x01" — yb brotli version 1)
```

The xz magic `\xFD7zXZ\x00` is already emitted by `lzma-rs` / `xz2` as part of
the standard container format — no prefix needed.

On **store**, after compressing:
- Assert that the xz output starts with `\xFD7zXZ\x00`.
- Prepend `\x59\x42\x72\x01` to the brotli output.

On **fetch**, if C=1, inspect the first bytes of the payload to dispatch:
- `\xFD7zXZ\x00` → xz decompress.
- `\x59\x42\x72\x01` → strip 4-byte prefix, brotli decompress.
- Anything else → error: corrupt store.

### 9. Compression levels

- **brotli**: level 11 (maximum compression; slow but called only at store time).
- **xz**: preset 9 (maximum compression).

Typical compression ratios for common key material:
- PEM RSA private key (1,700 bytes): brotli ~60% / xz ~55% → ~680 / ~770 bytes
- SSH authorized_keys (300 bytes): brotli ~50% / xz ~45% → ~150 / ~165 bytes
- Random binary (AES key): neither helps → C = 0 path taken

### 10. Error handling

- Plaintext too large: if `plaintext.len() > 0x7FFFFF`, error immediately before
  compression is attempted.
- Stored bytes too large: if the final stored bytes (after optional encryption)
  exceed 0x7FFFFF, error before any write occurs.
- Magic verification failure on store: if the compressor output does not start
  with the expected magic bytes, fail hard with a descriptive error (this
  indicates a bug in the compression library or a version mismatch, not a user
  error).
- Compression failure on store: propagate as an error.  No partial writes occur.
- Decompression failure on fetch: propagate as an `anyhow::Error` with context
  `"decompressing blob '{name}'"`.  This indicates a corrupt store.
- Unknown magic on fetch (C=1 but no recognized header): propagate as an error
  `"unknown compression format in blob '{name}'"`.

---

## Open Questions

- Confirm that `lzma-rs` preset-9 output is readable by the system `xz` tool
  (it should be, since both use the xz container format).
- The 0x7FFFFF limit is unreachable in practice (YubiKey NVM ~51,200 bytes), but
  `store_blob` must check explicitly rather than silently corrupt bit 23 of
  `blob_plain_size` or `blob_size`.

---

## References

- YBLOB_FORMAT spec (in-tree): field layout and offsets
- Spec 0006 (security hardening): compress-then-encrypt is the standard order
- `brotli` crate: https://crates.io/crates/brotli
- `lzma-rs` crate: https://crates.io/crates/lzma-rs
- `xz2` crate: https://crates.io/crates/xz2
- Spec 0010 (dynamic object sizing): related NVM efficiency work
