<!--
SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# Code Quality Review — yb Rust Codebase (2026-03)

**Scope:** `rust/yb/`, `rust/yb-core/`, `rust/yb-piv-harness/`
**Version reviewed:** v0.3.0

**Overall verdict:** the codebase is production-quality.  Clippy is clean,
error handling is consistent (`Result<T>` throughout, no unwrap in library
code), sensitive data is zeroized, and the layering is clear.  The issues
below are maintainability concerns, not correctness bugs.

---

## 1. Duplicate code

### 1.1 `crypto_ecb` — six near-identical match arms

**File:** `yb-core/src/piv/tlv.rs`, lines 100–172

The function contains eight match arms for `(AlgId, Direction)`.  Six of
them are structurally identical:

```rust
use cipher::{BlockDecrypt, KeyInit};
let cipher = AesXxx::new_from_slice(key)?;
let mut b = GenericArray::clone_from_slice(&block);
cipher.decrypt_block(&mut b);
block.copy_from_slice(&b);
```

Only the concrete cipher type (`Des`, `TdesEde3`, `Aes128`, `Aes256`) and
the trait (`BlockEncrypt` vs `BlockDecrypt`) differ.  The duplication
makes the function 73 lines long and means any fix must be applied six
times.

**Recommendation:** introduce a helper macro or a closure-based helper that
accepts a `(key, block, cipher_fn)` triple.

### 1.2 `Object` construction repeated three times

**File:** `yb-core/src/orchestrator.rs`, lines 183–200, 213–230, 310–327

Three distinct call sites each construct a full `Object` literal with the
same ten common-header fields (`yblob_magic`, `object_count`,
`store_key_slot`, `object_size`, `age`, …).  Adding or renaming any field
requires editing all three sites.

**Recommendation:** add a `Store::make_object(age, chunk_pos, next_chunk)
-> Object` helper that fills in the common fields from the store's own
metadata; callers then only set the blob-specific fields.

### 1.3 TLV nested-tag extraction repeated in `session.rs`

**File:** `yb-core/src/piv/session.rs`, lines 322–329, 347–354, 386–394

Three places execute:

```rust
let outer = parse_tlv_flat(&resp).get(&OUTER_TAG)
    .ok_or_else(|| anyhow!("missing tag …"))?;
let value = parse_tlv_flat(outer).get(&INNER_TAG)
    .ok_or_else(|| anyhow!("missing tag …"))?;
```

**Recommendation:** a one-liner helper
`fn tlv_get<'a>(buf: &'a [u8], tag: u8, label: &str) -> Result<&'a [u8]>`
would eliminate the repetition and make the error messages uniform.

---

## 2. Non-idiomatic patterns

### 2.1 `if !x.is_empty() { false } else { true }` anti-pattern

**File:** `yb/src/cli/fsck.rs`, lines 170–173

```rust
} else {
    false
};
```

The `has_anomalies` binding is computed via an `if args.verbose { ... } else
{ false }` block that returns `!warnings.is_empty()`.  This is correct but
the structure is harder to read than a direct assignment.

**Recommendation:** minor; could be written as
`let has_anomalies = args.verbose && { … !warnings.is_empty() };`.

### 2.2 `needs_quoting` tests bytes instead of chars

**File:** `yb/src/cli/util.rs`, lines 110–112

```rust
fn needs_quoting(name: &str) -> bool {
    name.bytes().any(|b| !matches!(b, b'a'..=b'z' | …))
}
```

All safe characters are ASCII, so iterating bytes is correct.  However
the comment says "non-ASCII … triggers quoting", which is true as a
consequence, not as an explicit test.  The implementation is correct and
efficient; the comment could be made more precise.

### 2.3 Redundant `pub use` of `VirtualPiv` gated behind two feature flags

**File:** `yb-core/src/lib.rs`, line 56

```rust
pub use piv::{DeviceInfo, FlashHandle, PivBackend, VirtualPiv};
```

`VirtualPiv` is a test-only type but is unconditionally re-exported.
Callers outside the crate can construct it in production code.

**Recommendation:** gate the re-export:
```rust
#[cfg(any(feature = "virtual-piv", feature = "test-utils"))]
pub use piv::VirtualPiv;
```

---

## 3. Complex functions

### 3.1 `store_blob` — single function for five concerns

**File:** `yb-core/src/orchestrator.rs`, lines 90–240 (~150 lines)

`store_blob` handles: name validation, store capacity check, compression
decision, encryption, chunk layout, and writing.  Each phase is clearly
commented but the function is long enough that understanding it requires
holding five different mental models simultaneously.

**Recommendation:** extract `compress_and_encrypt(payload, opts, piv,
reader, pin) -> Result<Vec<u8>>` as a named helper.  The chunk-layout
logic that follows is already well-isolated.

### 3.2 `resolve_and_auth_management_key` — mixed concerns

**File:** `yb-core/src/piv/session.rs`, lines ~200–260

This function resolves the management key from three sources (explicit
argument, PIN-protected object, environment variable) and then performs
the three-pass mutual authentication.  Resolution logic and
authentication logic are interleaved.

**Recommendation:** split into `resolve_management_key(…) -> Result<String>`
and `authenticate_management_key(key: &str) -> Result<()>`.  The public
`authenticate_management_key` entry point that currently exists already
calls the combined function — separating resolution makes unit-testing
the resolution logic possible without touching hardware.

---

## 4. Files that are candidates for splitting

### 4.1 `yb-core/src/piv/session.rs` — 633 lines, six concerns

| Lines | Concern |
|-------|---------|
| 1–60 | Session lifecycle (`open`, `select_applet`, `transmit`) |
| 61–170 | GET DATA / PUT DATA / size probing |
| 171–270 | Management key resolution and three-pass mutual auth |
| 271–380 | GENERAL AUTHENTICATE (ECDH, ECDSA, challenge) |
| 381–480 | PIN verification, key generation, certificate read |
| 481–633 | Serial/version/attestation helpers + `sw_description` |

The file is coherent (everything is PC/SC protocol) but large.  A natural
split would be:

- `session/transport.rs` — open, select, transmit, sw_description
- `session/objects.rs` — GET DATA, PUT DATA, try_get_data_size
- `session/auth.rs` — management key resolution and mutual auth
- `session/crypto.rs` — ECDH, ECDSA, key gen, PIN
- `session/info.rs` — serial, version, attestation, certificate

This is not urgent at 633 lines but will pay off as new APDU commands are
added.

### 4.2 `yb-core/src/orchestrator.rs` — 691 lines, four concerns

| Lines | Concern |
|-------|---------|
| 1–89 | Public types (`Encryption`, `Compression`, `StoreOptions`, `BlobInfo`) |
| 90–467 | Blob CRUD (`store_blob`, `fetch_blob`, `remove_blob`, `list_blobs`) |
| 468–570 | Compression helpers (`compress_payload`, `decompress_payload`) |
| 571–691 | Tests |

A natural split:

- `orchestrator/types.rs` — public types
- `orchestrator/compression.rs` — compress/decompress
- `orchestrator/mod.rs` — CRUD operations, re-exports

The signature-trailer logic (`append_signature_trailer`,
`find_last_chunk_idx`, `collect_blob_chain`) could live in a
`orchestrator/signature.rs` module, mirroring spec 0017's own
self-contained design.

---

## 5. Public API surface

### 5.1 `Object` fields are all `pub`

**File:** `yb-core/src/store/mod.rs`, lines 23–59

All fields on `Object` are public, allowing external callers to construct
or mutate `Object` values without going through any validation.  In
practice only the CLI and tests do this, but it is an invitation to
invariant violations.

**Recommendation:** mark internal chain fields (`age`, `chunk_pos`,
`next_chunk`, `payload`) as `pub(crate)`.  Keep read-only blob metadata
fields (`blob_name`, `blob_size`, `blob_mtime`, `blob_key_slot`,
`blob_plain_size`) public as they form the natural read API.

### 5.2 `raw_ecdsa_to_der` is `pub` on an internal module

**File:** `yb-core/src/piv/session.rs`

`raw_ecdsa_to_der` is called from `yb/src/cli/util.rs` via the full path
`yb_core::piv::session::raw_ecdsa_to_der`.  This means an internal
serialization detail of `session.rs` is now part of the public API.

**Recommendation:** move `raw_ecdsa_to_der` to `yb-core/src/crypto.rs`
(which already contains related P-256 helpers) and re-export it from
`yb_core::crypto`.

---

## 6. Minor issues

| File | Issue |
|------|-------|
| `yb-core/src/piv/session.rs` | Error messages have two formats: some include a dynamic `label`, others hardcode `"GET DATA"`. Standardise to always use the dynamic label. |
| `yb/src/cli/fsck.rs` | The `Object` import is only needed for type annotations in the `detect_anomalies` helper; could be `pub(crate)` in `store/mod.rs` and then removed from `fsck.rs` imports once fields are `pub(crate)`. |
| `yb-core/src/nvm.rs` | `measure_free_nvm` (the destructive binary-search prober) and `scan_nvm` (the read-only tally) are in the same file but have very different risk profiles. A module-level doc comment flagging this distinction would help reviewers. |
| `yb/tests/cli_tests.rs` | The test file is 760+ lines with no internal structure markers beyond comments. `mod` blocks grouping tests by subsystem would improve navigability. |

---

## Priority order

1. Extract `make_object` helper in `orchestrator.rs` — small change, high
   payoff, eliminates the three-site duplication before the struct grows
   more fields.
2. Refactor `crypto_ecb` — most egregious duplication; self-contained
   change in `tlv.rs`.
3. Move `raw_ecdsa_to_der` to `crypto.rs` — seals the leaking internal.
4. Mark `Object` fields `pub(crate)` — prevents future invariant
   violations; requires updating test code that constructs `Object`
   literals directly.
5. Split `session.rs` — deferred until the file grows further or new APDU
   commands are needed.
