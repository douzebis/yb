<!--
SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0011 — Refactoring Opportunities and Test Coverage Gaps

**Status:** implemented
**App:** yb (Rust)
**Implemented in:** 2026-03-21

## Problem

A code review of the Rust implementation of yb reveals several categories of
opportunity:

1. **Non-idiomatic or unnecessarily complex code** that can be simplified using
   standard Rust idioms without changing behavior.
2. **Duplicated logic** that appears in two or more places and should be unified
   behind a shared helper.
3. **Missing unit and integration tests** for paths that are currently exercised
   only implicitly (if at all).

None of these are bugs, but addressing them will make the codebase easier to
maintain, extend, and reason about.

---

## Goals

- Enumerate every refactoring opportunity with enough detail to act on each one
  independently.
- Enumerate every test gap with a concrete description of what should be tested
  and where the test should live.
- Serve as a backlog: items can be picked off individually without requiring a
  single large PR.

## Non-goals

- Changing the wire format, public API, or observable CLI behavior.
- Implementing spec 0010 (dynamic object sizing) — that is a separate concern.
- Micro-optimizations with no legibility benefit.

---

## Specification

### Part 1 — Refactoring Opportunities

---

#### R1 — Duplicated glob-resolution loop in `fetch.rs` and `remove.rs`

**Location:** `rust/yb/src/cli/fetch.rs:60-89`, `rust/yb/src/cli/remove.rs:31-67`

Both `fetch::run` and `remove::run` contain nearly identical code that:

1. Iterates over a `Vec<String>` of patterns.
2. Checks whether each pattern is a glob (contains `*`, `?`, or `[`).
3. Builds a `GlobBuilder` matcher and collects matching blob names.
4. Falls through to exact-match logic for plain names.
5. Deduplicates the result with `!matched.contains(&name)`.

The deduplication is O(n²) via linear `Vec::contains` — a minor inefficiency
that also differs between the two files (`matched.contains` vs
`to_remove.iter().any`), creating a latent inconsistency.

**Proposed fix:** Extract a free function in a shared module (e.g.
`yb/src/cli/util.rs` or `yb_core`) with signature:

```rust
pub fn resolve_patterns<'a>(
    patterns: &[String],
    blob_names: &'a [String],
    ignore_missing: bool,
) -> Result<Vec<&'a str>>
```

Use an `IndexSet` (or `Vec` + `HashSet` seen-guard) for O(1) deduplication.

---

#### R2 — `crypto_ecb_decrypt` / `crypto_ecb_encrypt` are a copy-paste pair

**Location:** `rust/yb-core/src/piv/hardware.rs:706-772`

`crypto_ecb_decrypt` and `crypto_ecb_encrypt` share the exact same structure:
both call `crypto_ecb_op`, both `match key.len()` over 24 / 16 / 32 bytes, and
both call the equivalent `Aes*/TdesEde3` type with only the encrypt/decrypt
direction differing.  The bodies of the two functions are ~60 lines of almost
identical code.

**Proposed fix:** Introduce an enum or boolean `direction` parameter, then
unify into a single `crypto_ecb` function:

```rust
enum EcbDirection { Encrypt, Decrypt }

fn crypto_ecb(key: &[u8], data: &[u8], block_size: usize, dir: EcbDirection) -> Result<Vec<u8>>
```

Or, since `crypto_ecb_op` already takes a closure, lift the closure
construction into a helper per algorithm so the match arms are not duplicated:

```rust
fn des3_ecb_block_op(key: &[u8], block: &mut [u8], dir: EcbDirection) -> Result<()> { ... }
fn aes128_ecb_block_op(key: &[u8], block: &mut [u8], dir: EcbDirection) -> Result<()> { ... }
fn aes256_ecb_block_op(key: &[u8], block: &mut [u8], dir: EcbDirection) -> Result<()> { ... }
```

---

#### R3 — `Object::reset()` sets every field explicitly; use `Default`

**Location:** `rust/yb-core/src/store/mod.rs:177-188`

`Object::reset()` manually zeros eleven fields.  Because `Object` does not
derive `Default`, a future contributor adding a new field may forget to reset
it.

**Option A:** Derive `Default` on `Object` and implement `reset` as:

```rust
pub fn reset(&mut self) {
    let preserved_index = self.index;
    let preserved_size  = self.object_size;
    *self = Self {
        index:       preserved_index,
        object_size: preserved_size,
        yblob_magic: YBLOB_MAGIC,
        dirty: true,
        ..Default::default()
    };
}
```

**Option B:** Keep `reset()` as-is but add a `#[allow(missing_docs)]` comment
noting that any new field must be reset here and in `Store::format`.

Option A is preferred: the compiler will catch forgotten fields if `Default` is
derived rather than implemented by hand.

---

#### R4 — Chunk-count calculation duplicated between `orchestrator.rs` and `cli/store.rs`

**Location:** `rust/yb-core/src/orchestrator.rs:75-79`,
`rust/yb/src/cli/store.rs:101-118`

`orchestrator::store_blob` computes `chunks_needed` from `head_cap` and
`cont_cap`.  `cli::store::run` re-implements the same arithmetic for its
all-or-nothing capacity pre-check (using an approximated encrypted size).  The
two computations diverge: the CLI uses `payload.len() + 94` as a GCM
approximation while the orchestrator uses the actual encrypted length.

**Proposed fix:** Expose a free function from `yb_core`:

```rust
pub fn chunks_needed_for(data_len: usize, name_len: usize, object_size: usize) -> usize
```

Let `cli::store::run` call it with `payload.len() + crypto::GCM_OVERHEAD` (a
new public constant) instead of the inline approximation.  This removes the
duplicate arithmetic and makes the approximation explicit and testable.

Note: `crypto::GCM_OVERHEAD` (currently the unlabeled literal `94` at
`cli/store.rs:106`) should be promoted to a named constant in `crypto.rs`
regardless.

---

#### R5 — `encode_length` panics on large inputs; use `Result` or a doc constraint

**Location:** `rust/yb-core/src/piv/hardware.rs:617-627`

```rust
fn encode_length(len: usize) -> Vec<u8> {
    // ...
    } else {
        panic!("length too large for BER encoding: {len}");
    }
}
```

A `panic!` in library code is non-idiomatic unless the invariant is
contractually guaranteed by the caller.  Here, the length comes from
user-supplied object data, so the input can in principle be large.

**Proposed fix:** Return `Result<Vec<u8>>` and propagate with `?`, or add a
debug-mode `assert` and a doc comment that states the precondition (`len ≤
0xFFFF` which is guaranteed for PIV data objects whose max is 3,052 bytes).
The latter is acceptable given the existing PIV size constraints.

---

#### R6 — `parse_tlv_flat` silently ignores malformed TLV

**Location:** `rust/yb-core/src/auxiliaries.rs:29-47`

On a truncated length or value field, the loop simply `break`s:

```rust
if i + len > data.len() {
    break;
}
```

This means a truncated APDU response is parsed as a shorter-than-expected map
rather than an error.  Code that later calls `.get(&tag).ok_or_else(...)` will
produce a confusing "missing tag X" error instead of "malformed TLV".

**Proposed fix:** Change `parse_tlv_flat` to `Result<HashMap<u8, Vec<u8>>>` and
return `Err` on truncation.  Or keep it infallible but add a second return value
indicating whether parsing consumed all bytes.  The latter is a smaller change
with no API churn.

---

#### R7 — `save_fixture` method name collision / redundant delegation

**Location:** `rust/yb-core/src/piv/virtual_piv.rs:452-454`

The `PivBackend` trait impl for `VirtualPiv` delegates `save_fixture` to an
inherent method of the same name via `VirtualPiv::save_fixture(self, path)`.
This explicit call is redundant — `self.save_fixture(path)` would call the
inherent method directly — but it is subtly confusing because it looks like a
recursive call:

```rust
fn save_fixture(&self, path: &std::path::Path) -> Result<()> {
    VirtualPiv::save_fixture(self, path)
}
```

**Proposed fix:** Replace with `self.save_fixture_impl(path)` by renaming the
inherent method to `save_fixture_impl`, or simply call `self.do_save_fixture()`
with a distinct name.  Alternatively, remove the name conflict by making the
`PivBackend` default trait method call the inherent method with a different
name.

---

#### R8 — `get_pin_protected_management_key` leaks a PC/SC coupling into `auxiliaries.rs`

**Location:** `rust/yb-core/src/auxiliaries.rs:203-214`

`get_pin_protected_management_key` bypasses the `PivBackend` trait and opens a
`PcscSession` directly, making `auxiliaries.rs` aware of `hardware::PcscSession`:

```rust
pub fn get_pin_protected_management_key(
    reader: &str,
    _piv: &dyn PivBackend,   // ignored!
    pin: &str,
) -> Result<String> {
    use crate::piv::hardware::PcscSession;
    let mut session = PcscSession::open(reader)?;
    // ...
}
```

The `_piv` parameter is silently ignored.  This is a design smell: the function
always uses the hardware backend regardless of what `Context` has selected.
The `VirtualPiv` path is unreachable here, which means PIN-protected mode
cannot be tested via `Context::with_backend(VirtualPiv)`.

**Proposed fix:** Move the "verify PIN then read PRINTED object" logic into the
`PivBackend` trait as a default method (or add a `read_printed_object_with_pin`
method), and remove the direct `PcscSession` import from `auxiliaries.rs`.
Alternatively, add a dedicated method to the `PivBackend` trait and implement
it in both `HardwarePiv` and `VirtualPiv`.

---

#### R9 — `alloc_free` always returns the lowest-index free slot (not a concern, but worth noting)

**Location:** `rust/yb-core/src/store/mod.rs:394-396`

`alloc_free` uses `find` which always returns the first (lowest-index) free
slot.  This is fine — the allocation order only determines how objects appear on
disk and does not affect correctness.  However, it means newly written blobs
cluster at the low end while higher-index slots stay free, which could make
`fsck -v` output harder to read.  No code change required; this is a note for
documentation.

---

#### R10 — `store.rs` capacity check in `cli/store.rs` does not account for overwriting existing blobs

**Location:** `rust/yb/src/cli/store.rs:101-136`

The all-or-nothing pre-check (`total_chunks ≤ store.free_count()`) counts only
currently free slots.  However, `orchestrator::store_blob` removes the existing
blob of the same name before allocating new slots.  If the user re-stores a
blob that already exists, the pre-check may incorrectly reject the operation
when it would in fact succeed (the freed slots are counted back by the
orchestrator).

**Proposed fix:** When computing the capacity check, subtract from
`total_chunks` the number of chunks that will be freed by overwriting existing
same-name blobs.

---

### Part 2 — Missing Tests

---

#### T1 — `Store::sanitize` is never tested directly

**Location:** `rust/yb-core/src/store/mod.rs:307-355`

`sanitize` performs three actions: removes stale duplicate heads (keeping the
one with the higher age), collects reachable chunk indices, and resets
unreachable occupied objects.  None of these paths has a unit test.

**Test cases to add (in `store/mod.rs` or a separate `store_tests.rs`):**

1. Two head objects with the same name → `sanitize` keeps the one with higher
   age.
2. A continuation chunk whose head has been reset → `sanitize` marks it empty.
3. A store with no anomalies → `sanitize` is a no-op (no objects become dirty).

---

#### T2 — `Store::chunk_chain` cycle detection is absent and untested

**Location:** `rust/yb-core/src/store/mod.rs:411-423`

`chunk_chain` walks `next_chunk` pointers until `next == idx` (self-reference).
If a corrupt store has a cycle (A → B → A), the function loops forever.  There
is no cycle guard and no test for malformed chains.

**Tests to add:**
- Write a test that constructs a chain with a non-terminating `next_chunk` and
  verify that `chunk_chain` either terminates (with a cycle guard added) or that
  `fsck` detects the anomaly.

**Code change needed:** Add a `seen: HashSet<u8>` guard in `chunk_chain` and
return early (or return an error) on revisit.

---

#### T3 — `crypto.rs` GCM decryption of a tampered ciphertext

**Location:** `rust/yb-core/src/crypto.rs`

The existing `encrypt_decrypt_roundtrip` test verifies the happy path.  There
is no test that verifies authentication failure when the ciphertext is mutated.

**Test case to add:**

```rust
#[test]
fn tampered_ciphertext_fails_authentication() {
    // Encrypt something, flip a byte in the ciphertext, verify decrypt errors.
}
```

---

#### T4 — `hybrid_decrypt` rejects unknown version bytes

**Location:** `rust/yb-core/src/crypto.rs:120-124`

The `match` on `encrypted[0]` handles `0x02`, `0x04`, and falls through to an
error.  There is no test that passes a blob with, e.g., `0x03` as the first
byte.

**Test case to add:**

```rust
#[test]
fn unknown_version_byte_rejected() {
    let mock = /* minimal MockPiv */;
    let blob = vec![0x03u8, 0x00]; // unknown version
    assert!(hybrid_decrypt(&mock, "r", 0x82, &blob, None, false).is_err());
}
```

---

#### T5 — `hybrid_decrypt` on an empty input

**Location:** `rust/yb-core/src/crypto.rs:116-118`

The early bail for an empty blob is tested only by code inspection, not by a
test.

**Test case to add:**

```rust
#[test]
fn empty_blob_rejected() {
    let mock = /* minimal MockPiv */;
    assert!(hybrid_decrypt(&mock, "r", 0x82, &[], None, false).is_err());
}
```

---

#### T6 — `validate_name` edge cases: max-length name and exactly `MAX_NAME_LEN + 1`

**Location:** `rust/yb-core/src/orchestrator.rs:263-274`

The existing `validate_name_invalid_chars` test does not test boundary lengths.

**Test cases to add:**

```rust
#[test]
fn validate_name_length_boundaries() {
    assert!(validate_name("").is_err());
    // 255-byte name — max allowed.
    assert!(validate_name(&"x".repeat(MAX_NAME_LEN)).is_ok());
    // 256-byte name — one over max.
    assert!(validate_name(&"x".repeat(MAX_NAME_LEN + 1)).is_err());
}
```

---

#### T7 — `BlobInfo::mtime_local` is never tested

**Location:** `rust/yb-core/src/orchestrator.rs:28-34`

`mtime_local` is feature-gated on `chrono` and has no test.  The
`unwrap_or_else(chrono::Local::now)` fallback is exercised only when
`timestamp_opt` returns `LocalResult::None`, which happens for out-of-range
timestamps.

**Test cases to add (with `#[cfg(feature = "chrono")]`):**

1. A zero `mtime` → should not panic (returns `Local::now()` or an arbitrary
   valid datetime depending on the platform).
2. `mtime = 1_700_000_000` → `mtime_local()` returns a datetime in 2023.
3. `mtime = u32::MAX` → very far future timestamp; should not panic.

---

#### T8 — `Store::from_device` with a mismatched object count

**Location:** `rust/yb-core/src/store/mod.rs:230-263`

`from_device` reads `object_count` from the first object and then blindly reads
that many subsequent objects.  There is no test that:

- Uses a `VirtualPiv` with the first object claiming `object_count = 5` but
  only 3 objects actually written.
- Verifies that `from_device` returns an appropriate error rather than panicking
  on the missing object IDs.

---

#### T9 — `fsck` verbose output and exit-code 1 on anomaly are not tested

**Location:** `rust/yb/src/cli/fsck.rs`, `rust/yb/tests/cli_tests.rs`

The existing `fsck_clean_store` test only covers a healthy store.  Missing:

1. `fsck` on a store with a duplicate-name anomaly → test that `run` returns
   `Ok(())` but `detect_anomalies` returns a non-empty vec (since `process::exit`
   cannot be caught in unit tests, test `detect_anomalies` directly).
2. `fsck -v` produces per-object output for occupied objects.
3. An orphaned continuation chunk is reported.

`detect_anomalies` should be made `pub(crate)` or `pub` so it can be called in
tests without going through `run`.

---

#### T10 — `auxiliaries::check_for_default_credentials` skip path (firmware < 5.3)

**Location:** `rust/yb-core/src/auxiliaries.rs:107-149`

When `piv.send_apdu` returns `Err`, the function returns `Ok(())` early.  This
path (old firmware or unsupported APDU) is never tested.  With `VirtualPiv`
returning an empty vec for `send_apdu`, the check always proceeds to the
metadata parse path, so the Err-early-return is dead code in tests.

**Test to add:** A mock `PivBackend` whose `send_apdu` always errors should
cause `check_for_default_credentials` to return `Ok(())` immediately.

---

#### T11 — `Context::with_backend` with multiple devices returns an error

**Location:** `rust/yb-core/src/context.rs:101-133`

The error case ("multiple devices in backend") is documented but never tested.
A `VirtualPiv` always exposes exactly one device, so a test would need a custom
`PivBackend` stub returning two devices.

---

#### T12 — `Store::format` with `object_count = 0` or `object_count = 255`

**Location:** `rust/yb-core/src/store/mod.rs:266-305`

Boundary values for `object_count` are never tested.  What happens with 0
objects?  (`for i in 0..0` is a no-op; the store writes nothing, which is odd
but probably not a panic.)

---

#### T13 — `Store::alloc_free` returns `None` on a full store

**Location:** `rust/yb-core/src/store/mod.rs:394-396`

There is no test that verifies `alloc_free` returns `None` when all slots are
occupied.

**Test to add:** Fill a small store (e.g. 2 objects), then call `alloc_free` and
assert `None`.

---

#### T14 — `store_blob` returns `false` (store full) without mutating the store

**Location:** `rust/yb-core/src/orchestrator.rs:81-83`

`store_blob` returns `Ok(false)` when the store is full.  There is no test
verifying this path, and no test verifying that the store is left completely
unmodified (no partial state) when the capacity check fails.

---

#### T15 — `PcscSession::put_data` chained APDU path has no integration-test coverage

**Location:** `rust/yb-core/src/piv/hardware.rs:101-150`

This path is exercised by hardware/vsmartcard tests but not by `VirtualPiv`
(which stores data in a `HashMap` directly).  The chaining logic (CLA=0x10 on
all but last chunk) is only validated against real or emulated hardware.

This is a structural gap rather than something fixable in unit tests, but it
should be noted so the integration test suite (spec 0009) verifies at least one
object write that exceeds 255 bytes and thus requires chaining.

---

## Open Questions

- R8 (PIN-protected mode via `PivBackend` trait): is it acceptable to add a new
  method to `PivBackend`, or would a wrapper at the `Context` level be
  preferable to avoid widening the trait?
- T2 (cycle detection in `chunk_chain`): should the guard panic (internal
  invariant violation) or return an error (user-visible corruption)?  The latter
  is friendlier for `fsck`.

## References

- Spec 0008 (CLI direct-call tests): the T-series items above identify gaps in
  the test suite established by that spec.
- Spec 0009 (CLI subprocess tests): T15 should be verified there.
- `rust/yb-core/src/store/mod.rs` — Object, Store
- `rust/yb-core/src/orchestrator.rs` — store_blob, fetch_blob
- `rust/yb-core/src/crypto.rs` — hybrid_encrypt, hybrid_decrypt
- `rust/yb-core/src/piv/hardware.rs` — HardwarePiv, PcscSession
- `rust/yb-core/src/piv/virtual_piv.rs` — VirtualPiv
- `rust/yb-core/src/auxiliaries.rs` — TLV helpers, credential checks
- `rust/yb/src/cli/fetch.rs`, `rust/yb/src/cli/remove.rs`
