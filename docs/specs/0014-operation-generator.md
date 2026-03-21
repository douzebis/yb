<!--
SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0014 — ToyFilesystem and OperationGenerator Test Primitives

**Status:** draft
**App:** yb (Rust)
**Implemented in:** <!-- YYYY-MM-DD, fill after implementation -->

## Problem

The existing Tier-1 unit tests exercise individual functions with hand-crafted
inputs.  They do not cover interaction sequences — overlapping stores, updates to
existing blobs, interleaved removes and fetches, capacity pressure near the store
limit.  These interaction patterns are where real bugs hide.

The Python version has two reusable test primitives (`ToyFilesystem` and
`OperationGenerator`) that were used both in Tier-3 self-tests against real
hardware and in deterministic unit tests.  No equivalent exists in the Rust
codebase.

## Goals

- Port `ToyFilesystem` and `OperationGenerator` to Rust, available to both the
  Tier-1 unit test suite (`yb-core`) and the forthcoming Tier-3 self-test command.
- Add a seeded randomized Tier-1 integration test (`test_random_operations`) that
  drives a `VirtualPiv` in-memory store through N operations and verifies every
  fetch against the ground truth — no hardware required.

## Non-goals

- Replacing hand-crafted unit tests.
- Covering encryption in `test_random_operations` (encryption is already covered
  by dedicated tests; randomized coverage of it adds little and slows the test).

---

## Specification

### 1. `ToyFilesystem`

An in-memory model of the expected store state.  Maps blob name to
`(payload, mtime)`.

```rust
pub struct ToyFilesystem {
    files: HashMap<String, (Vec<u8>, u32)>,
}

impl ToyFilesystem {
    pub fn new() -> Self;
    pub fn store(&mut self, name: &str, payload: Vec<u8>, mtime: u32);
    pub fn fetch(&self, name: &str) -> Option<&(Vec<u8>, u32)>;
    pub fn remove(&mut self, name: &str) -> bool;  // true if existed
    pub fn list(&self) -> Vec<String>;              // sorted
}
```

### 2. `OperationGenerator`

Produces a deterministic sequence of operations from a fixed seed.

```rust
pub enum OpType { Store, Fetch, Remove, List }

pub struct Operation {
    pub op_type: OpType,
    pub name: String,
    pub payload: Vec<u8>,   // non-empty only for Store
    pub encrypted: bool,    // for Store: whether to encrypt
}

pub struct OperationGenerator {
    rng: /* seeded SmallRng or StdRng */,
    max_capacity: usize,
    existing: HashSet<String>,
}

impl OperationGenerator {
    pub fn new(seed: u64, max_capacity: usize) -> Self;
    pub fn generate(&mut self, count: usize, encryption_ratio: f64) -> Vec<Operation>;
}
```

#### Operation distribution

Weights vary with fill level to keep the store exercised at all fill states:

| Fill level | Store | Fetch | Remove | List |
|------------|-------|-------|--------|------|
| empty      | 100%  | 0%    | 0%     | 0%   |
| < 80%      | 40%   | 35%   | 15%    | 10%  |
| 80–100%    | 25%   | 35%   | 25%    | 15%  |
| at capacity | 20%  | 40%   | 30%    | 10%  |

At capacity, stores always target an existing name (update) to avoid attempting
a new allocation.  Below capacity, 30% of stores target an existing name.

#### Payload size distribution

- 70%: small, 1–1,024 bytes
- 25%: medium, 1,025–5,120 bytes
- 5%: large, 5,121–16,384 bytes

Payload bytes are random (uniform).

#### Non-existent name probing

- 10% of Fetch operations target a name not in the store.
- 10% of Remove operations target a name not in the store.

These probe the "not found" code paths.

#### Name pool

A fixed pool of 24 short ASCII names (matching the Python version):
`config`, `secret`, `backup`, `key`, `cert`, `data`, `log`, `cache`,
`index`, `metadata`, `state`, `info`, `settings`, `profile`, `session`,
`token`, `auth`, `creds`, `database`, `schema`, `archive`, `snapshot`,
`checkpoint`, `manifest`.

New names that collide with existing ones get a numeric suffix
(`config-1234`).

### 3. Placement in the codebase

Both types live in `yb-core/src/test_utils.rs`, gated behind
`#[cfg(any(test, feature = "test-utils"))]`.

A new `test-utils` feature is added to `yb-core/Cargo.toml`:

```toml
[features]
test-utils = []
```

The self-test CLI command (spec 0015) depends on this feature being enabled in
`yb/Cargo.toml`:

```toml
yb-core = { path = "../yb-core", features = ["test-utils", "chrono"] }
```

`rand` is already a dev-dependency of `yb-core`; it must be promoted to a
regular dependency (gated behind the `test-utils` feature) so the self-test
binary can use it at runtime:

```toml
[dependencies]
rand = { version = "0.8", optional = true }

[features]
test-utils = ["dep:rand"]
```

### 4. Tier-1 randomized test

Add `test_random_operations` to `yb-core/tests/virtual_piv_tests.rs`:

```rust
/// Seeded random store/fetch/remove/list operations against VirtualPiv.
/// Verifies every fetch result against ToyFilesystem ground truth.
#[test]
fn test_random_operations() {
    // 4-object × 512-byte store → small, exercises capacity pressure
    let piv = with_key_piv();
    let mgmt = "010203040506070801020304050607080102030405060708";
    let mut store = formatted_store(&piv);   // 8 objects × 512 bytes

    let mut toy = ToyFilesystem::new();
    let mut gen = OperationGenerator::new(42, 7); // max_capacity = 7 (< 8 objects)
    let ops = gen.generate(300, 0.0);             // no encryption for speed

    for op in &ops {
        match op.op_type {
            OpType::Store => {
                let ok = store_blob(&mut store, &piv, &op.name, &op.payload,
                                    Encryption::None, Some(mgmt), None).unwrap();
                if ok {
                    toy.store(&op.name, op.payload.clone(), 0);
                }
                // ok=false (full) is valid; ground truth unchanged
            }
            OpType::Fetch => {
                let reader = piv.reader_name();
                let result = fetch_blob(&store, &piv, &reader, &op.name, None, false).unwrap();
                let expected = toy.fetch(&op.name).map(|(p, _)| p.as_slice());
                assert_eq!(result.as_deref(), expected,
                    "fetch '{}' mismatch", op.name);
            }
            OpType::Remove => {
                let removed = remove_blob(&mut store, &piv, &op.name, Some(mgmt), None).unwrap();
                let expected = toy.remove(&op.name);
                assert_eq!(removed, expected,
                    "remove '{}' return value mismatch", op.name);
            }
            OpType::List => {
                let blobs: Vec<String> = list_blobs(&store)
                    .into_iter().map(|b| b.name).collect();
                assert_eq!(blobs, toy.list(), "list mismatch");
            }
        }
    }
}
```

This test runs entirely in memory (no PC/SC, no hardware), is deterministic, and
completes in well under 1 second.

---

## References

- Python `test_helpers.py`: `ToyFilesystem`, `OperationGenerator`
- Python `self_test.py`: `run_test_operations`, `SubprocessExecutor`
- Spec 0015: `yb self-test` CLI command (uses `OperationGenerator` at runtime)
- `yb-core/tests/virtual_piv_tests.rs`: home for `test_random_operations`
