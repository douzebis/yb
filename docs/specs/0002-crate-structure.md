# 0002 — Crate structure: library + CLI split

**Status:** draft
**App:** yb (Rust)
**Implemented in:** <!-- YYYY-MM-DD, fill after implementation -->

## Problem

The current Rust port is a single binary crate (`rust/yb/`). This has two
concrete consequences:

1. **Internal users subprocess `yb fetch`** to read blob contents from a
   YubiKey. This is fragile (PATH dependency, stdout parsing, error
   propagation via exit codes) and unnecessarily heavy for what is a
   programmatic read operation.

2. **Testing requires a physical YubiKey.** Because everything lives in a
   binary crate with CLI wiring, there is no clean injection point for a
   software PIV backend. Unit and integration tests cannot run without
   hardware.

## Goals

- Split the Rust workspace into two crates: `yb-core` (library) and `yb`
  (binary, thin CLI shell over the library).
- Define a minimal, stable-enough public API on `yb-core` covering the
  primary use case: list and fetch blobs from a YubiKey.
- Write operations (`store`, `remove`, `format`) are part of the library
  but not the focus of the initial public API.
- Enable a three-tier test strategy via `PivBackend` dependency injection:
  unit (in-memory), integration (vsmartcard + piv-authenticator), manual
  (real YubiKey).
- Publish both crates to crates.io under `0.x` versioning (no semver
  stability guarantees until the API settles).
- Integration tests requiring vsmartcard are gated behind
  `features = ["integration-tests"]` and excluded from the default
  crates.io test run.

## Non-goals

- Extracting `yb-piv` as a standalone PIV client crate — deferred until
  the API has real external users and has settled.
- semver stability guarantees — deferred until `1.0`.
- Async API — the PC/SC layer is synchronous; no async wrapper planned.
- Python bindings (PyO3) — not planned at this stage.

## Specification

### 2.1 Workspace layout

```
rust/
  Cargo.toml          # workspace root: members = ["yb-core", "yb"]
  yb-core/
    Cargo.toml        # lib crate, published as "yb-core"
    src/
      lib.rs          # public API surface
      store/
        mod.rs
        constants.rs
      orchestrator.rs
      crypto.rs
      piv/
        mod.rs        # PivBackend trait, DeviceInfo
        hardware.rs   # HardwarePiv
        virtual.rs    # VirtualPiv (shallow in-memory backend)
      auxiliaries.rs
      context.rs
  yb/
    Cargo.toml        # bin crate, published as "yb", depends on yb-core
    src/
      main.rs
      cli/
        format.rs
        store.rs
        fetch.rs
        list.rs
        remove.rs
        fsck.rs
        list_readers.rs
```

The CLI crate contains only argument parsing and dispatch. All business
logic lives in `yb-core`.

### 2.2 Public API of `yb-core`

The initial public surface is deliberately minimal. Internal modules
(`store`, `orchestrator`, `crypto`, `auxiliaries`) remain `pub(crate)`.
The public API is the entry point that internal users need today.

```rust
// yb-core/src/lib.rs

pub use context::Context;
pub use orchestrator::{BlobInfo, fetch_blob, list_blobs};
pub use piv::{PivBackend, DeviceInfo};
pub use piv::hardware::HardwarePiv;
#[cfg(feature = "virtual-piv")]
pub use piv::virtual::VirtualPiv;
```

**`Context`** — device selection and session state:

```rust
pub struct Context { /* opaque */ }

impl Context {
    /// Connect to a YubiKey by serial number, reader name, or auto-select
    /// if only one device is present.
    pub fn new(
        serial: Option<u32>,
        reader: Option<String>,
        management_key: Option<String>,
        pin: Option<String>,
        debug: bool,
        allow_defaults: bool,
    ) -> Result<Self>;

    /// Connect using a custom PIV backend (for testing or embedding).
    /// Takes `Arc<dyn PivBackend>` so the backend can be shared across
    /// threads — e.g. fetching multiple blobs concurrently, or sharing
    /// a single `VirtualPiv` instance across test cases.
    pub fn with_backend(
        backend: Arc<dyn PivBackend>,
        pin: Option<String>,
        debug: bool,
    ) -> Result<Self>;
}
```

**`list_blobs`** — enumerate blobs on the device:

```rust
pub fn list_blobs(ctx: &Context) -> Result<Vec<BlobInfo>>;

pub struct BlobInfo {
    pub name: String,
    pub plain_size: usize,
    pub is_encrypted: bool,
    pub mtime: u32,         // Unix timestamp
    pub chunk_count: u8,
}
```

**`fetch_blob`** — retrieve blob contents by name:

```rust
/// Returns the plaintext contents of the named blob.
/// If the blob is encrypted, `ctx` must have a PIN configured.
pub fn fetch_blob(ctx: &Context, name: &str) -> Result<Vec<u8>>;
```

**`store_blob`**, **`remove_blob`**, **`format_store`** — write operations,
public but not the focus of the initial API:

```rust
pub fn store_blob(ctx: &Context, name: &str, data: &[u8], encrypt: bool) -> Result<()>;
pub fn remove_blob(ctx: &Context, name: &str) -> Result<()>;
pub fn format_store(ctx: &Context, object_count: u8, object_size: usize, slot: u8) -> Result<()>;
```

### 2.3 PivBackend trait (unchanged, now public)

```rust
pub trait PivBackend: Send + Sync {
    fn list_devices(&self) -> Result<Vec<DeviceInfo>>;
    fn list_readers(&self) -> Result<Vec<String>>;
    fn read_object(&self, reader: &str, id: u32) -> Result<Vec<u8>>;
    fn write_object(&self, reader: &str, id: u32, data: &[u8],
                    management_key: Option<&str>, pin: Option<&str>) -> Result<()>;
    fn verify_pin(&self, reader: &str, pin: &str) -> Result<bool>;
    fn send_apdu(&self, reader: &str, apdu: &[u8]) -> Result<Vec<u8>>;
}
```

Making this trait public allows external callers to inject their own
backend — useful for testing, for wrapping hardware with logging/tracing,
or for alternative hardware backends.

### 2.4 Three-tier test strategy

#### Tier 1 — Unit tests (no hardware, always run)

`VirtualPiv` implements `PivBackend` with in-memory state:

- PIV object store: `HashMap<u32, Vec<u8>>`
- PIN, PUK, management key: stored as strings with retry counters
- ECDH: computed in software via `p256` crate using a stored private key
- X.509 cert generation: self-signed via `rcgen` crate
- YubiKey-proprietary objects (0x5FFF00 admin data, 0x5FC109 PRINTED)
  populated from a fixture on construction

Fixture files live in `yb-core/tests/fixtures/`. All private key material
in fixture files carries a prominent header:

```yaml
# WARNING: DISPOSABLE TEST KEY MATERIAL
# This file contains private keys for use in automated tests only.
# Do not use these keys to protect real data.
# Do not confuse these with production YubiKey credentials.
```

`VirtualPiv` is gated behind `features = ["virtual-piv"]` to keep the
default library build free of test-only dependencies (`p256` key
generation, `rcgen`). The feature is enabled automatically in
`[dev-dependencies]` and in the `yb` CLI dev profile.

#### Tier 2 — Integration tests (vsmartcard + piv-authenticator, opt-in)

Gated behind `features = ["integration-tests"]`.

The test harness:
1. Spawns a `piv-authenticator` process (with `vpicc` feature) connected
   to the local vsmartcard daemon.
2. Connects `HardwarePiv` to the resulting virtual PC/SC reader.
3. Runs the full `yb-core` API against it.

This tests the `HardwarePiv` APDU layer against a standards-compliant PIV
responder without hardware. Missing YubiKey-proprietary APDUs
(GET_METADATA, GET_SERIAL, PRINTED object) are handled by falling back to
`VirtualPiv` for those specific paths, or by contributing the missing
commands to `piv-authenticator` upstream.

These tests run automatically during `nix build .#yb-rust` via a dedicated
`rustIntegrationTests` crane derivation with `vsmartcard` and
`piv-authenticator` in `nativeBuildInputs`. They are not run by plain
`cargo test` (no feature flag set) to keep the crates.io experience clean.

Requires in the Nix dev-shell and nix-build:
- `vsmartcard` (nixpkgs 25.05+)
- `piv-authenticator` binary (built from source as part of the Nix build)

#### Tier 3 — Manual / destructive tests (real YubiKey, never in CI)

Gated behind `features = ["hardware-tests"]` AND
`YB_HARDWARE_TESTS=1` environment variable. Both must be set.

Test fixture documents the dedicated test YubiKey:
- Serial: recorded in `yb-core/tests/fixtures/hardware-key.yaml`
- PIN: `654321` (documented as test-only)
- Management key: PIN-protected (standard test setup)

Running `cargo test --features hardware-tests` without the env var is a
no-op with a printed reminder. This prevents accidental destructive
operations.

### 2.5 crates.io vs nixpkgs publication

Both crates are published to crates.io. The same Git repository serves
both distribution channels without conflict:

- **crates.io** — `cargo publish` resolves workspace path dependencies
  (`yb` → `yb-core`) to versioned registry dependencies automatically.
  `Cargo.lock` is committed (required by crane/nixpkgs, harmless for
  crates.io). No special configuration needed.

- **nixpkgs** — crane uses the source tree directly, bypassing crates.io.
  The crane build runs tier-1 and tier-2 tests; crates.io users run only
  tier-1 by default.

The default feature set for crates.io users includes none of the optional
test features. Standard `cargo test` on the published crate runs only
tier-1 unit tests, which have no system dependencies.

The `yb-core` crate documents its feature flags in `README.md`:

| Feature | Purpose | Enabled in |
|---|---|---|
| `virtual-piv` | In-memory PIV backend for testing | dev, nix-build |
| `integration-tests` | vsmartcard + piv-authenticator tests | nix-build only |
| `hardware-tests` | Real YubiKey destructive tests | manual only |

Versioning: both crates start at `0.1.0`. No semver stability guarantees
until `1.0`. The `yb-core` public API (§2.2) is the surface to stabilize
first; internal modules remain `pub(crate)`.

### 2.6 Migration from current single-crate layout

The migration is mechanical:

1. Create `rust/yb-core/` with `src/lib.rs` exposing the public API.
2. Move all non-CLI source files from `rust/yb/src/` to
   `rust/yb-core/src/`.
3. Update `rust/yb/Cargo.toml` to depend on `yb-core`.
4. Update `rust/yb/src/main.rs` and `cli/*.rs` to import from `yb_core::`.
5. Add `VirtualPiv` to `yb-core/src/piv/virtual.rs`.
6. Update `rust/Cargo.toml` workspace members.
7. Update `default.nix` crane build to build both crates.

No behavior changes — this is a pure reorganization pass.

## Decisions

- **`Context::with_backend`** takes `Arc<dyn PivBackend>`. Enables sharing
  a backend across threads for concurrent blob fetches. `HardwarePiv::new()`
  returns `Arc<HardwarePiv>` for convenience. The CLI path uses
  `Arc::new(HardwarePiv::new())` internally — one extra allocation,
  negligible cost.

- **`BlobInfo.mtime`** is `u32` (raw Unix timestamp) in the struct, with an
  optional `chrono` feature providing a `mtime_local() -> DateTime<Local>`
  convenience method. Avoids imposing a public `chrono` dependency on users
  who don't need it.

- **`fetch_blob`** returns `Vec<u8>`. Blobs are bounded at ~48 KB (PIV
  object size × 16 chunk maximum). Callers needing `impl Read` can wrap with
  `std::io::Cursor::new(vec)`.

## References

- Spec 0001: `docs/specs/0001-rust-port.md`
- Library research: `docs/yubikey-rust-libs.md`
- `piv-authenticator`: https://github.com/Nitrokey/piv-authenticator
- `vsmartcard`: https://github.com/frankmorgner/vsmartcard
- `vpicc-rs`: https://github.com/Nitrokey/vpicc-rs
