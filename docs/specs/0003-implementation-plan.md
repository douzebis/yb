<!--
SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
SPDX-FileCopyrightText: 2025 - 2026 Thales Cloud Sécurisé

SPDX-License-Identifier: MIT
-->

# 0003 — Implementation plan for spec 0002 evolutions

**Status:** draft
**App:** yb (Rust)
**Implemented in:** <!-- YYYY-MM-DD, fill after implementation -->

## Purpose

This spec translates the architectural decisions in
`docs/specs/0002-crate-structure.md` into a concrete, step-by-step
implementation plan. It identifies every file to create, move, or modify,
every dependency to add or remove, and every interface change required.
It is intended to be executed in order, with each phase leaving the
codebase in a buildable and testable state.

## Overview of phases

```
Phase 1 — Workspace restructure      (mechanical move, no logic changes)
Phase 2 — CLI elimination of subprocs (replace yubico-piv-tool/ykman/pkcs11-tool
                                        with pcsc APDUs and RustCrypto)
Phase 3 — VirtualPiv backend         (in-memory PIV for unit tests)
Phase 4 — Public library API         (yb-core lib.rs surface + docs)
Phase 5 — Tier-2 test harness        (vsmartcard + piv-authenticator)
Phase 6 — Nix build updates          (crane derivations for both crates,
                                        integration-test derivation)
```

Phases 1 and 2 are independent of each other in intent but must be done
in order (phase 1 creates the workspace structure that phase 2 builds on).
Phases 3–6 depend on phase 1 and can be parallelised by different
contributors once phase 1 is merged.

---

## Phase 1 — Workspace restructure

**Goal:** Split the single `rust/yb/` crate into `rust/yb-core/` (library)
and `rust/yb/` (binary). No logic changes.

### 1.1 New directory layout

```
rust/
  Cargo.toml              # workspace root — update members
  yb-core/
    Cargo.toml            # new lib crate
    src/
      lib.rs              # new: re-exports public API
      auxiliaries.rs      # moved from yb/src/
      context.rs          # moved from yb/src/
      crypto.rs           # moved from yb/src/
      orchestrator.rs     # moved from yb/src/
      piv/
        mod.rs            # moved from yb/src/piv/
        hardware.rs       # moved from yb/src/piv/
        emulated.rs       # moved from yb/src/piv/ (renamed → virtual.rs in phase 3)
      store/
        mod.rs            # moved from yb/src/store/
        constants.rs      # moved from yb/src/store/
  yb/
    Cargo.toml            # updated: depends on yb-core
    src/
      main.rs             # updated: imports from yb_core::
      cli/
        mod.rs
        format.rs         # updated: imports from yb_core::
        store.rs
        fetch.rs
        list.rs
        remove.rs
        fsck.rs
        list_readers.rs
```

### 1.2 `rust/Cargo.toml` changes

```toml
[workspace]
resolver = "2"
members  = ["yb-core", "yb"]

[profile.release]
codegen-units = 1
lto           = "thin"
```

### 1.3 `rust/yb-core/Cargo.toml` (new)

All dependencies currently in `rust/yb/Cargo.toml` except `clap`,
`clap_complete`, `crossterm`, and `chrono` move here. `chrono` moves to
an optional feature.

```toml
[package]
name        = "yb-core"
version     = "0.1.0"
edition     = "2021"
license     = "MIT"
description = "Secure blob storage on a YubiKey — core library"
repository  = "https://github.com/douzebis/yb"
homepage    = "https://github.com/douzebis/yb"
readme      = "../../README.md"
keywords    = ["yubikey", "piv", "encryption", "security"]
categories  = ["cryptography", "hardware-support"]

[lib]
name = "yb_core"
path = "src/lib.rs"

[features]
default          = []
chrono           = ["dep:chrono"]
virtual-piv      = ["dep:rcgen"]          # phase 3
integration-tests = []                    # phase 5
hardware-tests   = []                     # manual only

[dependencies]
# Cryptography (RustCrypto)
p256    = { version = "0.13", features = ["ecdh", "pkcs8"] }
hkdf    = "0.12"
sha2    = "0.10"
aes     = "0.8"
cbc     = { version = "0.1", features = ["alloc"] }
cipher  = { version = "0.4", features = ["block-padding"] }
rand    = "0.8"

# Encoding / serialization
hex      = "0.4"
serde    = { version = "1", features = ["derive"] }
serde_yaml = "0.9"

# PC/SC (smartcard)
pcsc = "2"

# Error handling
anyhow    = "1"
thiserror = "1"

# Glob pattern matching
globset = "0.4"

# Temp files (used in crypto.rs for pkcs11-tool interop — removed in phase 2)
tempfile = "3"

# Optional
chrono = { version = "0.4", optional = true }
rcgen  = { version = "0.13", optional = true }   # phase 3: VirtualPiv cert gen

[dev-dependencies]
# VirtualPiv is always available in tests
yb-core = { path = ".", features = ["virtual-piv"] }
```

### 1.4 `rust/yb/Cargo.toml` changes

Remove all dependencies that moved to `yb-core`. Keep only:

```toml
[package]
name        = "yb"
version     = "0.1.0"
edition     = "2021"
license     = "MIT"
description = "Secure blob storage on a YubiKey"
repository  = "https://github.com/douzebis/yb"
homepage    = "https://github.com/douzebis/yb"
readme      = "../../README.md"
keywords    = ["yubikey", "piv", "encryption", "security"]
categories  = ["command-line-utilities", "cryptography"]

[[bin]]
name = "yb"
path = "src/main.rs"

[dependencies]
yb-core       = { path = "../yb-core", features = ["chrono"] }
clap          = { version = "4", features = ["derive", "env"] }
clap_complete = "4"
crossterm     = "0.27"
anyhow        = "1"
chrono        = "0.4"
```

### 1.5 `rust/yb-core/src/lib.rs` (new)

```rust
// SPDX-License-Identifier: MIT

//! Core library for yb — secure blob storage on a YubiKey.
//!
//! # Quick start
//!
//! ```no_run
//! use yb_core::{Context, fetch_blob, list_blobs};
//!
//! let ctx = Context::new(None, None, None, Some("123456".into()), false, false)?;
//! for blob in list_blobs(&ctx)? {
//!     println!("{}", blob.name);
//! }
//! let data = fetch_blob(&ctx, "my-secret")?;
//! # Ok::<(), anyhow::Error>(())
//! ```

mod auxiliaries;
mod crypto;
mod store;

pub mod context;
pub mod orchestrator;
pub mod piv;

pub use context::Context;
pub use orchestrator::{fetch_blob, list_blobs, remove_blob, store_blob, BlobInfo};
pub use piv::{DeviceInfo, PivBackend};
pub use piv::hardware::HardwarePiv;

#[cfg(feature = "virtual-piv")]
pub use piv::virtual_piv::VirtualPiv;
```

### 1.6 Import path updates in CLI modules

Every `use crate::` in `cli/*.rs` and `main.rs` becomes `use yb_core::`.
Concretely:

| Old import | New import |
|---|---|
| `use crate::context::Context` | `use yb_core::Context` |
| `use crate::orchestrator` | `use yb_core::orchestrator` |
| `use crate::store::Store` | `use yb_core::store::Store` (pub(crate) — expose if needed) |
| `use crate::piv::PivBackend` | `use yb_core::PivBackend` |

`store` and `auxiliaries` remain `pub(crate)` within `yb-core`; only the
orchestrator functions and context are public. CLI modules that need
`Store` directly (e.g. `fsck.rs`) will use `yb_core::store::Store` once
`store` is made `pub` — or `fsck` logic moves into an orchestrator helper.

### 1.7 Acceptance criteria for phase 1

- `cargo build --release` succeeds for both crates.
- `cargo test` passes (existing 9 unit tests).
- `yb --allow-defaults ls` against the test YubiKey still works.
- No logic changes — diff is purely file moves and import renames.

---

## Phase 2 — Eliminate CLI subprocess dependencies

**Goal:** Replace all `yubico-piv-tool`, `ykman`, `pkcs11-tool`, and
`openssl` subprocess calls with in-process code using `pcsc` APDUs and
RustCrypto. After this phase, `HardwarePiv` has no external runtime
dependencies beyond `pcscd`.

This is the most security-relevant phase — the result is a fully auditable
PIV client traceable to NIST SP 800-73-4 and Yubico's APDU documentation.

### 2.1 Subprocess inventory

The following subprocess calls exist in the current codebase and must be
eliminated:

| Location | Command | Replacement |
|---|---|---|
| `piv/hardware.rs:list_readers` | `yubico-piv-tool --action list-readers` | `pcsc::Context::list_readers` |
| `piv/hardware.rs:list_devices` | `ykman list --serials` | Already using APDU (`serial_from_reader`); remove ykman fallback |
| `piv/hardware.rs:read_object` | `yubico-piv-tool read-object` | `pcsc` GET DATA APDU |
| `piv/hardware.rs:write_object` | `yubico-piv-tool write-object` | `pcsc` PUT DATA APDU + mgmt key auth |
| `piv/hardware.rs:verify_pin` | `yubico-piv-tool verify-pin` | `pcsc` VERIFY APDU |
| `auxiliaries.rs:get_pin_protected_management_key` | `ykman piv objects export` | `pcsc` VERIFY + GET DATA in one session |
| `context.rs:get_public_key` | `yubico-piv-tool read-certificate` + `openssl x509` | `pcsc` GET DATA → parse DER cert with `x509-cert` crate |
| `cli/format.rs:generate_certificate` | `yubico-piv-tool generate/selfsign/import-certificate` | `pcsc` GENERATE ASYMMETRIC KEY + `rcgen` self-sign + PUT DATA |
| `crypto.rs:hybrid_decrypt` | `pkcs11-tool --derive` | `pcsc` GENERAL AUTHENTICATE (ECDH, tag 0x85) |

### 2.2 New dependencies for phase 2

Add to `yb-core/Cargo.toml`:

```toml
# X.509 certificate parsing (replaces openssl subprocess)
x509-cert = "0.2"
der        = "0.7"
spki       = "0.7"

# Self-signed cert generation (replaces yubico-piv-tool selfsign)
# Already optional under virtual-piv feature; promote to default
rcgen = "0.13"
```

Remove from `yb-core/Cargo.toml` once phase 2 is complete:
- `tempfile` (was used only for pkcs11-tool and openssl temp files)
- `serde_yaml` (review — may still be needed for VirtualPiv fixtures)

Remove from Nix dev-shell (no longer needed at runtime after phase 2):
- `yubico-piv-tool`
- `ykman`
- `pkcs11-tool` (from `opensc`)

Keep in dev-shell for manual/tier-3 tests only:
- `opensc` (for `opensc-tool --list-readers` diagnostics)
- `ykman` (for PIN/management key operations outside yb)

### 2.3 `HardwarePiv` rewrite plan

The rewritten `HardwarePiv` uses only `pcsc` for all operations. Each
method maps to one or more APDU exchanges on a `pcsc::Card`. A shared
`PcscSession` helper manages the card handle, SELECT PIV, and response
parsing within a single method call.

#### APDU reference

All APDUs below target the YubiKey PIV applet (AID `A0 00 00 03 08`).
Status word `90 00` = success; others are errors unless noted.

**SELECT PIV applet**
```
CLA=00 INS=A4 P1=04 P2=00 Lc=05 Data=A0000003 08 Le=00
```
Must be sent first on every new card connection.

**list_readers** — no APDU needed:
```rust
pcsc::Context::establish(Scope::User)?.list_readers(&mut buf)
```
Returns null-separated reader name strings.

**serial_from_reader** (already implemented via APDU, keep as-is):
```
CLA=00 INS=F8 P1=00 P2=00 Le=00   (YubiKey GET_SERIAL, proprietary)
Response: 4 bytes big-endian serial
```

**version_from_reader** (already implemented, keep as-is):
```
CLA=00 INS=FD P1=00 P2=00 Le=00   (YubiKey GET_VERSION, proprietary)
Response: 3 bytes major.minor.patch
```

**read_object** — GET DATA:
```
CLA=00 INS=CB P1=3F P2=FF
Lc=05  Data=5C 03 XX XX XX   (tag 5C = data tag, 3 bytes = object ID)
Le=00
Response: BER-TLV wrapped: 53 <len> <data>
Strip outer 53 tag before returning.
```
Object ID mapping: `u32` → 3-byte big-endian (e.g. `0x5F0000` → `5F 00 00`).

**write_object** — PUT DATA (requires prior management key auth):
```
CLA=00 INS=DB P1=3F P2=FF
Lc=N  Data=5C 03 XX XX XX   (object ID)
            53 <len> <data>  (content, BER-TLV wrapped)
```
Management key authentication (GENERAL AUTHENTICATE, 3DES or AES) must
precede this call in the same session.

**Management key authentication** (3-pass mutual auth):
```
Step 1 — Request witness:
  CLA=00 INS=87 P1=03 P2=9B Lc=04 Data=7C 02 80 00
  Response: 7C <len> 80 <len> <8-byte-witness-encrypted>

Step 2 — Decrypt witness + generate challenge:
  (decrypt witness with mgmt key locally using AES/3DES)
  CLA=00 INS=87 P1=03 P2=9B Lc=N
    Data=7C <len>
           80 <len> <decrypted-witness>
           81 <len> <8-byte-challenge>
  Response: 7C <len> 82 <len> <encrypted-challenge-response>

Step 3 — Verify response:
  (verify card encrypted our challenge correctly)
```
P1=`03` for 3DES, `08` for AES-128, `0C` for AES-192, `0E` for AES-256.
P2=`9B` is the management key slot.

**verify_pin** — VERIFY:
```
CLA=00 INS=20 P1=00 P2=80
Lc=<pin_len>  Data=<pin-bytes, no padding>
```
P2=`80` is the PIV user PIN reference.
SW `90 00` = success; `63 CX` = X retries remaining; `69 83` = blocked.

**get_pin_protected_management_key** — VERIFY then GET DATA in one session:
```
1. Connect to reader
2. SELECT PIV
3. VERIFY PIN (P2=80)
4. GET DATA for object 0x5FC109 (PRINTED)
5. Parse TLV: 53 <len> [ 88 <len> [ 89 <len> <key-bytes> ] ]
```
This replaces the current `ykman piv objects export` subprocess.

**ECDH key agreement** (replaces `pkcs11-tool --derive`):
```
GENERAL AUTHENTICATE, ECC P-256, slot 0x82:
CLA=00 INS=87 P1=11 P2=<slot>
Lc=N  Data=7C <len>
              85 <len> <peer-uncompressed-point-65-bytes>
Le=00
Response: 7C <len> 85 <len> <shared-secret-point-65-bytes>
```
P1=`11` for ECC P-256. Slot values: `82`=RETIRED1, `83`=RETIRED2, etc.
The shared secret is the 65-byte uncompressed EC point; pass all 65 bytes
into HKDF (matching current Python behavior).

**read_certificate** — GET DATA for standard PIV cert objects:
```
GET DATA for slot certificate objects:
  Slot 9A → object 0x5FC105
  Slot 9C → object 0x5FC10A
  Slot 9D → object 0x5FC10B
  Slot 9E → object 0x5FC101
  Slot 82 (RETIRED1) → object 0x5FC10D
  ...
Response TLV: 53 <len> [ 70 <len> <DER cert> 71 01 00 FE 00 ]
Parse with `x509-cert` crate: Certificate::from_der(der)?
Extract SubjectPublicKeyInfo → p256::PublicKey::from_sec1_bytes(point)?
```
Slot-to-object-ID mapping for all 20 retired slots is defined in
NIST SP 800-73-4 Table 3.

**generate_key** — GENERATE ASYMMETRIC KEY:
```
CLA=00 INS=47 P1=00 P2=<slot>
Lc=05  Data=AC 03 80 01 11   (algorithm=ECC P-256)
Le=00
Response: 7F 49 <len> 86 <len> <uncompressed-point-65-bytes>
```
Returns the generated public key as an uncompressed EC point.
Requires prior management key auth.

**self-sign and import certificate** (replaces yubico-piv-tool selfsign):
1. Generate key (above) → get public key point.
2. Build self-signed X.509 cert with `rcgen`:
   - Subject: provided via `--subject` arg (e.g. `CN=YBLOB ECCP256`)
   - Key: wrap the uncompressed point as a P-256 public key
   - Validity: 1 year from now
   - Sign: using the on-card private key via GENERAL AUTHENTICATE
     (signing, not ECDH — tag `0x82` in the TLV, P1=`11` for P-256)
3. Import certificate: PUT DATA to the slot's cert object ID.

Note: `rcgen` supports external signing via a `RemoteKeyPair` trait.
Implement `RemoteKeyPair` using a GENERAL AUTHENTICATE SIGN APDU.

### 2.4 `PcscSession` helper (new internal type)

To avoid reconnecting for every operation and to support multi-APDU
sequences (verify PIN → read protected object), introduce a
`PcscSession` struct in `piv/hardware.rs`:

```rust
struct PcscSession {
    card: pcsc::Card,
}

impl PcscSession {
    fn open(reader: &str) -> Result<Self>;
    fn select_piv(&mut self) -> Result<()>;
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>>;
    fn get_data(&mut self, object_id: u32) -> Result<Vec<u8>>;
    fn put_data(&mut self, object_id: u32, data: &[u8]) -> Result<()>;
    fn verify_pin(&mut self, pin: &str) -> Result<()>;
    fn authenticate_management_key(&mut self, key_hex: &str) -> Result<()>;
    fn general_authenticate_ecdh(&mut self, slot: u8, peer_point: &[u8]) -> Result<Vec<u8>>;
    fn general_authenticate_sign(&mut self, slot: u8, digest: &[u8]) -> Result<Vec<u8>>;
    fn generate_key(&mut self, slot: u8, algorithm: u8) -> Result<Vec<u8>>;
}
```

`PcscSession` is `pub(crate)` within `yb-core`. `HardwarePiv` methods
create a session, call the needed operations, and drop it. Multi-step
operations (e.g. auth + write) share one session.

### 2.5 `PivBackend` trait evolution

The trait gains two new methods to support the ECDH and key-generation
paths that are currently bypassing the backend:

```rust
pub trait PivBackend: Send + Sync {
    // existing methods unchanged
    fn list_readers(&self) -> Result<Vec<String>>;
    fn list_devices(&self) -> Result<Vec<DeviceInfo>>;
    fn read_object(&self, reader: &str, id: u32) -> Result<Vec<u8>>;
    fn write_object(&self, reader: &str, id: u32, data: &[u8],
                    management_key: Option<&str>) -> Result<()>;
    fn verify_pin(&self, reader: &str, pin: &str) -> Result<()>;
    fn send_apdu(&self, reader: &str, apdu: &[u8]) -> Result<Vec<u8>>;

    // new in phase 2
    /// ECDH key agreement: given peer's uncompressed P-256 point (65 bytes),
    /// return the shared secret point (65 bytes).
    fn ecdh(&self, reader: &str, slot: u8, peer_point: &[u8],
            pin: Option<&str>) -> Result<Vec<u8>>;

    /// Read an X.509 certificate from a PIV slot; return DER bytes.
    fn read_certificate(&self, reader: &str, slot: u8) -> Result<Vec<u8>>;

    /// Generate an EC P-256 key pair; return the public key as an
    /// uncompressed point (65 bytes).
    fn generate_key(&self, reader: &str, slot: u8,
                    management_key: Option<&str>) -> Result<Vec<u8>>;
}
```

`write_object` drops the `pin` parameter (it was unused in the hardware
implementation — management key auth is sufficient for PUT DATA).

`verify_pin` return type changes from `Result<bool>` to `Result<()>` —
failure is an error, not a boolean. The retry count is encoded in the
error message when SW is `63 CX`.

### 2.6 `context.rs` changes

- `get_public_key()` delegates to `piv.read_certificate(reader, slot)` →
  parse DER with `x509-cert` crate → extract SubjectPublicKeyInfo.
  Removes the `openssl` subprocess and `tempfile` usage.
- `management_key_for_write()` delegates to
  `auxiliaries::get_pin_protected_management_key()` which now uses a
  `PcscSession` directly (not `ykman`).

### 2.7 `crypto.rs` changes

`hybrid_decrypt` currently calls `pkcs11-tool --derive` as a subprocess.
Replace with:

```rust
// Old: pkcs11-tool subprocess
// New: piv.ecdh(reader, slot, &epk_uncompressed, pin)
let shared_secret_point = piv.ecdh(reader, slot, &epk_uncompressed, pin)?;
// Then: HKDF-SHA256 over shared_secret_point → AES key → AES decrypt
```

`hybrid_decrypt` signature gains `piv: &dyn PivBackend` and `reader: &str`
parameters (currently it only takes `serial` and calls pkcs11-tool by
serial number). All callers in `orchestrator.rs` and `cli/fetch.rs` are
updated.

### 2.8 Acceptance criteria for phase 2

- `yb ls`, `yb fetch`, `yb store`, `yb rm`, `yb format --generate` all
  work against the test YubiKey with no `yubico-piv-tool`, `ykman`,
  `pkcs11-tool`, or `openssl` processes spawned (verify with `strace -e
  execve` or `bpftrace`).
- All 9 existing unit tests pass.
- `yubico-piv-tool`, `ykman`, `opensc` removed from `default.nix` runtime
  dependencies (kept only in dev-shell for diagnostics).

---

## Phase 3 — VirtualPiv backend

**Goal:** Implement `VirtualPiv` — an in-memory PIV backend for tier-1
unit tests. After this phase, all `yb-core` business logic is testable
without hardware.

### 3.1 `VirtualPiv` state

```rust
pub struct VirtualPiv {
    state: Mutex<VirtualState>,
}

struct VirtualState {
    // Object store
    objects: HashMap<u32, Vec<u8>>,

    // Auth state
    pin: String,
    puk: String,
    management_key: String,      // hex, 48 chars (3DES) or 32/48/64 (AES)
    pin_retries: u8,
    puk_retries: u8,
    pin_verified: bool,
    mgmt_key_authenticated: bool,

    // Key slots: slot byte → (private_key_scalar, public_key_point)
    key_slots: HashMap<u8, SlotKey>,

    // Simulated device identity
    serial: u32,
    version: String,
    reader: String,
}

struct SlotKey {
    private_key: p256::SecretKey,
    public_key: p256::PublicKey,
    certificate_der: Option<Vec<u8>>,
}
```

### 3.2 `VirtualPiv` construction

```rust
impl VirtualPiv {
    /// Create from a fixture file (YAML).
    pub fn from_fixture(path: &Path) -> Result<Self>;

    /// Create with defaults — useful for one-off tests.
    pub fn new_default() -> Self;
}
```

Default state:
- PIN: `123456`, PUK: `12345678`
- Management key: `010203040506070801020304050607080102030405060708` (default 3DES)
- Serial: `99999999`, reader: `Virtual YubiKey 00 00`
- Admin data object (0x5FFF00): populated to indicate non-protected mode
- No key slots, no objects

### 3.3 Fixture file format

```yaml
# WARNING: DISPOSABLE TEST KEY MATERIAL
# This file contains private keys for use in automated tests only.
# Do not use these keys to protect real data.
# Do not confuse these with production YubiKey credentials.

identity:
  serial: 99999999
  version: "5.4.3"
  reader: "Virtual YubiKey 00 00"

credentials:
  pin: "123456"
  puk: "12345678"
  management_key: "010203040506070801020304050607080102030405060708"
  pin_protected: false   # if true, management key stored in object 0x5FC109

slots:
  "82":                  # RETIRED1 — hex slot number
    private_key_hex: "..."    # 32-byte P-256 scalar, hex-encoded
    certificate_subject: "CN=YBLOB ECCP256"

objects:
  "0x5f0000": "..."      # hex-encoded object contents (base64 or hex)
  "0x5f0001": "..."
```

Fixture files live in `yb-core/tests/fixtures/`. The default fixture
(`default.yaml`) is a blank store. A `prefilled.yaml` fixture contains
two pre-stored blobs (one encrypted, one plain) for fetch/list tests.

### 3.4 `VirtualPiv` method implementations

**`read_object`**: return `objects[id].clone()` or error if absent.

**`write_object`**: assert `mgmt_key_authenticated`, insert into `objects`.

**`verify_pin`**: compare `pin` string, decrement `pin_retries` on failure,
return `Err` with retry count in message if wrong, `Err("PIN blocked")`
at zero.

**`ecdh`**: look up `key_slots[slot]`, compute ECDH with `p256` crate:
```rust
let shared = key_slots[slot].private_key
    .diffie_hellman(&peer_public_key);
Ok(shared.raw_secret_bytes().to_vec())  // 32-byte x-coordinate
```
Note: the hardware returns the full 65-byte uncompressed point; the
software should match this format exactly for test parity.

**`generate_key`**: assert `mgmt_key_authenticated`, generate fresh
`p256::SecretKey::random(&mut rng)`, store in `key_slots[slot]`, return
uncompressed public key point.

**`read_certificate`**: return `key_slots[slot].certificate_der.clone()`
or error if no cert in slot.

**`list_devices`**: return a single `DeviceInfo` from `state.serial/version/reader`.

**`list_readers`**: return `vec![state.reader.clone()]`.

### 3.5 Unit test structure

Tests live in `yb-core/tests/` (integration test files, not `#[test]` in
source files, so they can use `VirtualPiv` without a feature flag in the
main source).

```
yb-core/tests/
  fixtures/
    default.yaml       # blank store, default credentials
    prefilled.yaml     # two blobs pre-stored (one encrypted, one plain)
    pin_protected.yaml # management key stored in PRINTED object
    hardware-key.yaml  # tier-3: real YubiKey serial + PIN (no private key)
  test_list.rs         # list_blobs against VirtualPiv
  test_fetch.rs        # fetch_blob (plain and encrypted)
  test_store.rs        # store_blob round-trip
  test_remove.rs       # remove_blob
  test_format.rs       # format_store
  test_crypto.rs       # hybrid_encrypt / hybrid_decrypt via VirtualPiv
  test_auxiliaries.rs  # TLV, admin data, PIN-protected mgmt key
```

Every test function documents in a comment:
- What it tests
- Which fixture it uses
- Whether key material is disposable (always yes for VirtualPiv tests)

### 3.6 Acceptance criteria for phase 3

- `cargo test` passes with no YubiKey connected (all tier-1 tests run).
- `cargo test --features virtual-piv` runs all unit tests including
  VirtualPiv-specific ones.
- `yb fetch` against a `VirtualPiv` returns correct plaintext for both
  encrypted and unencrypted blobs.
- PIN retry counter decrements correctly and blocks at zero.

---

## Phase 4 — Public library API

**Goal:** Stabilise and document the `yb-core` public API. After this phase,
internal users can replace their `yb fetch` subprocess calls with a direct
library call.

### 4.1 `Context::with_backend` (new constructor)

```rust
impl Context {
    pub fn with_backend(
        backend: Arc<dyn PivBackend>,
        pin: Option<String>,
        debug: bool,
    ) -> Result<Self> {
        // Enumerate devices via the backend to get reader name and serial.
        let devices = backend.list_devices()?;
        let (device, reader) = match devices.as_slice() {
            [] => bail!("no device found in backend"),
            [d] => (d.clone(), d.reader.clone()),
            _ => bail!("multiple devices — use Context::new with --serial"),
        };

        // Detect PIN-protected mode (reads admin data object).
        let (pin_protected, pin_derived) =
            auxiliaries::detect_pin_protected_mode(&reader, backend.as_ref())
                .unwrap_or((false, false));

        Ok(Self {
            reader,
            serial: device.serial,
            management_key: None,
            pin,
            piv: backend,
            debug,
            pin_protected,
        })
    }
}
```

### 4.2 Orchestrator function signatures (public)

The orchestrator functions are currently free functions taking raw
parameters. For the public API, wrap them behind `Context`:

```rust
// yb-core/src/lib.rs  (or orchestrator.rs made pub)

pub fn list_blobs(ctx: &Context) -> Result<Vec<BlobInfo>>;
pub fn fetch_blob(ctx: &Context, name: &str) -> Result<Vec<u8>>;
pub fn store_blob(ctx: &Context, name: &str, data: &[u8], encrypt: bool) -> Result<()>;
pub fn remove_blob(ctx: &Context, name: &str) -> Result<()>;
pub fn format_store(ctx: &Context, object_count: u8, object_size: usize, slot: u8) -> Result<()>;
```

These wrappers load the `Store` from the device, call the inner function,
and handle `management_key_for_write` internally. Callers never see
`Store` or `Object`.

### 4.3 `BlobInfo` with optional chrono

```rust
#[derive(Debug, Clone)]
pub struct BlobInfo {
    pub name: String,
    pub plain_size: u32,
    pub is_encrypted: bool,
    pub mtime: u32,       // Unix timestamp (seconds since epoch)
    pub chunk_count: usize,
}

impl BlobInfo {
    /// Return mtime as a local DateTime. Requires feature `chrono`.
    #[cfg(feature = "chrono")]
    pub fn mtime_local(&self) -> chrono::DateTime<chrono::Local> {
        chrono::DateTime::from(
            chrono::DateTime::<chrono::Utc>::from_timestamp(self.mtime as i64, 0).unwrap()
        )
    }
}
```

### 4.4 Documentation requirements

Every public item must have a doc comment covering:
- What the item does
- Error conditions
- Which feature flags (if any) are required

The crate-level `lib.rs` doc includes:
- Quick-start example (doctested with `no_run`)
- Feature flag table
- Link to the wire format spec (`doc/DESIGN.md`)
- Security note: "Key material on the YubiKey is never extracted; ECDH
  is performed on-card."

### 4.5 Acceptance criteria for phase 4

- `cargo doc --no-deps` produces no warnings.
- The quick-start example in `lib.rs` compiles (`cargo test --doc`).
- An internal user can replace:
  ```python
  result = subprocess.run(["yb", "--pin", pin, "fetch", name], capture_output=True)
  data = result.stdout
  ```
  with:
  ```rust
  let ctx = Context::new(None, None, None, Some(pin), false, false)?;
  let data = fetch_blob(&ctx, name)?;
  ```

---

## Phase 5 — Tier-2 test harness

**Goal:** Integration tests that run `HardwarePiv` against a real PIV
APDU stack (piv-authenticator via vsmartcard), exercising every APDU
implemented in phase 2. These run automatically during `nix build`.

### 5.1 Infrastructure

`vsmartcard` provides:
- `pcscd` IFD plugin (`ifd-vpcd.so`) — registers virtual reader slots
- `vpcd` daemon — bridges IFD plugin to TCP port 35963

`piv-authenticator` provides:
- Rust PIV applet implementation
- `vpicc` feature: connects to vpcd TCP port, responds to PIV APDUs

Both are available in nixpkgs 25.05.

### 5.2 Test harness setup

```rust
// yb-core/tests/integration/harness.rs

pub struct VirtualCardHarness {
    vpcd_process: Child,
    piv_process: Child,
    reader: String,
}

impl VirtualCardHarness {
    pub fn start() -> Result<Self> {
        // 1. Start vpcd daemon on a random port.
        // 2. Start piv-authenticator with --vpicc-port <port>.
        // 3. Wait for pcscd to register the virtual reader.
        // 4. Return reader name for use in HardwarePiv.
    }
}

impl Drop for VirtualCardHarness {
    fn drop(&mut self) {
        // Kill piv-authenticator and vpcd.
    }
}
```

### 5.3 Coverage plan for tier-2

Each test in `yb-core/tests/integration/` corresponds to one APDU or
operation:

| Test | APDUs exercised |
|---|---|
| `test_select_piv` | SELECT PIV |
| `test_get_data` | GET DATA (read object) |
| `test_put_data` | GENERAL AUTHENTICATE (mgmt key) + PUT DATA |
| `test_verify_pin` | VERIFY PIN (success + wrong PIN + retry count) |
| `test_generate_key` | GENERATE ASYMMETRIC KEY |
| `test_ecdh` | GENERAL AUTHENTICATE (ECDH) |
| `test_read_cert` | GET DATA (cert object) |
| `test_store_fetch_roundtrip` | full yb store + yb fetch via HardwarePiv |

YubiKey-proprietary APDUs (GET_SERIAL, GET_VERSION, GET_METADATA,
PRINTED object) are not covered by `piv-authenticator`. These are tested
in tier-1 via `VirtualPiv`, which implements the Yubico-specific behavior.

### 5.4 Nix derivation

```nix
rustIntegrationTests = craneLib.cargoTest (rustCommon // {
  cargoArtifacts = rustDeps;
  cargoTestExtraArgs = "--features integration-tests";
  nativeBuildInputs = rustCommon.nativeBuildInputs ++ [
    pkgs.vsmartcard-vpcd
    pivAuthenticator   # built from source via crane
  ];
  preCheck = ''
    # Start vsmartcard daemon
    vpcd &
    sleep 1
  '';
});
```

The `ybRust` final derivation's `checkPhase` runs both `rustTests` (tier-1)
and `rustIntegrationTests` (tier-2).

### 5.5 Acceptance criteria for phase 5

- `nix build .#yb-rust` succeeds, running tier-1 + tier-2 tests.
- Each APDU in § 2.3 is covered by at least one tier-2 test.
- Tests pass without a physical YubiKey.

---

## Phase 6 — Nix build updates

**Goal:** Update `default.nix` to build both crates, run all test tiers
appropriately, and produce clean outputs for both nixpkgs and crates.io.

### 6.1 Crane derivation updates

```nix
# Shared build inputs for both crates
rustCommon = {
  src = rustSrc;
  strictDeps = true;
  buildInputs    = [ pkgs.pcsclite ];
  nativeBuildInputs = [ pkgs.pkg-config ];
};

# Shared deps build (covers both crates in workspace)
rustDeps = craneLib.buildDepsOnly rustCommon;

# Tier-1 tests
rustTests = craneLib.cargoTest (rustCommon // {
  cargoArtifacts = rustDeps;
  # No extra features — runs default tier-1 only
});

# Tier-2 tests (new)
rustIntegrationTests = craneLib.cargoTest (rustCommon // {
  cargoArtifacts = rustDeps;
  cargoTestExtraArgs = "--features yb-core/integration-tests";
  nativeBuildInputs = rustCommon.nativeBuildInputs ++ [
    pkgs.vsmartcard-vpcd
    pivAuthenticator
  ];
});

# Final binary
ybRust = craneLib.buildPackage (rustCommon // {
  cargoArtifacts = rustDeps;
  cargoExtraArgs = "--bin yb";
  doCheck = true;
  checkPhase = ''
    ${rustTests}/bin/...   # tier-1
    ${rustIntegrationTests}/bin/...  # tier-2
  '';
});
```

### 6.2 Dev-shell updates

Remove from `nativeBuildInputs` once phase 2 is complete:
- `yubico-piv-tool` (no longer a runtime dependency)
- `ykman` (no longer called by yb; keep as diagnostic tool optionally)

Add to `nativeBuildInputs`:
- `pkgs.vsmartcard-vpcd` (for tier-2 test development in dev-shell)

### 6.3 Outputs

```nix
packages = {
  default  = ybRust;   # nix build
  yb       = ybRust;   # nix build .#yb
  yb-rust  = ybRust;   # nix build .#yb-rust (compat alias)
  shell    = devShell; # nix build .#shell
};
```

### 6.4 crates.io publication checklist

Before `cargo publish`:
- [ ] `rust/yb-core/Cargo.toml`: `version`, `description`, `readme`,
      `repository`, `license` all set.
- [ ] `rust/yb/Cargo.toml`: `yb-core` path dep resolves to version dep
      for publish (`cargo publish` handles this automatically).
- [ ] `README.md` updated with library usage example.
- [ ] `CHANGELOG.md` entry for `0.1.0`.
- [ ] `cargo publish --dry-run` passes for both crates.
- [ ] Publish `yb-core` first, then `yb` (dependency order).

---

## Cross-cutting concerns

### Error messages and retry counts

When `verify_pin` fails with SW `63 CX`, the error message must include
the retry count: `"wrong PIN: {X} retries remaining"`. This gives the user
actionable information without requiring a separate GET_METADATA query.

### APDU buffer sizing

The current `pcsc_send_apdu` uses a fixed 258-byte response buffer. PIV
data objects can be up to 3052 bytes. The `PcscSession` transmit method
must use a larger buffer (4096 bytes) and handle `SW 61 XX` (more data
available) chaining for large objects.

### Management key algorithm detection

The current implementation assumes 3DES management keys. The YubiKey 5
supports AES-128/192/256 management keys. GET_METADATA (INS=0xF7,
P1=0x00, P2=0x9B) returns the algorithm of the current management key.
`PcscSession::authenticate_management_key` should query metadata first
and branch on algorithm.

### Thread safety

`VirtualPiv` wraps state in `Mutex<VirtualState>` to satisfy `Send + Sync`.
`HardwarePiv` is stateless (each method opens a fresh `PcscSession`),
so it is trivially `Send + Sync`.

---

## Open questions

- Should `format_store` in the public API also accept `generate: bool`
  (generate a new key pair) or always assume a key already exists in the
  slot? The current CLI has `--generate`; the library should probably
  expose both paths separately.
- `piv-authenticator` does not implement the PRINTED object convention.
  Should we upstream a PR to add it, or accept that the PRINTED object
  path is tier-1-only (VirtualPiv)?
- Should `HardwarePiv` cache the management key algorithm after the first
  GET_METADATA call, or query it fresh each time?

## References

- Spec 0001: `docs/specs/0001-rust-port.md`
- Spec 0002: `docs/specs/0002-crate-structure.md`
- NIST SP 800-73-4: PIV APDU specification
- Yubico PIV extension APDUs:
  https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html
- `piv-authenticator`: https://github.com/Nitrokey/piv-authenticator
- `vsmartcard`: https://github.com/frankmorgner/vsmartcard
- `x509-cert` crate: https://docs.rs/x509-cert
- `rcgen` crate: https://docs.rs/rcgen
