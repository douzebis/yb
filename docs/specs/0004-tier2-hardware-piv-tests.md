<!--
SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0004 — Tier-2 Integration Tests for HardwarePiv

**Status:** ready
**App:** yb-core
**Implemented in:** <!-- YYYY-MM-DD, fill after implementation -->

## Problem

`HardwarePiv` (the production PC/SC backend) is untested by automated tests.
The tier-1 `VirtualPiv` suite covers business logic but exercises none of the
APDU-encoding, command-chaining, or PC/SC transaction code in `hardware.rs`.
Two APDU bugs were found by manual cross-reference with `yubico-piv-tool` source
(AES-256 P1 byte, missing ECDH `82 00` placeholder); automated tests would have
caught these earlier.

## Goals

- Run `HardwarePiv` against a real PIV APDU stack without physical hardware.
- Cover every `PivBackend` method implemented in `hardware.rs`.
- Tests run in CI (no YubiKey required).
- Tests live under the existing `integration-tests` Cargo feature gate so they
  are opt-in and do not affect normal `cargo test` runs.

## Non-goals

- Testing `piv-authenticator` itself (that is upstream's responsibility).
- RSA or P-384 key operations (yb only uses P-256).
- PIN-unblock (PUK) flows.
- Full store/orchestrator round-trips (already covered by tier-1).
- Nix derivation changes (Phase 6).

## Specification

### Architecture

```
┌─────────────────────────────────────────────────────┐
│  Test process                                        │
│                                                      │
│  ┌──────────────────┐    PC/SC    ┌───────────────┐ │
│  │  HardwarePiv     │◄──────────►│  pcscd        │ │
│  │  (under test)    │            │  (system)     │ │
│  └──────────────────┘            └───────┬───────┘ │
│                                          │ vpcd IPC │
│  ┌──────────────────────────────────────▼────────┐  │
│  │  piv-authenticator VpiccCard (in-process      │  │
│  │  thread, RAM-backed, polled via vpicc crate)  │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

The virtual card runs in a background thread inside the test process, connected
to `pcscd` via the `vpcd` Unix socket (`/var/run/vpcd`). `HardwarePiv` connects
through normal PC/SC (`SCardEstablishContext` → `SCardConnect`).

### New crate: `yb-piv-harness`

A new workspace member at `rust/yb-piv-harness/` provides the test harness
library. It is not published.

```
rust/yb-piv-harness/
  Cargo.toml
  src/
    lib.rs          # pub fn with_vsc<F>(f: F) -> R
```

`Cargo.toml` dependencies:

```toml
[dependencies]
piv-authenticator = { git = "https://github.com/trussed-dev/piv-authenticator",
                       rev = "<pinned-sha>", features = ["vpicc"] }
vpicc             = "0.1.0"
stoppable_thread  = "0.2"

[dev-dependencies]
yb-core = { path = "../yb-core", features = ["integration-tests"] }
```

`piv-authenticator` is fetched from its pinned upstream rev (same SHA as the
vendor subtree at `vendor/piv-authenticator/`). The vendor subtree is a safety
copy only; Cargo builds from the git URL.

### `with_vsc` helper

```rust
pub fn with_vsc<F, R>(options: piv_authenticator::Options, f: F) -> R
where
    F: FnOnce(&str) -> R,   // receives the reader name
{
    // 1. connect to vpcd
    // 2. spin up piv-authenticator VpiccCard in a stoppable thread
    // 3. poll once to confirm card is ready (recv on mpsc channel)
    // 4. sleep 200 ms for pcscd to detect the card
    // 5. find the new reader via HardwarePiv::list_readers()
    // 6. call f(reader_name)
    // 7. stop the thread, join, propagate errors
}
```

A `Mutex<()>` serialises concurrent calls (vpcd supports only one virtual card
at a time per process).

### Test file: `rust/yb-piv-harness/tests/hardware_piv_tests.rs`

Feature-gated with `#[cfg(feature = "integration-tests")]` (re-exported from
`yb-core`). Runs only when `cargo test --features integration-tests` is invoked.

Tests to implement (one `#[test]` per row):

| Test name | Operation exercised |
|---|---|
| `t2_list_readers` | `list_readers` returns a reader containing the virtual card |
| `t2_list_devices` | `list_devices` returns one device with expected serial/version |
| `t2_read_object_missing` | `read_object` errors on an unpopulated object ID |
| `t2_write_read_object` | `write_object` + `read_object` round-trip with default 3DES key |
| `t2_write_wrong_mgmt_key` | `write_object` with wrong management key is rejected |
| `t2_verify_pin` | `verify_pin` succeeds with `123456`, fails with wrong PIN |
| `t2_generate_key` | `generate_key` returns a 65-byte uncompressed P-256 point |
| `t2_generate_key_no_auth` | `generate_key` without management key is rejected |
| `t2_ecdh` | `ecdh` with a software-generated ephemeral key returns 32 bytes |
| `t2_generate_certificate` | `generate_certificate` stores a cert readable by `read_certificate` |

The test set mirrors the tier-1 `virtual_piv_tests.rs` suite so that regressions
surface at both levels.

The default management key on a fresh `piv-authenticator` virtual card is confirmed
to be 3DES `010203040506070801020304050607080102030405060708` (see
`vendor/piv-authenticator/src/constants.rs`: `YUBICO_DEFAULT_MANAGEMENT_KEY`).
pcscd auto-detects the new reader; a 200 ms sleep after the first poll suffices
(matches the reference implementation in `vendor/piv-authenticator/tests/card/mod.rs`).

### Environment requirements

The following must be present at test runtime (provided by the dev-shell):

- `pcscd` running with `vpcd` driver loaded (`vsmartcard-vpcd` package).
- `libpcsclite.so` on `LD_LIBRARY_PATH`.

Tests skip gracefully (via `eprintln!` + early return, not `panic!`) if
`/var/run/vpcd` is absent, to avoid breaking CI environments without vpcd.

### Cargo feature wiring

`yb-piv-harness/Cargo.toml`:

```toml
[features]
integration-tests = ["yb-core/integration-tests"]
```

`rust/Cargo.toml` workspace:

```toml
[workspace]
members = ["yb-core", "yb", "yb-piv-harness"]
```

## Open questions

None.

## References

- `vendor/piv-authenticator/tests/card/mod.rs` — `with_vsc` reference implementation
- `vendor/piv-authenticator/examples/vpicc.rs` — standalone vpicc entry point
- `rust/yb-core/tests/virtual_piv_tests.rs` — tier-1 test suite (mirror target)
- `docs/yubikey-apdu-reference.md` — APDU reference and bug history
- `docs/specs/0002-crate-structure.md` — workspace layout
