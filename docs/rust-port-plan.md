<!--
SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# yb — Rust Port Plan

## Goals

- Produce a single-binary Rust crate (`yb`) publishable to crates.io.
- Preserve full wire-format compatibility with the existing Python implementation
  (same PIV object layout, same hybrid-encryption envelope).
- Enable updating the nixpkgs package from a Python derivation to a standard
  Rust/cargo derivation.
- Keep the same CLI surface so existing users and scripts are unaffected.

## Non-goals

- Adding new features during the port.
- Supporting macOS or Windows (Linux only, same as today).
- Providing a library API (`yb` as a Rust lib crate) beyond what the binary needs.

---

## Complexity Assessment

### Overall verdict: **medium-high**

The Python code is clean and well-layered (~6 350 LOC), but several subsystems
touch hardware, binary protocols, and cryptographic APIs that need careful
mapping to Rust equivalents.

### Subsystem breakdown

| Subsystem | File(s) | Rust difficulty | Notes |
|-----------|---------|-----------------|-------|
| Binary serialization | `store.py`, `constants.py` | Medium | Precise byte-level layout; well-documented; maps cleanly to `byteorder`/manual bit ops |
| Linked-list store logic | `store.py`, `orchestrator.py` | Low-medium | Pure algorithmic code; straightforward to port |
| Hybrid crypto (ECDH+AES) | `crypto.py` | Medium | `ring` or `aws-lc-rs` cover ECDH, HKDF, AES-CBC; the tricky part is delegating ECDH to the YubiKey |
| PIV object I/O via subprocess | `piv.py` HardwarePiv | Medium | `std::process::Command`; parse stdout/stderr; same approach as Python |
| APDU / TLV (PIN-protected mode) | `auxiliaries.py`, `piv.py` send_apdu | High | Requires `pcsc-rs` (PC/SC bindings); TLV parser needed; rare but critical code path |
| Device enumeration | `piv.py`, `main.py` | Medium | `pcsc-rs` covers this; replaces `ykman` Python library |
| PKCS#11 ECDH (encrypted blobs) | `crypto.py` | High | Either shell out to `pkcs11-tool` (easy, current approach) or use `pkcs11` crate (harder but eliminates dep) |
| CLI framework | `cli_*.py`, `main.py` | Low | `clap` v4 is a direct analog to Click; shell completion via `clap_complete` |
| Interactive device selector | `yubikey_selector.py` | Medium | Replace `prompt_toolkit` with `crossterm` or `ratatui`; LED flash via APDU |
| X.509 subject parsing | `x509_subject.py` | Low | Simple string parsing |
| YAML output | `cli_list.py` | Low | `serde_yaml` |
| Test suite | `tests/` | Medium | Rewrite using `#[cfg(test)]`; port `EmulatedPiv` as a trait mock |

---

## Key Challenges

### 1. PIV hardware interface

Python uses `yubico-piv-tool` (subprocess) for object read/write and `ykman`
(Python library) for device enumeration. The two roles must be handled in Rust:

- **Object read/write**: keep shelling out to `yubico-piv-tool`. The binary
  protocol is opaque to the calling process; `Command::output()` is sufficient.
- **Device enumeration**: replace the `ykman` Python library with `pcsc-rs`
  (`pcsclite` bindings). Call `SCardListReaders` + `GET DATA` APDU to read serial
  numbers. Alternatively, shell out to `ykman list --serials` if the full APDU
  path is not worth the effort at first.

### 2. PKCS#11 / ECDH decryption

Decryption requires the YubiKey to perform ECDH. Python drives this via
`pkcs11-tool` subprocess. Two options:

- **Option A (recommended for v1)**: Keep shelling out to `pkcs11-tool`.
  Zero new complexity; direct translation of the Python subprocess call.
- **Option B (future)**: Use the `cryptoki` crate (PKCS#11 bindings) to call
  `C_DeriveKey` directly, removing the runtime dependency on `pkcs11-tool`.

Option A is correct for the initial port; Option B can follow as a separate
improvement.

### 3. PIN-protected mode (APDU path)

`auxiliaries.py` reads the ADMIN DATA object (0x5FFF00) and PRINTED object
(0x5FC109) over raw APDU to detect and retrieve the PIN-protected management
key. This requires a working PC/SC stack:

- Add `pcsc` crate (`pcsclite` on Linux).
- Implement TLV parser (a ~50-line function; no external crate needed).
- Wrap in a `PcscContext` struct analogous to `send_apdu()` in Python.

### 4. Binary wire format

`constants.py` defines a bespoke byte layout with variable-length fields and a
linked-list spanning up to 16 PIV objects. This is the most correctness-critical
code. The strategy:

- Define a `PivObjectHeader` struct with explicit field sizes matching the
  Python offsets table.
- Use `byteorder::ReadBytesExt` / `WriteBytesExt` for all multi-byte reads.
- Add round-trip property tests (via `proptest`) that confirm
  `deserialize(serialize(x)) == x`.
- Add a compatibility test: hard-code a binary blob produced by the Python
  implementation and assert the Rust parser produces the expected fields.

### 5. EmulatedPiv for testing

The Python test suite uses an in-memory `EmulatedPiv`. Define a `PivBackend`
trait (analogous to Python's `PivInterface`) with implementations:

- `HardwarePiv` — shells out to `yubico-piv-tool`.
- `EmulatedPiv` — `HashMap<u32, Vec<u8>>` in memory; used in unit tests.

---

## Rust Crate Structure

```
yb/
├── Cargo.toml
├── src/
│   ├── main.rs            # clap CLI wiring; calls commands
│   ├── cli/
│   │   ├── mod.rs
│   │   ├── format.rs      # yb format
│   │   ├── store.rs       # yb store
│   │   ├── fetch.rs       # yb fetch
│   │   ├── list.rs        # yb list / ls
│   │   ├── remove.rs      # yb rm
│   │   ├── fsck.rs        # yb fsck
│   │   ├── self_test.rs   # yb self-test
│   │   └── list_readers.rs
│   ├── store/
│   │   ├── mod.rs         # Store / Object types, serialization
│   │   └── constants.rs   # Magic numbers, field offsets
│   ├── piv/
│   │   ├── mod.rs         # PivBackend trait
│   │   ├── hardware.rs    # HardwarePiv (yubico-piv-tool subprocess)
│   │   └── emulated.rs    # EmulatedPiv (tests)
│   ├── crypto.rs          # Hybrid encrypt/decrypt
│   ├── auxiliaries.rs     # TLV, PIN-protected mode, device helpers
│   ├── orchestrator.rs    # store_blob, fetch_blob, remove_blob, list_blobs
│   └── selector.rs        # Interactive YubiKey selector
└── tests/
    ├── store_basic.rs
    └── store_comprehensive.rs
```

---

## Dependency Plan

| Python dependency | Rust equivalent | Crate |
|-------------------|-----------------|-------|
| `click` | `clap` v4 | `clap` |
| `cryptography` (AES, HKDF, EC) | `ring` or `aws-lc-rs` | `ring` |
| `PyYAML` | `serde_yaml` | `serde`, `serde_yaml` |
| `prompt_toolkit` | `crossterm` | `crossterm` |
| `pyscard` (PC/SC) | `pcsc` | `pcsc` |
| `yubikey-manager` (enum) | `pcsc` + direct APDU | `pcsc` |
| `subprocess` (yubico-piv-tool) | `std::process::Command` | stdlib |
| `subprocess` (pkcs11-tool) | `std::process::Command` | stdlib |
| Shell completion | `clap_complete` | `clap_complete` |

All listed crates are well-maintained, have no GPL/LGPL licenses, and are
already present in nixpkgs.

---

## Implementation Phases

### Phase 0 — Project scaffold (1–2 days)

- `cargo new --bin yb`; set up `Cargo.toml` with all dependencies pinned.
- Add `PivBackend` trait and `EmulatedPiv` stub.
- Wire `clap` CLI skeleton (all subcommands return `unimplemented!()`).
- Set up CI (GitHub Actions): `cargo test`, `cargo clippy --deny warnings`,
  `cargo fmt --check`.
- Add `Cargo.lock` and a minimal `flake.nix` / `default.nix` that calls
  `rustPlatform.buildRustPackage`.

### Phase 1 — Wire format (3–4 days)

- Port `constants.py` to `store/constants.rs`.
- Port `store.py` serialization/deserialization to `store/mod.rs`.
- Port `EmulatedPiv` to `piv/emulated.rs`.
- Port `tests/test_store.py` and `tests/test_store_comprehensive.py`.
- **Exit criterion**: all ported tests pass; round-trip property tests pass.

### Phase 2 — HardwarePiv subprocess layer (2–3 days)

- Port `piv.py` `HardwarePiv` to `piv/hardware.rs`.
- Port device enumeration (initially via `ykman list --serials` subprocess;
  can be replaced with `pcsc` in Phase 5).
- **Exit criterion**: `yb format`, `yb ls`, `yb store --unencrypted`,
  `yb fetch`, `yb rm` work end-to-end with a real YubiKey.

### Phase 3 — Cryptography (2–3 days)

- Port `crypto.py` to `crypto.rs` using `ring`.
- Encryption path: generate ephemeral EC key, ECDH, HKDF, AES-CBC → pure Rust.
- Decryption path: shell out to `pkcs11-tool` for the YubiKey ECDH step
  (same as Python), then HKDF + AES-CBC in Rust.
- **Exit criterion**: `yb store --encrypted` and `yb fetch` of encrypted blobs
  work end-to-end; `yb self-test` passes.

### Phase 4 — PIN-protected mode (2–3 days)

- Add `pcsc` crate.
- Port TLV parser from `auxiliaries.py`.
- Port `send_apdu()` and ADMIN DATA / PRINTED object reads.
- **Exit criterion**: `yb --pin` works with a PIN-protected YubiKey.

### Phase 5 — Interactive selector + polish (2 days)

- Port `yubikey_selector.py` using `crossterm`.
- LED flash APDU via `pcsc`.
- Replace `ykman` subprocess enumeration with `pcsc` if not already done.
- Port `yb fsck`, `yb self-test`, `yb list-readers`.
- Shell completion via `clap_complete`.
- **Exit criterion**: all subcommands functional; `yb self-test` passes.

### Phase 6 — crates.io + nixpkgs (1 day)

- Fill in `Cargo.toml` metadata: `description`, `license`, `repository`,
  `keywords`, `categories`, `homepage`.
- Publish to crates.io: `cargo publish`.
- Update nixpkgs package from `buildPythonApplication` to
  `rustPlatform.buildRustPackage`; update the nixpkgs PR / derivation.

---

## Wire-Format Compatibility Strategy

The binary layout in PIV objects must remain byte-for-byte identical so that
data stored with the Python tool is readable by the Rust tool and vice versa.

1. Extract the Python implementation's format constants into a shared
   `fixtures/` directory as binary test vectors (hex strings).
2. In Rust, assert that parsing those vectors produces the expected field
   values.
3. Assert that re-serializing produces the identical bytes.
4. Run this test in CI for every PR.

---

## crates.io Publishing Checklist

- `[package]` in `Cargo.toml`:
  - `name = "yb"`
  - `version = "0.1.0"`
  - `license = "MIT"`
  - `description = "Secure blob storage on a YubiKey"`
  - `repository = "https://github.com/douzebis/yb"`
  - `keywords = ["yubikey", "piv", "encryption", "security"]`
  - `categories = ["command-line-utilities", "cryptography"]`
  - `readme = "README.md"`
- `Cargo.lock` committed (binary crate).
- `cargo publish --dry-run` passes before tagging.
- Tag format: `v0.2.0` (increment from Python's `v0.1.0` to mark the Rust
  rewrite clearly).

---

## nixpkgs Update

Replace the current `buildPythonApplication` derivation with:

```nix
rustPlatform.buildRustPackage {
  pname = "yb";
  version = "0.2.0";

  src = fetchFromGitHub {
    owner = "douzebis";
    repo = "yb";
    rev = "v0.2.0";
    hash = "sha256-...";
  };

  cargoHash = "sha256-...";

  nativeBuildInputs = [ pkg-config ];
  buildInputs = [ pcsclite ];

  # Runtime tools still needed (until Phase 6 Option B)
  postInstall = ''
    wrapProgram $out/bin/yb \
      --prefix PATH : ${lib.makeBinPath [
        yubico-piv-tool
        opensc        # pkcs11-tool
        openssl
        yubikey-manager
      ]}
  '';

  meta = {
    description = "Secure blob storage on a YubiKey";
    homepage = "https://github.com/douzebis/yb";
    license = lib.licenses.mit;
    maintainers = with lib.maintainers; [ douzebis ];
    mainProgram = "yb";
    platforms = lib.platforms.linux;
  };
}
```

Key differences from the Python derivation:
- No Python interpreter, no `propagatedBuildInputs` for Python packages.
- `pcsclite` is a build-time input (for `pcsc` crate linking).
- `cargoHash` replaces `pyproject.toml` dependency hashes.
- Runtime `PATH` wrapping remains (for `yubico-piv-tool`, `pkcs11-tool`).

---

## Risk Register

| Risk | Likelihood | Mitigation |
|------|-----------|------------|
| `ring` does not expose raw ECDH output (only via `agree_ephemeral`) | Medium | Use `agree_ephemeral` with a closure; matches Python's pattern exactly |
| `pcsc` crate has no packaged tests without hardware | Medium | Mock with `EmulatedPiv`; hardware tests are opt-in (env var gate) |
| `yubico-piv-tool` stdout format changes between versions | Low | Pin version in nix; parse defensively |
| PKCS#11 module path differs across distros | Low | Inherit `PKCS11_MODULE_PATH` from environment; document in README |
| nixpkgs reviewers require no subprocess calls | Low | Subprocess wrapping is standard practice for YubiKey tools in nixpkgs |

---

## Estimated Total Effort

| Phase | Days |
|-------|------|
| 0 — Scaffold | 1–2 |
| 1 — Wire format | 3–4 |
| 2 — Hardware PIV | 2–3 |
| 3 — Cryptography | 2–3 |
| 4 — PIN-protected mode | 2–3 |
| 5 — Selector + polish | 2 |
| 6 — crates.io + nixpkgs | 1 |
| **Total** | **13–18 days** |

This assumes one developer familiar with both Rust and the YubiKey PIV
protocol, with access to a physical YubiKey for integration testing.
