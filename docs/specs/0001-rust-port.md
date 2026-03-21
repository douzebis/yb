<!--
SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
SPDX-FileCopyrightText: 2025 - 2026 Thales Cloud Sécurisé

SPDX-License-Identifier: MIT
-->

# 0001 — Rust port of the yb CLI

**Status:** implemented
**App:** yb (Rust)
**Implemented in:** 2026-03-20

## Problem

The Python implementation of `yb` requires a Python interpreter, yubikey-manager,
and associated dependencies at runtime.  This makes distribution and deployment
heavier than necessary for a security tool that users may want to run in minimal
environments.  A self-contained native binary is preferable.

## Goals

- Port the complete `yb` CLI to Rust, producing a single statically-linked binary.
- Preserve full wire-format compatibility with existing stores written by the
  Python implementation.
- Support all existing subcommands: `format`, `store`, `fetch`, `list` (alias
  `ls`), `remove` (alias `rm`), `fsck`, `list-readers`.
- Hybrid encryption (ephemeral EC P-256 ECDH + HKDF-SHA256 + AES-256-CBC) must
  interoperate with blobs encrypted by the Python version.
- PIN-protected management key mode must be supported for write operations.
- Global options (`--serial`, `--reader`, `--key`, `--pin`, `--debug`,
  `--allow-defaults`) must be placed before the subcommand name, matching Click
  group option semantics.
- Nix build via crane: `nix build .#yb-rust` produces the binary.
- All unit tests pass (`cargo test`).

## Non-goals

- Interactive device selector (crossterm TUI) — deferred.
- `yb self-test` subcommand — deferred.
- Shell completion generation — deferred.
- Interactive PIN prompting (PIN must be supplied via `--pin`) — deferred.
- Replacing the Python implementation; both coexist during the port.

## Specification

### Repository layout

The Rust port lives under `rust/` at the repo root, leaving the Python source
under `src/yb/` untouched.

```
rust/
  Cargo.toml          # workspace root
  yb/
    Cargo.toml
    src/
      main.rs         # CLI (clap v4), entry point
      context.rs      # Context: device selection, key retrieval
      orchestrator.rs # store_blob / fetch_blob / remove_blob / list_blobs
      crypto.rs       # hybrid_encrypt / hybrid_decrypt
      auxiliaries.rs  # TLV parser, default-cred check, PIN-protected mgmt key
      store/
        mod.rs        # Store, Object: parse/serialise PIV objects
        constants.rs  # wire-format constants and offsets
      piv/
        mod.rs        # PivBackend trait, DeviceInfo
        hardware.rs   # HardwarePiv (yubico-piv-tool + pcsc APDUs)
        emulated.rs   # EmulatedPiv (in-memory, for unit tests)
      cli/
        format.rs     # yb format
        store.rs      # yb store
        fetch.rs      # yb fetch
        list.rs       # yb list / ls
        remove.rs     # yb remove / rm
        fsck.rs       # yb fsck
        list_readers.rs
```

### Wire format

Unchanged from the Python implementation.  Binary layout constants are in
`store/constants.rs`.  Key fields:

| Offset | Size | Field |
|--------|------|-------|
| 0x00 | 4 | Magic `0xF2ED5F0B` (LE) |
| 0x04 | 1 | Object count |
| 0x05 | 1 | Store key slot |
| 0x06 | 3 | Object age (24-bit LE) |
| 0x09 | 1 | Chunk position |
| 0x0A | 1 | Next chunk index |
| 0x0B | 4 | Blob mtime (Unix timestamp, LE) |
| 0x0F | 3 | Blob size (24-bit LE) |
| 0x12 | 1 | Blob key slot |
| 0x13 | 3 | Blob plain size (24-bit LE) |
| 0x16 | 1 | Blob name length |
| 0x17 | N | Blob name (UTF-8) |
| 0x17+N | … | Payload |

Continuation objects use offset `0x0B` as payload start (no metadata header).

A `python_compat_vector` unit test hard-codes a binary blob with known field
values and asserts round-trip byte identity.

### Cryptography

`hybrid_encrypt(plaintext, peer_public_key)`:
1. Generate ephemeral EC P-256 key pair.
2. ECDH with peer public key → shared secret.
3. HKDF-SHA256 (no salt, no info) → 32-byte AES key.
4. AES-256-CBC with random IV, PKCS#7 padding.
5. Output: `epk_uncompressed(65) || iv(16) || ciphertext`.

`hybrid_decrypt(serial, slot, encrypted, pin, debug)`:
1. Parse envelope: first 65 bytes = ephemeral public key, next 16 = IV.
2. Reconstruct ephemeral public key → SPKI DER.
3. Write to temp file; call `pkcs11-tool --derive` subprocess with YubiKey
   PKCS#11 module to perform ECDH on-card → shared secret bytes.
4. HKDF-SHA256 → AES key; AES-256-CBC decrypt.

### PIN-protected management key retrieval

When the YubiKey has management key stored in the PRINTED object (0x5FC109),
detected via the admin-data object (0x5FFF00) tag `0x80 → 0x81` bitfield:

1. Call `ykman piv objects export 0x5FC109 - --pin <pin>` as a subprocess.
   This performs PIN verification and object retrieval in a single session
   (yubico-piv-tool subprocess calls lose PIN state between invocations).
2. Parse TLV: `88 <len> [ 89 <len> <key_bytes> ]`.
3. Return key as hex string for use in `--key=<hex>` argument to
   `yubico-piv-tool write-object`.

### Global option placement

All options on the top-level `Cli` struct use no `global = true`.  This
matches Click group semantics: options must appear before the subcommand name.
Passing e.g. `--pin` after the subcommand name produces a clap error.

### `yb ls` output format

No header row.  One line per blob:

```
<E> <CC>  <SIZE>  <DATE>  <NAME>
```

- `E`: `-` = encrypted, `U` = unencrypted.
- `CC`: chunk count (2 digits).
- `SIZE`: plain size in bytes (right-aligned, 8 chars).
- `DATE`: `%b %e %H:%M` (local time), matching `ls -l` style.
- `NAME`: blob name.

### Nix build

`default.nix` exports:

- `yb-rust` — the release binary (crane `buildPackage`, checkPhase runs
  `cargoFmt`, `cargoClippy`, `cargoTest`).
- `dev-shell` — development shell with `cargo build --release` on entry,
  `rust/target/release` on PATH, `pcsclite`, `opensc`, `yubico-piv-tool`,
  `ykman`, `ccid`, `usbutils`.

### pcscd / YubiKey passthrough (VM setup)

When running inside a KVM/libvirt VM with USB passthrough, the host's `pcscd`
must be stopped before attaching the YubiKey; otherwise it holds the device
open and the guest kernel cannot complete USB SET_CONFIGURATION, preventing
interface enumeration and smart-card reader detection.

## Open questions

- None.

## References

- Python implementation: `src/yb/`
- Wire format: `doc/DESIGN.md`
- PIN-protected mode: `doc/PIN_PROTECTED_MODE.md`
- Rust port plan (historical): `docs/rust-port-plan.md`
