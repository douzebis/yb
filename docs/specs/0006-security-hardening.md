<!--
SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
SPDX-FileCopyrightText: 2025 - 2026 Thales Cloud Sécurisé

SPDX-License-Identifier: MIT
-->

# 0006 — Security Hardening (Rust)

**Status:** ready
**App:** yb-core, yb
**Implemented in:** <!-- YYYY-MM-DD, fill after implementation -->

## Problem

`docs/sec-review.md` is a security analysis of the Python implementation.
Several of its findings apply directly to the Rust port.  This spec
identifies which ones, assesses their severity in the Rust context, and
specifies the required fixes.

### Findings from sec-review.md that apply to Rust

| # | Original finding | Applies to Rust? | Severity |
|---|---|---|---|
| 3.1 | AES-CBC without authentication (no MAC) | **YES** | Critical |
| 3.2 | PKCS7 padding oracle potential | **YES — same root cause as 3.1** | (covered by 3.1) |
| 2.3 | No Unicode normalization / control chars in blob names | **YES — null/slash only** | Low |
| 2.1 | X.509 subject string not validated | **NO — delegated to rcgen** | N/A |
| 8.3 | Internal error messages expose format details | **NO** | N/A |

Findings that do **not** apply to Rust:

| # | Original finding | Why it does not apply |
|---|---|---|
| 4.x | Command injection / subprocess args | Rust never forks subprocesses; all PIV ops are native PCSC APDUs |
| 6.1/6.2 | Secrets in debug output / process args | No subprocess calls; no `--key=...` in `ps` output |
| 6.3 | No memory zeroing | `zeroize` crate already used for key material (PKCS8 DER via `Zeroizing<>`) |
| 5.x | Dependency pinning / supply chain | Managed by Cargo.lock (already pinned) and Nix (hermetic builds) |
| 7.x | CI/CD security checks, signed releases | Out of scope for this spec |
| 1.1 | No rate-limiting on PIN attempts | Delegated to YubiKey hardware; same as Python |
| 8.1 | TOCTOU on device enumeration | Same as Python; inherent in PC/SC model; acceptable |
| 8.2 | No audit logging | Out of scope for this spec |
| 8.3 | Error messages expose internal format details | Rust error messages are already gated behind `{e:#}` at the CLI boundary; no extra leakage concern |

### Finding 3.1 in detail — AES-CBC without integrity protection

`crypto.rs` implements hybrid encryption as:

```
[Ephemeral pubkey (65 bytes)] || [IV (16 bytes)] || [AES-256-CBC ciphertext]
```

There is no MAC or authentication tag.  An attacker with write access to the
YubiKey's PIV data objects (which requires the management key, but is still
worth addressing) can:

- Flip bits in ciphertext blocks to corrupt plaintext in a controlled way.
- In principle mount a padding oracle attack: submit modified ciphertext,
  observe whether decryption succeeds or fails with an "unpadding error".

The Rust ciphertext is stored in PIV data objects on the YubiKey.  Any
process that can write those objects (any holder of the management key) can
mount these attacks.

The fix is to replace AES-256-CBC + PKCS7 with AES-256-GCM.  The wire
format changes, so **existing encrypted blobs become unreadable** after the
upgrade.  A migration path must be provided.

Note: AES-256-GCM with a 96-bit nonce has a birthday-bound collision
probability of 1 in 2^32 encryptions per key.  Since the key is derived
freshly via ECDH + HKDF for every single blob encryption, nonce reuse is
impossible and GCM is unconditionally safe here.

---

## Goals

1. Replace AES-256-CBC + PKCS7 with AES-256-GCM in `crypto.rs`.
2. New wire format: `[Ephemeral pubkey (65 B)] || [Nonce (12 B)] || [GCM ciphertext + tag (N+16 B)]`.
3. Old CBC-encrypted blobs can still be **decrypted** (backward-compatible read).
4. All new writes use GCM.  No new blobs are written in CBC format.
5. Reject blob names containing null bytes (0x00) or forward slashes (0x2F),
   matching Linux filesystem rules.  All other UTF-8 is allowed.

## Non-goals

- Migrating existing blobs automatically (the user runs `yb fetch` then
  `yb store` to re-encrypt; no automated migration command).
- Key rotation (`yb rotate-key` command) — tracked separately.
- Audit logging.
- Signed releases / CI hardening.
- Any change to the Python implementation.

---

## Specification

### S1 — Encryption wire format (GCM)

`crypto.rs` `hybrid_encrypt` produces:

```
ephemeral_pubkey (65 bytes, X9.62 uncompressed)
  || nonce (12 bytes, random, from OsRng)
  || GCM ciphertext + tag (plaintext_len + 16 bytes)
```

Total overhead per blob: 65 + 12 + 16 = 93 bytes (vs. 65 + 16 + 16 = 97
bytes for CBC, so slightly smaller for aligned sizes).

`HKDF_INFO` stays `b"hybrid-encryption"` — unchanged.  No salt.  Output
key length stays 32 bytes (AES-256).

AES-256-GCM Additional Authenticated Data (AAD): **none** (empty).  The
ephemeral public key is already authenticated implicitly: the ECDH step will
produce a different shared secret if the ephemeral key is tampered with, so
GCM decryption will fail.

Constants to add:

```rust
const NONCE_LEN: usize = 12;
const GCM_TAG_LEN: usize = 16;
```

`IV_LEN` (16) and the CBC types are removed.

### S2 — Backward-compatible decryption

`hybrid_decrypt` must detect the old CBC format and decrypt it correctly.

**Detection heuristic:** The minimum valid GCM blob is
65 + 12 + 16 = 93 bytes.  The minimum valid CBC blob is
65 + 16 + 16 = 97 bytes (1-block plaintext minimum with padding).  Both
formats are therefore at least 93 bytes long.

A more reliable discriminator: GCM nonces are 12 bytes; CBC IVs are 16
bytes.  We distinguish by trying to parse both and picking by total
length:

- If `encrypted.len() >= EPHEMERAL_PK_LEN + NONCE_LEN + GCM_TAG_LEN`
  **and** the length does not look like a CBC blob (see below), try GCM
  first.
- Fall back to CBC only if GCM authentication fails **and**
  `encrypted.len() >= EPHEMERAL_PK_LEN + IV_LEN`.

Practical approach: add a 1-byte **version prefix** to the new format:

```
version (1 byte: 0x02 = GCM)
  || ephemeral_pubkey (65 bytes)
  || nonce (12 bytes)
  || GCM ciphertext + tag
```

Old blobs have no version byte and start directly with the ephemeral
public-key's `0x04` uncompressed-point prefix byte.  A blob starting with
`0x04` is treated as legacy CBC; a blob starting with `0x02` is treated as
GCM.

This is unambiguous: `0x04` is the X9.62 uncompressed point indicator and
is the only valid first byte for an uncompressed P-256 point.  `0x02` is
the X9.62 compressed point indicator and will never appear as the first
byte of an uncompressed point.

Updated constants:

```rust
const VERSION_GCM: u8 = 0x02;
const EPHEMERAL_PK_LEN: usize = 65;
const NONCE_LEN: usize = 12;
const GCM_TAG_LEN: usize = 16;
const IV_LEN: usize = 16; // kept for legacy decryption only
```

`hybrid_encrypt` always writes `0x02 || ...`.

`hybrid_decrypt` branches on the first byte:
- `0x04` (legacy CBC): decode as before (skip version byte, `epk[0..65]`,
  `iv[65..81]`, `ciphertext[81..]`).
- `0x02` (GCM): `epk[1..66]`, `nonce[66..78]`, `ciphertext+tag[78..]`.
- Any other first byte: return an error.

### S3 — Cargo dependencies

Add to `yb-core/Cargo.toml`:

```toml
aes-gcm = "0.10"
```

Remove (or make optional) the CBC-only crates that are no longer needed for
new encryptions; keep them for legacy decryption:

```toml
cbc   = "0.1"  # kept for legacy decrypt only
```

Both `aes-gcm` and `cbc` use the same underlying `aes` crate, so no
additional `aes` dependency is introduced.

### S4 — Blob name validation

Blob names are stored as UTF-8 bytes inside PIV data objects and compared by
string equality.  There is no filesystem, no path traversal, and no shell
interpretation — so the only characters that need to be forbidden are those
that would cause ambiguity or corruption in the store format itself, matching
what Linux filesystems (`ext4`, `btrfs`) disallow:

- `0x00` (null) — terminates C strings and is invalid inside a PIV object field.
- `0x2F` (`/`) — the conventional path separator; forbidding it keeps names
  unambiguous when users derive blob names from file paths.

`orchestrator::validate_name` gains:

```rust
if name.contains('\0') || name.contains('/') {
    bail!("blob name must not contain null bytes or '/'");
}
```

All other Unicode (including non-ASCII, emoji, spaces, other punctuation) is
allowed, consistent with Linux filename semantics.

This check is applied at the write path only (`store_blob`); existing blobs
with such characters (not expected in practice) remain readable.

### S5 — X.509 subject validation

No application-level validation.  The subject string flows into
`parse_subject_dn` → `rcgen::DistinguishedName::push` → `cert.self_signed()`
in `hardware.rs` and `virtual_piv.rs`.  The `rcgen` crate validates all DN
values against ASN.1 `UTF8String` encoding rules internally and returns a
descriptive error if a value is malformed.  Any bad input is caught at
`generate_certificate` time with a clear error message.

Pre-validating in `format.rs` would require duplicating `rcgen`'s internal
rules (which are not part of its public API) and would likely diverge.
Delegating to `rcgen` is both more correct and less fragile.

### S6 — Tests

The existing `encrypt_decrypt_roundtrip` test in `crypto.rs` must be
updated to use the GCM path.

Add a second test `encrypt_decrypt_legacy_cbc` that exercises the
backward-compatible CBC decryption path (craft a legacy-format blob by
hand and verify `hybrid_decrypt` still decodes it correctly).

Add a test `validate_name_invalid_chars` in `orchestrator.rs` verifying that
null bytes and slashes are rejected, and that spaces, Unicode, and other
special characters are accepted.

---

## Open questions

None.

## References

- `docs/sec-review.md` — original security analysis (Python)
- `rust/yb-core/src/crypto.rs` — current AES-CBC implementation
- `rust/yb-core/src/orchestrator.rs` — `validate_name`
- `rust/yb/src/cli/format.rs` — subject parameter entry point
- NIST SP 800-38D — GCM specification
- RFC 5116 — An Interface and Algorithms for Authenticated Encryption
