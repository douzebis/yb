<!--
SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0017 — Blob Integrity Signature

**Status:** implemented
**App:** yb
**Implemented in:** 2026-03-23

## Problem

YubiKeys are stored in physical safes for long periods.  NVM cells can
degrade over time, silently corrupting stored blobs.  Currently the only
way to verify blob integrity is `yb fetch` followed by decryption — which
requires the PIN and a workstation with PC/SC.

Operators need a periodic, credential-free integrity audit: confirm that
every blob's stored bytes are exactly as written, without decrypting
anything or entering any credential.

## Goals

- `yb store` appends a P-256 ECDSA signature of the stored payload to
  every blob at write time (PIN already required — no extra credential
  burden).
- `yb fsck` can verify all blob signatures using only the public key from
  the X.509 certificate in slot `0x82` — no PIN, no management key.
- The scheme is backward-compatible: blobs written by older `yb` versions
  (no signature) are reported as UNVERIFIED rather than errors.
- The scheme is format-compatible: old `yb` clients handle new-format
  stores correctly (`fetch` and `remove` work without modification).
- Corruption anywhere in the payload chain is detected by `fsck`.

## Non-goals

- Signing unencrypted blobs differently from encrypted blobs (the
  signature covers stored bytes regardless of encryption).
- Using a key other than the store's existing ECDH key in slot `0x82`.
- Detecting substitution of the entire YubiKey (out of scope for NVM
  wear threat model).
- Verifying signatures on `fetch` (encrypted blobs already have GCM
  authentication; unencrypted blobs can be addressed in a follow-up).

## Background: yb version taxonomy

This spec introduces three generations of `yb` stores, referred to
throughout as yb0, yb1, and yb2:

| Generation | Object sizing | Signature | Spec |
|---|---|---|---|
| **yb0** | Fixed-size slots (e.g. 3,052 bytes, padded with zeros) | None | — |
| **yb1** | Exact-size slots, capped at 3,063 bytes | None | [spec 0010](0010-dynamic-object-sizing.md) |
| **yb2** | Exact-size slots, capped at 3,063 bytes | ECDSA appended after payload | [spec 0017](0017-blob-integrity-signature.md) |

## Specification

### 1. Signature layout

`yb store` (yb2) appends a **65-byte signature trailer** immediately
after the last payload byte in the blob chain.  The trailer is not a new
chunk type — it occupies the zero-padding region of the last slot, or
spills into one additional continuation slot if the last slot is full.

The trailer layout, starting at byte offset `BLOB_SIZE` within the
assembled chain:

```
Offset (from BLOB_SIZE)  Size  Field
───────────────────────  ────  ──────────────────────────────────────
0                          1   SIG_VERSION = 0x01
1                         32   SIG_R  — r component, raw big-endian u256
33                        32   SIG_S  — s component, raw big-endian u256
```

Total: 65 bytes.

`SIG_R` and `SIG_S` are the raw 32-byte big-endian representations of
the two ECDSA integers, **not** DER-encoded.  The YubiKey returns a DER
`SEQUENCE { INTEGER r, INTEGER s }`; `yb store` strips the DER framing
and zero-pads each integer to exactly 32 bytes before storing.
`yb fsck` reconstructs the DER encoding from the stored raw values
before passing to the P-256 verifier.

A note on the ephemeral scalar `k` used during ECDSA signing: security
requires that `k` is never reused across two signatures with the same
private key — reuse leaks the private key algebraically (this is how the
PS3 master signing key was recovered in 2010; Sony's RNG returned a
constant).  The YubiKey uses its internal hardware RNG for `k`; `yb`
does not control or observe it.

### 2. Signed data

The signature covers:

```
SHA-256( payload_bytes )
```

where `payload_bytes` is the concatenation of all payload bytes from the
blob chain, trimmed to exactly `BLOB_SIZE` bytes — the same bytes that
`yb fetch` returns before decryption.

For encrypted blobs this is the raw ciphertext (including the GCM tag
and ephemeral public key).  For unencrypted blobs it is the plaintext.

### 3. Signing at store time

`yb store` (yb2):

1. Assembles the full payload (post-compression, post-encryption) as
   today.
2. Computes `digest = SHA-256(payload_bytes)`.
3. Issues PIV GENERAL AUTHENTICATE (ECDSA, algorithm `0x11` — P-256) on
   slot `0x82` with `digest` as input.  PIN is already held in context.
4. Extracts raw `(r, s)` from the DER response: parse
   `SEQUENCE { INTEGER r, INTEGER s }`, zero-pad each to 32 bytes.
5. Appends the 65-byte trailer after the payload bytes in the last slot.
   If the last slot's padding region has at least 65 bytes free, the
   trailer fits entirely in-place.  Otherwise the remaining bytes spill
   into one additional continuation slot (normal `CHUNK_POS` increment).
   If no free slot is available for spill, a warning is emitted and the
   blob is stored without a signature.
6. Writes all dirty objects via `Store::sync` as today.

If the PIV ECDSA operation fails, `store` soft-fails: the blob is written
without a signature trailer and a warning is emitted.

### 4. Verification at fsck time

#### Definitions

Let `trailing` be the bytes stored in the chain beyond offset `BLOB_SIZE`
(i.e. `total_chain_bytes - BLOB_SIZE`).  `trailing.len()` is zero for
yb0/yb1 blobs and 65 for normal yb2 blobs.

**Supernumerary slot** — the last slot in the chain was not needed to
hold byte `#BLOB_SIZE`.  Formally: `combined_without_last >= BLOB_SIZE`,
where `combined_without_last` is the sum of payload lengths of all slots
except the last.

#### Algorithm

`yb fsck` reads the X.509 certificate from slot `0x82` (`GET DATA` on
`0x5F_C105`) and extracts the P-256 public key.  No credentials required.

For each blob, evaluate the following conditions in order (if/elif/…):

| # | Condition | Additional checks | Verdict |
|---|---|---|---|
| 1 | `total_chain_bytes < BLOB_SIZE` | — | CORRUPTED (truncated) |
| 2 | `trailing.len() == 0` | — | UNVERIFIED (yb0 or yb1, no trailer) |
| 3 | `trailing.len() > 65` | No supernumerary slot; all trailing bytes zero | UNVERIFIED (yb0 oversized slot); else CORRUPTED |
| 4 | `trailing.len() == 65` | `trailing[0] == 0x00`: no supernumerary, all zero → UNVERIFIED; `trailing[0] == 0x01`: verify ECDSA → VERIFIED or CORRUPTED; any other value → CORRUPTED | VERIFIED, UNVERIFIED, or CORRUPTED |
| 5 | `0 < trailing.len() < 65` | No supernumerary slot; all trailing bytes zero | UNVERIFIED (yb0 partial padding); else CORRUPTED |

In row 4, `trailing[0]` is the `SIG_VERSION` byte: `0x00` indicates a
yb0 slot whose fixed-size padding happened to be exactly 65 bytes;
`0x01` indicates a yb2 ECDSA trailer.  When `SIG_VERSION == 0x01` and no
verifying key is available (cert unreadable), the verdict is UNVERIFIED.

### 5. `fsck` output

Default output gains a signature summary line:

```
Store: 20 objects, slot 0x82, age 47
Blobs: 8 stored, 11 objects free (~34 KB available)

  my-config          VERIFIED
  my-secret          VERIFIED
  old-key            UNVERIFIED
  ssh-key            CORRUPTED

Integrity: 2 verified, 1 unverified, 1 corrupted
```

Exit code is 0 if all blobs are VERIFIED or UNVERIFIED; 1 if any blob is
CORRUPTED.

With `--verbose`, structural warnings (orphan chunks, duplicate blob
names) are printed after the integrity line, followed by a raw per-object
dump for debugging.

### 6. Backward compatibility

**Old `yb` reading a yb2 store:**

- `fetch`: reads exactly `BLOB_SIZE` bytes from the chain, stops.
  Signature trailer bytes are never seen.  ✓
- `remove`: resets all slots in the chain including any spill slot.  ✓
- Old `fsck`: may report anomalies on blobs with a spill slot (unexpected
  continuation).  This is a known limitation; upgrade `yb` before
  running integrity audits.

**yb2 reading a yb0 or yb1 store:**

- Blobs with no signature trailer are reported as UNVERIFIED.  ✓

### 7. PIV ECDSA APDU

```
Command:  00 87 11 82 [Lc] 7C [len] 82 00 81 20 [32-byte digest]
Response: 7C [len] 82 [sig_len] [DER-encoded SEQUENCE { INTEGER r, INTEGER s }]
```

Strip DER framing; zero-pad `r` and `s` to 32 bytes each to obtain the
stored `SIG_R` and `SIG_S`.  At verify time, reconstruct DER from the
stored raw values before passing to the P-256 verifier.

### 8. Object model changes

No new fields were added to the `Object` struct or the wire format.

The only behavioral change is in `Object::from_bytes`: previously it
trimmed `payload` to `blob_size` bytes when deserializing a head chunk.
Now it reads **all remaining bytes** in the slot into `payload`, so that
the signature trailer (which lives beyond `blob_size`) is preserved in
memory after a read-back.

Consumers that need only the blob content (`fetch_blob`) already truncate
`payload` to `blob_size` themselves.

### 9. `collect_blob_chain`

A new public function introduced in this spec:

```
collect_blob_chain(head: &Object, store: &Store)
    -> (payload: Vec<u8>, trailing: Vec<u8>, has_supernumerary_slot: bool)
```

It walks the chunk chain from `head`, concatenates all slot payloads,
then splits at `blob_size`:

- `payload` — the first `blob_size` bytes (the blob content, identical
  to what `fetch_blob` returns before decryption).
- `trailing` — everything beyond `blob_size` (empty for yb0/yb1; the
  65-byte signature trailer for yb2).
- `has_supernumerary_slot` — true if the chain would cover `blob_size`
  bytes without its last slot.

This function straddles the slot layer and the blob layer: it needs slot
boundaries to compute the supernumerary flag, but it splits the result at
the blob-content boundary (`blob_size`).  `fsck` calls it for every blob
to obtain the inputs for the verdict table in §4.

## Open questions

- Should `yb fetch` also verify the signature for unencrypted blobs
  (which lack GCM authentication)?  Left for a follow-up spec.
- `SIG_VERSION` is reserved for future algorithm agility (e.g. a
  hypothetical Ed25519 support in future YubiKey firmware).

## References

- [spec 0010](0010-dynamic-object-sizing.md) — dynamic PIV object sizing
- [docs/YBLOB_FORMAT.md](../YBLOB_FORMAT.md) — chunk layout and field offsets
- [NIST FIPS 186-5](https://doi.org/10.6028/NIST.FIPS.186-5) — ECDSA
- [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979) — deterministic k generation
- [Yubico PIV specification](https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html) — GENERAL AUTHENTICATE APDU
