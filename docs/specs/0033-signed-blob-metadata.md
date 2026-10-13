<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0033 — Signed Blob Metadata, Verified on Fetch

**Status:** draft
**App:** yb
**Implemented in:** <!-- YYYY-MM-DD, fill after implementation -->

## Problem

Spec 0017 signs each blob's stored bytes with the slot key (ECDSA P-256),
to detect corruption (`yb fsck`, `yb ls`).  It was not designed against an
attacker, and the Python-era design document claimed protections that
neither implementation provides ("replay attacks: age-based freshness";
audit finding 1.2):

- **The signature covers the payload only**, not the blob's name, age,
  encryption slot or sizes: two blobs can be swapped between names, and
  metadata altered, without breaking any signature.
- **`yb fetch` does not verify signatures** (spec 0017 non-goal): a
  tampered unencrypted blob is returned as is; an encrypted one is caught
  only by its AES-GCM tag, which anyone with the public certificate can
  produce for content of their choice.
- **An unsigned blob is accepted:** `yb ls` shows it as "unverified", not
  as a problem, so removing a signature defeats it.
- **Signing failures are silent:** if signing fails, or the store has no
  room for the signature's spill chunk, the blob is stored unsigned with a
  warning only.

## Threat model

The signature key is the store's slot key (0x82), usable only with the
PIN.  Writing PIV objects needs the management key, which yb keeps on the
YubiKey, unlocked by the PIN (spec 0027), or which the user holds.

This spec protects blobs against anyone who can **write PIV objects but
cannot use the PIN**: corruption, a leaked or default management key not
kept on the YubiKey, a tool writing objects directly.

It cannot protect against someone **with the PIN**: they can sign
anything.  In particular, rolling the whole store back to an older,
genuinely signed state is undetectable by the YubiKey alone, since a
counter that only the legitimate user could advance would itself need a
secret the attacker lacks.  The documentation states this limit instead
of claiming replay protection.

## Goals

- **G1 — Bound metadata.**  A new signature (trailer version 2) covers a
  domain-separation tag, the blob's name, its key slot, its compression
  flag, its plain and stored sizes, its modification time, and its stored
  bytes.
- **G2 — A bad signature refuses the fetch.**  `yb fetch` verifies the
  signature with the public key of the slot's certificate (no PIN) before
  returning or decrypting data; a mismatch is an error naming the blob as
  corrupted or tampered with, and nothing is written.
- **G3 — Unsigned is visible.**  A blob without a signature (written by a
  yb version before spec 0017) is still fetched, with a warning; `yb ls`
  and `yb fsck` mark it `UNSIGNED`.
- **G4 — No unsigned stores.**  `yb store` fails, writing nothing, if it
  cannot sign; capacity already counts the signature's spill chunk (spec
  0031).
- **G5 — Honest documentation.**  The README and `rust/docs/DESIGN.md`
  state the threat model above, including the rollback limit.

## Non-goals

- Rollback protection (impossible with one YubiKey; see Threat model).
- Refusing unsigned blobs, or a command to re-sign them: a user who wants
  a blob signed stores it again.  Someone able to write objects without
  the PIN could strip a signature and cause only a warning; accepted for
  now.
- Signing with a key other than the store's slot key.
- Changing the encryption scheme.

## Specification

### Trailer version 2

`0x02 ‖ r ‖ s` (65 bytes, as version 1), where `(r, s)` is the ECDSA
P-256 signature, by the slot key, of SHA-256 over:

```
"yb-blob-sig-v2\0"
‖ u8 len(name) ‖ name
‖ u8 blob_key_slot ‖ u8 is_compressed
‖ u32le blob_plain_size ‖ u32le blob_size ‖ u32le blob_mtime
‖ stored bytes
```

The age is not included: it changes when objects are rewritten, and does
not identify a version against an attacker who can re-sign anyway.  New
stores write version 2; version 1 is still verified.

### Verification

| Trailer | `fetch` | `ls`, `fsck` |
|---|---|---|
| v2, valid | returns data | (nothing) / verified |
| v2, invalid | **error**: corrupted or tampered | CORRUPTED |
| v1 (payload only), valid | returns data | (nothing) / verified |
| v1, invalid | **error** | CORRUPTED |
| none | returns data, with a warning | UNSIGNED |

Verification happens before decryption, so a tampered encrypted blob
never reaches the PIN-protected ECDH operation.

### Store

`append_signature_trailer` returns an error instead of warning; the
store writes nothing in that case (the error happens before any write).

### Tests

- Tampering with a v2 blob's name, metadata or bytes makes `fetch` fail
  and `ls` show CORRUPTED (simulated card).
- v1 blobs (fixture) still verify; unsigned blobs fetch with a warning and
  show UNSIGNED.
- A signing failure stores nothing.

## Open questions

None.

## References

- Spec 0017 — blob integrity signature (version 1).
- Spec 0018 — integrity signals in `yb ls`.
- Spec 0027 — management key kept on the YubiKey.
- Spec 0031 — rip-safe replace; `objects_needed`.
- `docs/reviews/2026-10-python-design-audit.md`, finding 1.2.
