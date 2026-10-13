<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0035 — Storage Key Rotation

**Status:** pending
**App:** yb
**Implemented in:** <!-- YYYY-MM-DD, fill after implementation -->

> **Pending.**  Recorded for later; not to be implemented now
> (decision of 2026-10-13).  Until then, rotating the storage key means
> copying the blobs to a freshly formatted YubiKey.

## Problem

Blobs are encrypted with ephemeral-static ECDH against the store's slot
key (0x82 by default).  Whoever obtains that key, or a way to use it,
decrypts every blob ever stored with it, including copies of the store
taken earlier (the store is readable without the PIN).  The Python-era
design document's "forward secrecy: fresh ephemeral key per store" was
never true (audit finding 1.2).

Per-blob forward secrecy is incompatible with storage that is read back
later: decryption must stay possible, so the key must stay.  What is
achievable is **forward secrecy per key generation**: replacing the
storage key and re-encrypting every blob under the new one, after which
the old key is destroyed and old copies of the store become undecryptable.

Today the only way is manual: format a second YubiKey, copy every blob to
it (`yb fetch`, `yb --serial S2 store`), then reset the first one.

## Goals

- **G1 — Rotate in place.**  `yb rotate-storage-key` generates a new key in
  a spare slot, re-encrypts every encrypted blob under it, makes it the
  store's key, and destroys the old key.
- **G2 — Interruption-safe.**  Pulling the YubiKey out at any point leaves
  every blob decryptable: each blob is replaced through the rip-safe path
  (spec 0031), and the old key is destroyed only after no blob uses it.
  Running the command again resumes the rotation.
- **G3 — Capacity.**  Needs room for one more copy of the largest blob,
  as any replace (spec 0031); checked before starting.
- **G4 — Documented alternative.**  The two-YubiKey copy stays documented,
  for moving to new hardware.

## Non-goals

- Per-blob forward secrecy (impossible for stored data).
- Rotating the management key (spec 0027) or the PIN.
- Unencrypted blobs (nothing to re-encrypt; they are re-signed only if
  spec 0033 requires).

## Specification

To be completed after the open questions.  Sketch, using the per-blob
`blob_key_slot` field that the format already has:

1. Choose a spare retired slot (e.g. 0x83) with no key in use.
2. Generate a key and a certificate in it (management key and PIN).
3. For each blob whose `blob_key_slot` is the old slot: fetch and decrypt
   (old key), store again encrypted to the new slot (rip-safe replace).
4. When no blob uses the old slot: make the new slot the store's key slot,
   then destroy the old key (overwrite it with a fresh key whose private
   part is never used, and delete its certificate).

A rotation in progress is recognizable from the blobs' slots, so the
command can resume.

## Open questions

- The store's key slot is recorded in every object's header
  (`store_key_slot`): changing it means rewriting every object, including
  empty ones.  Alternatively, keep the header's value as a default and let
  per-blob `blob_key_slot` decide.  Which?
- Is "destroying" a PIV key slot possible without a new key (no DELETE
  KEY in PIV before firmware 5.7: `MOVE/DELETE KEY` exists from 5.7)?
- Should the two slots alternate (0x82 ⇄ 0x83) on successive rotations?

## References

- Spec 0006 — encryption scheme.
- Spec 0027 — management key rotation (for the command's shape).
- Spec 0031 — rip-safe replace.
- Spec 0033 — signatures (re-signing during rotation).
- `docs/reviews/2026-10-python-design-audit.md`, finding 1.2.
