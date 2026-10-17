<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0006 — Tampering Is Detected Before Use

**Sources:** spec 0017, spec 0033

## Invariant

Every blob yb stores is signed by the store's slot key, over its name,
metadata and bytes; if it cannot sign, it stores nothing.  `yb fetch`
checks the signatures of all matched blobs, with the certificate and no
PIN, before writing or decrypting any, and fetches nothing if one does
not verify.  `yb ls` and `yb fsck` mark such a blob CORRUPTED.

## Why

Anyone able to write PIV objects without the PIN (a leaked management
key, another tool, corruption) must not be able to alter, swap or
rename blobs unnoticed.

## Where the code keeps it

- `append_signature_trailer`, `check_blob_signature`; the verification
  loop at the top of `yb fetch`.

## Limits

- No rollback protection: an older, genuinely signed store state cannot
  be told apart by the YubiKey alone.
- Someone with the PIN can sign anything.
- A stripped signature yields an UNSIGNED blob, fetched with a warning
  (spec 0033 non-goal).
- A signature version this yb does not know (written by a newer yb) is
  not checkable here: the blob is fetched with a warning, not called
  CORRUPTED, so that a new version raises no false alarm on older
  installations (yb 0.5 did).  Changing the version byte gains an
  attacker nothing a stripped signature does not already give.

## Post-quantum stores (spec 0028)

The seal replaces the signature as proof of authorship (D5, D6): each
blob is encrypted with AES-GCM under a key from the YubiKey's FIDO2
`hmac-secret` (the tag is the seal), or sealed by an HMAC with such a
key.  `yb fetch` checks every matched blob's checksum (no PIN), then its
seal and the management key (FIDO2 PIN, one touch each), before writing
any, and returns nothing if one fails (exit status 4).  The checksum,
which `yb ls` and `yb fsck` check without PIN, detects corruption only:
anyone can recompute it.

## Regression tests

- `rust/yb-fido2-emulator/tests/post_quantum_protection_tests.rs`: `forged_blobs_pass_the_checksum_but_not_the_seal`, `corruption_is_detected_without_pin`
- `rust/yb-piv-harness/src/bin/yb_cli_tests.rs`: `pq_corruption_exits_4`
- `rust/yb/tests/cli_tests.rs`: `renamed_blob_is_corrupted_and_not_fetched`, `tampered_blob_is_not_fetched`, `tampered_mtime_is_corrupted`, `one_tampered_blob_among_several_fetches_nothing`, `signing_failure_stores_nothing`, `newer_signature_version_is_not_corruption`
