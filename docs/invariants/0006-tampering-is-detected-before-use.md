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

## Regression tests

- `rust/yb/tests/cli_tests.rs`: `renamed_blob_is_corrupted_and_not_fetched`, `tampered_blob_is_not_fetched`, `tampered_mtime_is_corrupted`, `one_tampered_blob_among_several_fetches_nothing`, `signing_failure_stores_nothing`, `newer_signature_version_is_not_corruption`
