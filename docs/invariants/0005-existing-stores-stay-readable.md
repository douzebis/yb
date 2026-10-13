<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0005 — Existing Stores Stay Readable

**Sources:** docs/YBLOB_FORMAT.md, spec 0006, spec 0033, spec 0034 G4

## Invariant

Every store and blob written by an earlier yb, the Python
implementation included, stays readable: the object format, legacy
AES-CBC blobs, version 1 signatures, and unsigned blobs.

## Why

A YubiKey outlives yb versions; its blobs are often the only copy.

## Where the code keeps it

- `Object::from_bytes`; `hybrid_decrypt`'s version dispatch;
  `check_blob_signature` (v1 and v2).

## Limits

- Legacy blobs are flagged (`LEGACY`, `UNSIGNED`) and should be stored
  again; they are not rewritten silently.

## Regression tests

- `rust/yb-core/src/store/tests.rs`: `python_compat_vector`
- `rust/yb/tests/cli_tests.rs`: `legacy_cbc_blob_is_fetched_and_flagged`, `v1_signature_still_verifies`, `unsigned_blob_is_fetched`
