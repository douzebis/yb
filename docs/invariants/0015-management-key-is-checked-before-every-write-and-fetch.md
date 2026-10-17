<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0015 — The Management Key Is Checked Before Every Write and Fetch

**Sources:** spec 0028 (D7, D11)

## Invariant

Every `yb store`, `yb fetch` and `yb rm` of a post-quantum store, and
`yb fsck`, unwraps the store's copy of the management key with the
FIDO2 key (in the same touch as the blob's key) and authenticates to
the card with it before anything else.  If the card rejects it, the
command stops with exit status 4, returns nothing and writes nothing.

## Why

An attacker without the FIDO2 PIN can write to the store only after a
PIV reset, which sets the factory management key; they cannot restore
the original key, which only the YubiKey's FIDO2 application can
unwrap.  The mismatch reveals the reset, whatever objects they write
back.

## Where the code keeps it

- `PostQuantumProtection::assert` and `management_key`
  (`checked_management_key`), used by `protect`, `open` and the
  commands; `IntegrityError::ManagementKeyMismatch` maps to status 4.

## Limits

- A user who changes the key with another tool sees the same error
  until `yb management-key set`.

## Regression tests

- `rust/yb-fido2-emulator/tests/post_quantum_protection_tests.rs`: `piv_reset_is_detected`
- `rust/yb-piv-harness/src/bin/yb_cli_tests.rs`: `pq_piv_reset_exits_4`, `pq_management_key_set`
