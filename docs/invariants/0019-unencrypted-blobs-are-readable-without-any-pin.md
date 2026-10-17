<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0019 — Unencrypted Blobs Are Readable Without Any PIN

**Sources:** spec 0044

## Invariant

An unencrypted blob can always be read without any PIN or touch, in both
kinds of store, whatever the state of the YubiKey's PINs (blocked, few
attempts left, FIDO2 reset).  An encrypted blob never can.

- **Legacy stores:** `yb fetch` and `yubiblob_fetch_unencrypted` check
  the signature (no PIN) and never ask for or try the PIV PIN.
- **Post-quantum stores:** on request (`yb fetch --no-check`,
  `yubiblob_fetch_unencrypted`), with the checksum only (invariant 0006).

## Why

Content stored unencrypted is protected by other means (a KeePass
database by its master key) or is public.  A blocked PIN, or a FIDO2
reset, must not make it unreadable: the bytes are on the card.

## Where the code keeps it

- `orchestrator::fetch_unencrypted`, and `post_quantum::ChecksumOnly`
  (no FIDO2); `LegacyProtection::open` asks for no PIN for unencrypted
  blobs.  `NoPinFetchError::Encrypted` refuses encrypted ones.

## Limits

- A PIV reset erases the PIV objects, and with them the store: nothing
  is left to read.

## Regression tests

- `rust/yb-piv-harness/src/bin/yb_cli_tests.rs`: `pq_no_check`, `pq_no_check_after_fido2_reset`, `legacy_unencrypted_fetch_needs_no_pin`
- `rust/yb-fido2-emulator/tests/yubiblob_tests.rs`: `fetch_unencrypted_without_fido2`, `legacy_kind`
