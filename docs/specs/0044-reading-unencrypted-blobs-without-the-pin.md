<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0044 — Reading Unencrypted Blobs Without the PIN

**Status:** implemented
**App:** yb, yb-core, yubiblob
**Implemented in:** 2026-10-17

## Problem

An unencrypted blob holds nothing secret for yb to protect.  It is
stored unencrypted because its content is already protected, like a
KeePass database encrypted by its master key, or because it is public.
Its owner wants to read it whatever the state of the YubiKey's PINs.

**Legacy stores already allow this.**  An unencrypted blob's signature is
checked against the slot's certificate, which needs no PIN.  The PIN only
decrypts.

**Post-quantum stores do not.**  Every fetch needs the FIDO2 PIN and a
touch, encrypted or not.  yb checks the blob's seal and checks the
management key against the card (spec 0028, D6, D11), and both need the
card's `hmac-secret`.  So an unencrypted blob becomes unreadable when:

- the FIDO2 PIN is blocked (8 wrong PINs; only a FIDO2 reset clears it);
- the PIN is temporarily blocked (3 wrong in a row: replug);
- 3 attempts or fewer are left, and yb refuses to spend one (D10);
- the FIDO2 application was reset: the credential is gone for good, so
  no seal can ever be checked again;
- the FIDO2 side cannot be reached (permissions, FIDO application
  disabled).

After a FIDO2 reset, encrypted blobs are lost by design.  Unencrypted
ones need not be: their bytes are on the card, and their checksum still
detects corruption.

## Goals

- G1. **`yb fetch --no-check`** reads unencrypted blobs of a
  post-quantum store with no PIN, no touch and no FIDO2 device:
  - the checksum is checked;
  - the seal and the management key are not.
- G2. **The weakening is explicit:**
  - it happens only with the option;
  - yb says on standard error what was not checked, every time, even
    with `--quiet`;
  - encrypted blobs are refused, and nothing is fetched.
- G3. **yb suggests the option when it would help:** a fetch fails
  because the FIDO2 side is locked, reset or unreachable, and every blob
  asked for is unencrypted.  The error then says so.
- G4. **libyubiblob 0.3.0** offers the same read to applications, with
  the integrity level reported.  KeePassYB (spec 0046) uses it when the
  YubiKey is locked.
- G5. **Legacy stores:** an unencrypted blob is read without the PIN, as
  today, and that is guaranteed by tests.  `--no-check` is accepted
  and changes nothing: the signature is still checked, since that needs
  no PIN.

## Non-goals

- Reading encrypted blobs without the PIN: impossible by design.
- Repairing or rewriting anything: a checksum-only read writes nothing
  (invariant 0002).
- Making checksum-only the default, or a setting.
- Detecting a blocked PIV PIN for legacy stores: their unencrypted reads
  never need it.

## Specification

### S1. `yb fetch --no-check`

The name is not literal: the checksum is still checked.  It says what
matters to the user: the YubiKey checks nothing (no seal, no management
key).

```
yb fetch --no-check [-p | -o FILE | -d DIR] PATTERN…
```

**On a post-quantum store:**

1. **Matching and refusal:** every blob matched must be unencrypted.
   Otherwise yb fails with exit status 1, fetching nothing:
   "'NAME' is encrypted: it cannot be read without the FIDO2 PIN".
2. **Checksums:** each blob's checksum is checked, as by `fsck`.  A
   mismatch fails with exit status 4, "corrupted", fetching nothing.
3. **What is skipped:** no FIDO2 device is opened, so there is no PIN,
   no touch, no seal check and no management-key check.
4. **Output:** the blobs are written as with a normal fetch.
5. **Warning:** on standard error, once per command, even with
   `--quiet`:

   > warning: checksum only: 'NAME' was checked against corruption, not
   > against forgery (its seal and the YubiKey's management key were not
   > checked).  Anyone holding the management key could have written it.

**On a legacy store:** the same as a fetch without the option.

- Signatures are checked, which needs no PIN.
- Unencrypted blobs never ask for the PIN.
- Encrypted blobs are refused, as in step 1.

The option is listed in `yb fetch --help` and in the man page, with the
warning's meaning.

### S2. The suggestion

A post-quantum fetch without the option can fail for one of these
reasons:

| Failure | Today's error (spec 0028) |
|---|---|
| FIDO2 PIN blocked | `Fido2Error::PinBlocked` |
| 3 wrong PINs in a row | `PinAuthBlocked` |
| 3 attempts or fewer left | `FewAttempts` |
| FIDO2 reset (credential gone, or no PIN set) | `NoCredential`, `PinNotSet` |
| FIDO2 side not found | `NoDevice` |

If every blob asked for is unencrypted, yb adds to the error:

> hint: the blob(s) asked for are unencrypted: `yb fetch --no-check
> …` reads them without the FIDO2 PIN, checking their checksum only (not
> their seal).

The "few attempts left" check reads the attempts without using one
(D10).  So this hint appears **before** any PIN is typed: the user can
read the blob without risking an attempt.

The same applies to:

- a wrong PIN (`PinInvalid`) when 3 attempts or fewer remain;
- `fsck --seals`, for its checks.

### S3. libyubiblob 0.3.0

```c
/* Read an unencrypted blob without any PIN (spec 0044).  Post-quantum
 * stores: the checksum is checked, not the seal nor the management key;
 * legacy stores: the signature is checked as usual.  *verdict says which
 * (YUBIBLOB_SIGNATURE_CHECKSUM_OK or ..._VERIFIED / ..._UNSIGNED).
 * Encrypted blobs: YUBIBLOB_ERR_ENCRYPTED, nothing returned.
 * Free *data with yubiblob_buffer_free. */
yubiblob_status_t yubiblob_fetch_unencrypted(yubiblob_session_t* session,
                                             const char* name,
                                             uint8_t** data, size_t* len,
                                             yubiblob_signature_t* verdict);
```

- **New status:** `YUBIBLOB_ERR_ENCRYPTED = 20`.
- **Version:** the library becomes 0.3.0.  The ABI version stays 0
  (spec 0039 G7).
- **The existing `yubiblob_fetch` is unchanged.**  Applications choose
  the fallback themselves, after `yubiblob_fetch` fails with one of
  these statuses:
  - `PIN_BLOCKED`;
  - `REPLUG`;
  - `FEW_PIN_ATTEMPTS`;
  - `NO_CREDENTIAL`;
  - `NO_FIDO2_ACCESS`.

### S4. yb-core

- A function `fetch_unencrypted(store, piv, reader, name) ->
  Result<(Vec<u8>, SigVerdict)>` does the two kinds of check:
  - post-quantum: `quick_check`;
  - legacy: the signature check of `LegacyProtection`, without a PIN.
- Nothing else in the post-quantum path changes.
- **No `Protection` implementation is weakened:** the checksum-only path
  is separate, and named for what it does.

## Invariants

- **0006 (tampering is detected before use), amended.**  A checksum-only
  read of an unencrypted blob of a post-quantum store detects corruption
  but not forgery.  It happens only on request (`--no-check`,
  `yubiblob_fetch_unencrypted`), and yb says so each time.  Encrypted
  blobs never have this exception.
- **0015 (the management key is checked before every write and fetch),
  amended:** except checksum-only reads, which write nothing and return
  only unencrypted blobs.
- **New: 0019 (unencrypted blobs are readable without any PIN).**

**Regression tests** (CLI tests with the emulator, and libyubiblob tests
in `yb-fido2-emulator`):

- `pq_no_check`: few attempts left, so the hint is shown before any PIN
  is tried and no attempt is used; `--no-check` reads with no touch and
  warns even with `--quiet`; an encrypted blob is refused; a corrupted
  blob exits 4.
- `pq_no_check_after_fido2_reset`: a fresh emulator (no PIN, no
  credential); the hint, then the read.
- `legacy_unencrypted_fetch_needs_no_pin`: a wrong PIV PIN is never
  tried; `--no-check` refuses encrypted blobs.
- libyubiblob: `fetch_unencrypted_without_fido2` (FIDO2 side refusing,
  no touch, encrypted refused, corruption detected), `legacy_kind`
  (legacy, no PIN).

## Open questions

None.  (The option's name, decided 2026-10-17: `--no-check`.  It is not
literal, since the checksum is still checked, but it conveys the risk:
the YubiKey checks nothing.  The warning says exactly what was checked.)

## References

- [spec 0028](0028-post-quantum-protection.md): D5 (checksums), D6
  (seals), D10 (PIN attempts), D11 (management key check).
- [spec 0039](0039-c-api.md): libyubiblob, G7.
- [spec 0046](0046-keepassyb.md): the first user of
  `yubiblob_fetch_unencrypted`.
- Invariants 0002, 0006, 0015.
