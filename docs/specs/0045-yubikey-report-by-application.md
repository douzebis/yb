<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0045 — The YubiKey Report, by Application

**Status:** draft
**App:** yb, yb-core (`report.rs`, `fsck`)
**Implemented in:** <!-- YYYY-MM-DD, fill after implementation -->

## Problem

`yb fsck` on a post-quantum store today:

```
YubiKey 32283437 — firmware 5.7.1
  PIN              ok (3/3 tries left)
  PUK              ok (3/3 tries left)
  Management key   AES-192, kept on the YubiKey, unlocked by the PIN

Store: post-quantum, 32 objects, age 1
Credential: 64-byte ID; management key: AES-192
Blobs: 1 stored, 31 objects free

  bar                            CHECKSUM OK

Integrity: 1 checksum OK, 0 corrupted (checksums need no PIN; seals are checked by fetch, and by --seals)
FIDO2 PIN:
Touch your YubiKey…
FIDO2: the store's credential answers; the management key matches
```

- **The management key appears twice,** with no link between the two
  lines.  It is the PIV application's key, kept in PRINTED, and the
  store also holds a copy wrapped by FIDO2.
- **"PIN" and "PUK" don't say which application they belong to,** on a
  YubiKey where both applications matter.
- **The FIDO2 PIN's state is never shown:** whether it is set, and the
  attempts left, which yb can read without using one.
- **The order mixes things:** a FIDO2 prompt and a touch come after the
  integrity summary, without a heading.
- **What protects the store is not said:** PIV or FIDO2.

## Goals

- G1. **One structured report:**
  - the YubiKey;
  - then each application, with what belongs to it;
  - then the store, with what protects it;
  - then the blobs and the integrity summary.
  Each fact appears once.
- G2. **Different by store kind:**
  - a legacy store shows the PIV application in full, and FIDO2 only as
    "not used";
  - a post-quantum store shows both applications, and says which role
    each plays.
- G3. **The FIDO2 PIN state** (set or not, attempts left) is shown
  without using an attempt.
- G4. **`yb fsck` asks for no PIN and no touch by default,** on both
  kinds of store.
  - The checks that need the FIDO2 PIN and touches are the credential,
    the management key and the seals.  They run with `--seals`, under
    their own heading.
  - The report says what was not checked, and how to check it.
- G5. **The same items as today,** with the same severity rules
  (warning, ERROR) and hints.
- G6. **The other commands' short card summaries** (e.g. `yb ls -l`'s
  header) use the same vocabulary.

## Non-goals

- Changing what is checked, except moving the FIDO2 checks under
  `--seals` (G4).
- Machine-readable output (JSON): later, in its own spec.
- `--nvm`'s breakdown: unchanged, after the report.

## Specification

### S1. Legacy store

```
YubiKey 32283437 — firmware 5.7.1

PIV application — protects this store
  PIN              ok (3/3 tries left)
  PUK              ok (3/3 tries left)
  Management key   AES-192, kept on the YubiKey (PRINTED), unlocked by the PIV PIN
  Store key        slot 0x82: ECC P-256, certificate "CN=yb"

FIDO2 application — not used by this store

Store: legacy, 16 objects, age 12
  Blobs            3 stored, 10 objects free (~5,120 bytes)

  notes.txt                      VERIFIED
  vault.kdbx                     VERIFIED
  old.bin                        UNSIGNED

Integrity: 2 verified, 1 unsigned, 0 corrupted (signatures need no PIN)
```

### S2. Post-quantum store, default (no PIN, no touch)

```
YubiKey 32283437 — firmware 5.7.1

PIV application — holds the store's objects
  PIN              ok (3/3 tries left) — not used by this store
  PUK              ok (3/3 tries left)
  Management key   AES-192, kept on the YubiKey (PRINTED), unlocked by the PIV PIN

FIDO2 application — protects this store
  PIN              set, 8 tries left
  Credential       the store's: 64-byte ID, not checked (needs the FIDO2 PIN)

Store: post-quantum, 32 objects, age 1
  Management key   a copy, wrapped by FIDO2 (AES-192); not checked against the card
  Blobs            1 stored, 31 objects free

  bar                            CHECKSUM OK

Integrity: 1 checksum OK, 0 corrupted (checksums need no PIN)
Not checked: the credential, the management key, the seals —
  `yb fsck --seals` checks them (FIDO2 PIN, one touch, then one per blob)
```

**Rules:**

- **The PIV PIN's line says "not used by this store"** when the store is
  post-quantum.  It is still shown, because the PIV PIN guards the
  PRINTED copy of the management key.
- **The PRINTED copy:** if the management key is not kept on the
  YubiKey, the line says "not stored on the YubiKey", as today.
- **The FIDO2 PIN line:**

  | State | Shown as |
  |---|---|
  | normal | `set, N tries left` |
  | 3 tries or fewer | `warning: set, N tries left` + the D10 hint |
  | blocked | `ERROR: blocked (a FIDO2 reset clears it, and destroys this store's encrypted blobs)` + the spec 0044 hint if any blob is unencrypted |
  | not set | `ERROR: not set (FIDO2 reset?)` |

- **When the FIDO2 side cannot be reached** (permissions, FIDO
  application disabled), the FIDO2 section shows
  `ERROR: not reachable (…)`, with the udev hint, and the rest of the
  report continues.

### S3. Post-quantum store, `--seals`

The FIDO2 PIN is asked, then one touch for the management key, then one
per blob.  The "Not checked" line is replaced by:

```
Checked with the FIDO2 PIN:
  Credential       answers
  Management key   matches the card
  bar              seal OK
```

- **Failures** are shown on their own line, as ERROR: no credential,
  management key mismatch (D11), a seal failure.  They give exit status
  4, as today.
- **The prompts** ("FIDO2 PIN:", "Touch your YubiKey…") go to standard
  error, before this section is printed.  The section is printed whole
  once the checks are done, so prompts never interleave with the report.

### S4. Other commands

- `yb ls -l` and the other short summaries name the application in the
  same words: "PIV PIN", "FIDO2 PIN", "management key (PIV)".
- `CardReport` gains a FIDO2 section (`Fido2Report { pin:
  Option<FidoPinState>, reachable: Result<(), String> }`) filled without
  a PIN.
- The renderer takes the store kind, so it can tell each application's
  role.

## Invariants

None new.  0002 (reads never write) and 0017 (the FIDO2 PIN is not tried
with few attempts left) hold: the default `fsck` now uses no PIN at all.

**Regression tests:**

- the existing `fsck` CLI tests, updated;
- `fsck_post_quantum_asks_nothing_by_default`: the scripted prompter
  gets no question, and the emulator counts no touch;
- `fsck_shows_fido2_pin_state`: normal, few, blocked;
- `fsck_seals_checks_credential_and_key`.

## Open questions

None.  (Decided 2026-10-17: the management-key check moves under
`--seals` with the other FIDO2 checks.  A plain `yb fsck` no longer
detects a PIV reset; every fetch and store still does (D11).)

## References

- [spec 0028](0028-post-quantum-protection.md): D10, D11, "Commands"
  (`fsck --seals`).
- [spec 0044](0044-reading-unencrypted-blobs-without-the-pin.md): the
  hint for unencrypted blobs.
- `yb-core/src/report.rs`, `yb/src/cli/fsck.rs`.
