<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0023 — Guided Format and YubiKey Health Report

**Status:** draft
**App:** yb
**Implemented in:** <!-- YYYY-MM-DD, fill after implementation -->

## Problem

`yb format` is run rarely: once per YubiKey, plus the occasional
re-format.  Each time, the user has to piece together the right
invocation from the man page, the README, and error messages:

- **Default credentials block format without saying what to do.**  yb
  refuses to run while any factory-default credential is in place.  But
  `--protect` needs the factory management key, so the documented
  first-time command `yb format --generate --protect` fails unless the
  user also knows to add `--allow-defaults`.  Changing the PIN and PUK
  means switching to ykman.
- **`--generate` is dangerous and easy to get wrong.**  Leave it out on
  a fresh key and format fails: no certificate.  Add it on a key in use
  and the existing slot-0x82 key, and every blob encrypted to it, is
  lost.
- **Destruction happens without warning.**  Nothing shows what is
  already on the card (store, blobs, key, protection mode) before it is
  destroyed, and nothing asks for confirmation.
- **Success doesn't say what comes next.**  There is no summary and no
  pointer to the next step.

Separately, no yb command reports the state of the YubiKey itself: PIN
and PUK status, management key algorithm and protection, and the store
slot's key and certificate.  `yb fsck` covers only the store.  On a
factory-fresh card it cannot even run, because the default-credential
check refuses first.

## Goals

- Bare `yb format`, run from a terminal, starts a **guided flow**.  The
  flow:
  - inspects the YubiKey and explains its state in plain language;
  - proposes a plan with recommended answers;
  - asks for explicit confirmation before anything destructive;
  - runs the plan (spec 0022 sequence);
  - ends with a summary and next steps.
- The guided flow can change a default PIN and PUK itself, so first-time
  setup needs neither ykman nor `--allow-defaults`.
- `yb fsck` gains a **YubiKey section** that reports card-level health,
  from the same code the guided flow uses for its inspection.  It runs
  on factory-fresh cards and on cards without a store.
- `yb format` with flags behaves exactly as today, and `--yes` gives
  scripts today's bare `yb format` behavior.
- `yb format --dry-run` shows what a flag-driven format would do,
  without touching the card.

## Non-goals

- A full-screen TUI.  The flow is line-oriented prompts on stderr, with
  input read from the terminal.
- Guided versions of other commands.
- PIV reset (`ykman piv reset`).  When the card is blocked, the report
  says so and the flow stops.
- Choosing the management key algorithm (spec 0021 non-goal).
- Localization.
- A separate `yb status` command.  Its role is taken by `yb fsck` (§2).

## Specification

### 1. Card report module

This is a shared `yb-core` module that builds a `CardReport` from
**read-only** APDUs, with no PIN:

| Item | Source |
|---|---|
| Serial, firmware, form factor | existing device enumeration |
| PIN, PUK | GET METADATA (`P2 = 80/81`): default flag, retries left/total |
| Management key | spec 0021: algorithm, default flag, touch policy, protection mode (standard / legacy-yb (ambiguous) / PIN-derived / none) |
| Store slot | certificate present?, public key type, subject; GET METADATA on the slot for key presence and origin (generated/imported) where supported |
| Store | presence, object count, key slot, blobs with integrity verdicts (the existing `fsck` logic) |

Optionally, with the PIN, it adds a **key/certificate match** check
(spec 0022 Phase A step 5).

Every item has a severity:

- **ok**;
- **warning**: default PIN or PUK, default management key, legacy
  ADMIN DATA flag, touch policy "always";
- **error**: blocked PIN, PIN-derived mode, key/certificate mismatch,
  certificate present without a P-256 key, CORRUPTED blobs.

On firmware < 5.3 (no GET METADATA), the PIN, PUK and management key
items show `unknown (firmware < 5.3)`.

### 2. `yb fsck` YubiKey section

`yb fsck` prints the YubiKey section first, then the existing store
output unchanged:

```
YubiKey 12345678 — YubiKey 5 NFC, firmware 5.4.3
  PIN              ok (3/3 tries left)
  PUK              ok (3/3 tries left)
  Management key   3DES, PIN-protected
  Slot 0x82        EC P-256, generated on card, certificate CN=YBLOB ECCP256
  Key/certificate  not checked (use --check-key)

Store: 32 objects, slot 0x82, age 2
Blobs: 1 stored, 31 objects free (~188 bytes used by store)

  bar                            CORRUPTED

Integrity: 0 verified, 0 unverified, 1 corrupted
```

- **`--check-key`** (new): asks for the PIN and runs the key/certificate
  match check.  A mismatch is an error.
- **No store**: the store part is replaced with `Store: none — run `yb
  format` to create one`.  That is not an error.
- **Default credentials**: `fsck` no longer refuses on them.  It reports
  them as warnings, per the policy in spec 0024.
- **Exit status**:
  - 1 if the report has any error, i.e. CORRUPTED blobs as today, plus
    the new card-level errors;
  - 0 otherwise.

  Warnings never change the exit status.
- `--verbose` and `--nvm` are unchanged.

### 3. When `yb format` is guided

Guided mode applies when **all** of these hold:

- stdin and stderr are both terminals;
- no format-specific flag is given: `-g/--generate`, `--protect`,
  `-c/--object-count`, `-k/--key-slot`, `-n/--subject`, `--yes`,
  `--dry-run`.

Global options (`--serial`, `--reader`, `--quiet`) select the device or
reduce output, and do not prevent guided mode.  `--allow-defaults` is
accepted and ignored in guided mode; the flow handles defaults itself.

Otherwise `yb format` is **flag-driven**, i.e. exactly today's command,
plus the spec 0022 sequence and the §8 hints.

**`--yes`** (new) forces flag-driven mode.  `yb format --yes` does what
bare `yb format` does today: keep the existing key in the slot, 32
objects, no protection.

### 4. Guided flow — questions

Each question shows the recommended answer as the default.  Questions
whose answer is already settled by the card state are skipped.

1. **Report**: print the YubiKey section (§2) and a store summary.  If
   the report shows a blocking error, explain it and stop without
   asking anything:
   - blocked PIN with the PUK available: "unblock with `ykman piv access
     unblock-pin`";
   - blocked PIN and PUK: "a PIV reset is required";
   - PIN-derived mode: explain that yb does not support it.
2. **PIN.**
   - Factory default: "Your PIN is the factory default and must be
     changed."  Prompt for the new PIN twice, 6–8 characters, not
     echoed, and reject `123456`.
   - Otherwise: prompt for the current PIN.
3. **PUK.**  If it is the factory default: "Change it now? [Y/n]".
   Declining carries on with a warning.
4. **Store slot key.**  The key/certificate match check runs here, now
   that the PIN is known.
   - No key or certificate: "A new key will be generated." (no
     question).
   - Key matches certificate: "Keep the existing key (recommended), or
     generate a new one? [K/g]".  If the store holds blobs, choosing `g`
     warns that they become unrecoverable.
   - Mismatch: "The key in slot 0x82 does not match its certificate; a
     new key will be generated."
5. **Management key.**
   - Not protected: "Protect the management key with your PIN?
     (recommended) [Y/n]".  The explanation says that afterwards only
     the PIN is needed.
   - Already protected: no question.
   - Not default, not protected: prompt for it (hex, not echoed).
   - Factory default, and the user declines protection: refuse, and
     explain that yb will not operate with the factory management key.
6. **Object count.**  Default 32, with one sentence on the NVM
   trade-off.

### 5. Plan and confirmation

The plan is printed as numbered steps in execution order: PIN/PUK
changes first, then the spec 0022 sequence.  Every destructive step is
marked:

```
Plan for YubiKey 12345678:
  1. Change PIN
  2. Change PUK
  3. Replace management key with a random PIN-protected key (3DES)
  4. ERASE store — destroys 1 blob: bar
  5. Keep existing key in slot 0x82
```

**Confirmation:**

- **Non-destructive plan** (nothing to erase, no existing key replaced):
  `Proceed? [y/N]`.
- **Destructive plan** (blobs erased, or an existing key in the slot
  replaced): the user must type the YubiKey's serial number:

  ```
  This will destroy 1 blob (bar) on YubiKey 12345678.
  Type the serial number of this YubiKey to confirm: _
  ```

  The serial is shown on screen, so this is not a secret; it is not a
  security check.  It serves two purposes:
  - it stops a reflexive "y";
  - it makes the user look at which YubiKey is about to be wiped, which
    matters when several are plugged in.  The serial is also printed on
    the key's casing.

  Surrounding whitespace is ignored.  Any other input aborts.

An abort, including Ctrl-C at any prompt, prints `Nothing was changed on
the YubiKey.` and exits 1.

### 6. Execution and summary

1. **PIN change**: CHANGE REFERENCE DATA `00 24 00 80`, old and new PIN
   each padded to 8 bytes with `0xFF`.  If ADMIN DATA exists, update its
   pivman PIN timestamp (tag `0x83`) as ykman does.
2. **PUK change**: `00 24 00 81`.

   **PIN complexity** (Yubico firmware 5.7+ feature, card-enforced).
   yb follows ykman 5.9.1 (`_do_change_pin_puk`):
   - It does not reimplement the complexity rules; the card is the
     authority.
   - It reads the "PIN complexity enforced" flag from the management
     application's device info (tag `0x16`), where available.  The flag
     is shown in the §2 report and in the PIN prompt ("this YubiKey
     enforces PIN complexity").
   - Before sending, it checks only the length: 6–8, or exactly 8 on
     FIPS-capable PIV.  With complexity enforced, the length is counted
     in characters; otherwise in bytes.
   - `SW 6985` on CHANGE REFERENCE DATA is reported as "the new PIN/PUK
     does not meet this YubiKey's complexity requirement", and the flow
     prompts again.  Nothing has changed at that point.
3. **The spec 0022 sequence**, with the default-credential check
   satisfied: the PIN was just changed, and the factory management key
   is allowed because step 3 of the plan replaces it.  Progress lines
   and failure messages are spec 0022's.
   - A PIN or PUK change followed by a later failure is **not** rolled
     back.  The failure message says the PIN/PUK have already been
     changed.

Summary:

```
Done.  YubiKey 12345678 is ready.
  Store: 32 objects, empty.  Key: slot 0x82 (kept).
  Management key: PIN-protected (3DES).

Next:  echo "s3cr3t" | yb store -n my-secret
       yb ls -l
       yb fsck          (health check)
```

When the management key was replaced, the summary says how to read it
back if ever needed (`yubico-piv-tool -a verify-pin -a read-object --id
0x5fc109`).  It never prints the key.

### 7. `--dry-run`

`yb format --dry-run [flags]` is flag-driven.  It:

1. prints the §2 YubiKey section;
2. prints the plan the flags would carry out (same format as §5);
3. exits 0.

It prompts for nothing and makes no write APDUs.  Steps that depend on
the PIN are marked `(checked at run time)`.  To see what the guided flow
would do, run bare `yb format` and answer no at the confirmation.

### 8. Hints in flag-driven mode

- Default-credential errors from any command add: `Tip: run `yb format`
  in a terminal for guided setup.`  Default-credential warnings add
  "run `yb fsck` for details".  Both replace the interim wording of spec
  0024 §2, which cannot point to features this spec introduces.
- When an existing store is about to be erased, the blobs are listed as
  specified in spec 0022 §1 step 6 (printed even with `--quiet`).  There
  is no prompt, so scripts and `yb self-test` are unaffected.

### 9. Backward compatibility

**CLI**

- `yb format` with any format flag: unchanged, apart from the spec 0022
  ordering and the §8 hints.
- **Bare `yb format`** changes when stdin and stderr are both terminals:
  it now starts the guided flow instead of formatting immediately.  A
  script that runs bare `yb format` from an interactive shell will now
  prompt.  Use `yb format --yes` for the old behavior.  This goes in the
  changelog and the man page.  Without a terminal (CI, pipes, cron),
  behavior is unchanged.
- **`yb fsck`** output gains a leading YubiKey section.  It exits 1 on
  the new card-level errors as well.  It no longer refuses to run on
  default credentials.  The store part of the output is unchanged.
  `yb ls` remains the command meant for machine parsing.

**Card**

- The card content produced is the same as with the equivalent flags
  (spec 0022 sequence, spec 0021 metadata).
- PIN/PUK changes use the standard PIV APDUs, and the pivman timestamp
  follows ykman's layout, so ykman and older yb versions are unaffected.
- Spec 0021 §6 applies.

### 10. Tests

- Drive the guided flow through an injectable prompt/terminal trait
  rather than a real TTY, against the virtual PIV backend, for these
  cards:
  - factory-fresh;
  - set up, keep the key;
  - set up, generate a new key (serial confirmation required: a wrong
    serial aborts with no writes);
  - key does not match its certificate;
  - blocked PIN (the flow stops and nothing is written);
  - legacy flag `0x01`;
  - firmware 5.7 with AES-192.
- Guided-mode detection: each format flag, `--yes`, and a non-TTY stdin
  select flag-driven mode.
- `--dry-run` and `fsck` (without `--check-key`) make zero write APDUs,
  checked through the backend's write counter.
- `fsck`:
  - runs on a factory-default card;
  - runs on a card without a store;
  - exits 1 on a key/certificate mismatch with `--check-key`;
  - the store output is byte-identical to today's for an existing
    fixture.

## Open questions

None.  Resolved:

- PIN complexity: follow ykman and let the card enforce it (§6).
- Default credentials in other commands: covered by spec 0024.

## References

- [spec 0013](0013-interactive-device-selection.md) — device picker
- [spec 0017](0017-blob-integrity-signature.md) — blob integrity verdicts
- [spec 0021](0021-firmware-5.7-management-key.md) — management key algorithm, ADMIN DATA
- [spec 0022](0022-format-sequence.md) — format execution order, key/certificate check
- [spec 0024](0024-default-credential-policy.md) — default-credential policy
- [spec 0025](0025-actionable-errors.md) — error message layout
- ykman 5.9.1 `ykman/_cli/piv.py` (`_do_change_pin_puk`), `yubikit/management.py` (`TAG_PIN_COMPLEXITY`)
