<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0023 — Guided Format and YubiKey Health Report

**Status:** ready
**App:** yb
**Implemented in:** <!-- YYYY-MM-DD, fill after implementation -->

## Problem

`yb format` is run rarely: once per YubiKey, plus the occasional
re-format.  Each time, the user has to piece together the right
invocation from the man page, the README, and error messages:

- **First-time setup needs another tool.**  Since spec 0024, `yb format
  --protect` and `yb store` refuse while the PIN or PUK is at its factory
  value, and yb cannot change them: the user has to switch to ykman.
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
slot's key and certificate.  `yb fsck` covers only the store (since spec
0024 it runs on a factory-fresh card, but only prints a one-line
warning).

## Goals

- Bare `yb format`, run from a terminal, starts a **guided flow**.  The
  flow:
  - inspects the YubiKey and explains its state in plain language;
  - proposes a plan with recommended answers;
  - asks for explicit confirmation before anything destructive;
  - runs the plan (spec 0022 sequence);
  - ends with a summary and next steps.
- The guided flow changes a factory PIN and PUK itself, so first-time
  setup needs no other tool, and ends with a YubiKey that `yb store`
  accepts.
- The guided flow always leaves the management key PIN-protected.
- `yb fsck` gains a **YubiKey section** that reports card-level health,
  from the same code the guided flow uses for its inspection.  It runs
  on factory-fresh cards and on cards without a store.
- `yb format` with flags behaves exactly as today, and `--yes` gives
  scripts today's bare `yb format` behavior.
- `yb format --plan` shows what a flag-driven format would do, in the
  guided flow's plan format, and writes nothing to the card.

## Non-goals

- A full-screen TUI.  The flow is line-oriented prompts on stderr, with
  input read from the terminal.
- Guided versions of other commands.
- PIV reset (`ykman piv reset`).  When the card is blocked, the report
  says so and the flow stops.
- Choosing the management key algorithm (spec 0021 non-goal).
- Replacing an already PIN-protected management key with a new one.
  That is spec 0027 (management key rotation).
- Reading the YubiKey's management application (form factor, "PIN
  complexity enforced", FIPS capability).  The card enforces PIN
  complexity itself (§6).
- Localization.
- A `--dry-run` option.  A format plan depends on the card (store, slot
  key, protection), so it cannot be computed without talking to the
  YubiKey; `--plan` (§7) covers the need, and says what it does.
- A separate `yb status` command.  Its role is taken by `yb fsck` (§2).

## Specification

### 1. Card report module

This is a shared `yb-core` module that builds a `CardReport` from
**read-only** APDUs, with no PIN:

| Item | Source |
|---|---|
| Serial, firmware | existing device enumeration |
| PIN, PUK | GET METADATA (`P2 = 80/81`): default flag, retries left/total |
| Management key | spec 0021: algorithm, default flag, touch policy, protection mode (standard / legacy-yb (ambiguous) / PIN-derived / none) |
| Store slot | certificate present?, public key type, subject; GET METADATA on the slot for key presence and origin (generated/imported) where supported |
| Store | presence: none / present / unreadable (object 0 exists but cannot be parsed) |

The store's contents (object count, blobs, integrity verdicts) stay with
the existing `fsck` code in the CLI, which keeps its output unchanged
(§2); the guided flow uses the store listing for its summary and plan.

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
YubiKey 12345678 — firmware 5.4.3
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
- **Unreadable store** (object 0 exists but cannot be parsed): reported
  as `Store: unreadable (<reason>)`.  That is an error.
- **Default credentials** are reported in this section, as warnings.  The
  one-line default-credential warning that `fsck` prints since spec
  0024 is removed; this section replaces it.  `fsck` no longer applies
  the spec 0024 policy at all: its row (`SecretOp::Fsck`) leaves the
  table.
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
  `--plan`.

Global options (`--serial`, `--reader`, `--quiet`, `--allow-defaults`)
do not prevent guided mode.  In guided mode, `--allow-defaults` means
"allow keeping the factory PIN and PUK" (testing only), the same meaning
it has everywhere else: accepting factory credentials.

Detecting whether `-c`, `-k` or `-n` was given requires them to be
optional internally, with their defaults (32, `0x82`, `CN=YBLOB ECCP256`)
applied in code.

Otherwise `yb format` is **flag-driven**, i.e. exactly today's command,
plus the spec 0022 sequence and the §8 hints.

**`--yes`** (new) forces flag-driven mode.  `yb format --yes` does what
bare `yb format` does today: keep the existing key in the slot, 32
objects, no protection.

### 3a. `--protect` means "make sure the key is PIN-protected"

The same rule applies in guided and flag-driven mode:

- **not protected**: the key is replaced by a random key of the card's
  algorithm, stored behind the PIN (spec 0022 §2, B1);
- **already protected**: the key is kept; only the repairs the spec 0022
  resolver finds (legacy flag, interrupted switch) are made.

"Already protected" means: PRINTED tag `89` holds a key that the card
accepts, however the current key was obtained (PRINTED or
`YB_MANAGEMENT_KEY`).  ADMIN DATA flags alone do not decide it; a stale
PRINTED on a card that uses another key counts as not protected.  Format
has verified the PIN by then, so reading PRINTED costs nothing.

This amends spec 0022: until now, flag-driven `--protect` always switched
to a new key.  Replacing a protected key on purpose is spec 0027.

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
   - Otherwise: prompt for the current PIN (unless `YB_PIN` gives it)
     and verify it.  A wrong PIN stops the flow at once, as ykman does:
     the error shows the tries left, and nothing was changed.
   - Firmware < 5.3 cannot report a factory PIN.  If the PIN entered is
     `123456`, it is treated as the factory default.
3. **PUK.**  Factory default: "Your PUK is the factory default and must
   be changed" (a default PUK can reset the PIN, spec 0024 §1).  Prompt
   for the new PUK twice, 6–8 characters, not echoed, and reject
   `12345678`.

   A blocked PUK cannot be changed, and cannot reset the PIN either: it
   is left alone, even if it was the factory value.

   With `--allow-defaults`, steps 2 and 3 do not require a change: the
   factory PIN is used as is, and the summary says that `yb store` will
   refuse until the PIN and PUK are changed (spec 0024), unless it too
   gets `--allow-defaults`.
4. **Store slot key.**  The key/certificate match check runs here, now
   that the PIN is known.
   - No key or certificate: "A new key will be generated." (no
     question).
   - Key matches certificate: "Keep the existing key (recommended), or
     generate a new one? [K/g]".  If the store holds blobs, choosing `g`
     warns that they become unrecoverable.
   - The key does not match its certificate, or the certificate does
     not hold an EC P-256 key: a warning says what is in the slot, then
     "Replace the key in slot 0x82?  It may be used by another
     application.  [y/N]".  Slot 0x82 is a retired key slot that other
     tools can use (e.g. an RSA key for SSH or a VPN).  `N` stops the
     flow: `Nothing was changed on the YubiKey.`, exit 1.  `y` makes
     the plan destructive (§5).
5. **Management key: no question.**  The guided flow always leaves the
   key PIN-protected (the `--protect` behavior of §3a):
   - not protected: it is replaced by a random key of the card's
     algorithm, stored behind the PIN;
   - already protected: it is kept.

   yb finds the current key with the spec 0022 resolver.  It prompts for
   it (hex, not echoed) only when the resolver cannot find it.
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
  3. Replace the management key with a random PIN-protected key (3DES)
  4. ERASE store — destroys 1 blob: bar
  5. Keep existing key in slot 0x82
```

**Confirmation:**

- **Non-destructive plan** (nothing to erase, no existing key replaced):
  `Proceed? [y/N]`.
- **Destructive plan** (blobs erased, an unreadable store erased, or an
  existing key in the slot replaced): the user must type the YubiKey's
  serial number:

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

An explicit "no", or a wrong serial, prints `Nothing was changed on the
YubiKey.` and exits 1.  Nothing is written before the final confirmation,
so Ctrl-C at any prompt also leaves the card unchanged; no signal handler
is installed.

### 6. Execution and summary

1. **PIN change**: CHANGE REFERENCE DATA `00 24 00 80`, old and new PIN
   each padded to 8 bytes with `0xFF`.  ADMIN DATA is not touched: ykman
   (`pivman_change_pin`) only updates it for PIN-derived keys, which yb
   rejects.  `Context` then holds the new PIN.
2. **PUK change**: `00 24 00 81`.

   **PIN complexity** (Yubico firmware 5.7+ feature, card-enforced).
   yb follows ykman 5.9.1 (`_do_change_pin_puk`) and does not
   reimplement the rules; the card is the authority.  Before sending, yb
   checks only the length (6–8 bytes); a FIPS YubiKey rejects anything
   shorter than 8 itself.  `SW 6985` on CHANGE REFERENCE DATA is reported
   through the spec 0025 catalog ("the new PIN/PUK does not meet this
   YubiKey's complexity requirement"), and the flow prompts again.
   Nothing has changed at that point.
3. **The spec 0022 sequence.**  The guided flow applies its own rules
   (steps 2, 3 and 5 of §4) instead of the flag-driven spec 0024 policy,
   as 0024's table foresees.  After steps 1–2, `Context`'s record of the
   factory credentials is refreshed, so that the later steps see the
   current state.  Progress lines and failure messages are spec 0022's.
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

### 7. `--plan`

`yb format --plan [flags]` is flag-driven, in the spirit of `terraform
plan`: it runs the checks, shows the plan, and stops.  It:

1. prints the §2 YubiKey section;
2. runs spec 0022 Phase A in full, exactly as the real command would,
   PIN verification and key/certificate check included.  Phase A writes
   nothing; like any PIN verification, a wrong PIN uses up one try;
3. prints the plan the flags would carry out, built by the same code and
   in the same format as the guided flow's (§5);
4. exits 0, without running Phase B.

If Phase A refuses (e.g. no certificate without `--generate`, or
`--protect` with a factory PIN), `--plan` fails with the same error as
the real command, and exits 1.  So `--plan` is also a check that the
format would go through.

`--plan` has no effect on what the real command does, and the plan can
still fail at run time (e.g. the card is removed).  To see what the
guided flow would do, run bare `yb format` and answer no at the
confirmation.

### 8. Hints in flag-driven mode

- Default-credential errors keep pointing to `ykman piv access
  change-pin` / `change-puk`, which keep the store.  They do **not**
  suggest the guided `yb format`: it erases the store, and a user who
  kept factory credentials with `--allow-defaults` may have blobs.
  Default-credential warnings add "run `yb fsck` for details".
- Error-catalog fixes that point to `ykman piv info` (spec 0025 §2,
  interim wording) point to the `yb fsck` YubiKey section instead.
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
- **`yb fsck`** output gains a leading YubiKey section, which replaces
  the spec 0024 one-line default-credential warning.  It exits 1 on the
  new card-level errors as well.  The store part of the output is
  unchanged.  `yb ls` remains the command meant for machine parsing.
- **`yb format --protect` on an already-protected YubiKey** no longer
  replaces the management key (§3a).  The card ends up protected either
  way.  This goes in the changelog.
- New options only: `yb format --yes` and `--plan`, `yb fsck
  --check-key`.

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
  - key does not match its certificate, and a certificate without a
    P-256 key: answering `N` stops with no writes, `y` requires the
    serial;
  - wrong current PIN: the flow stops with no writes;
  - unreadable store: serial confirmation required;
  - blocked PIN (the flow stops and nothing is written); the virtual
    fixture gains an optional PIN retries field to build it;
  - factory PIN/PUK kept with `--allow-defaults`;
  - PIN change rejected with `6985` (a new virtual fault), then
    accepted;
  - legacy flag `0x01`;
  - firmware 5.7 with AES-192.
- Guided-mode detection: each format flag, `--yes`, and a non-TTY stdin
  select flag-driven mode.
- `--protect` (both modes) on an already-protected card keeps the key;
  on an unprotected card it switches to a random one.
- `--plan` and `fsck` (with or without `--check-key`) make zero write
  APDUs, checked through the backend's write counter.
- `--plan` prints the same plan lines as the guided flow for the same
  card and choices, and exits 1 with the real command's error when
  Phase A refuses.
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
- `--dry-run` replaced by `--plan` (§7), which says that it talks to the
  card.
- Wrong current PIN: stop at once, as ykman does (§4).
- A slot key that may belong to another application: ask before
  replacing it (§4).

## References

- [spec 0013](0013-interactive-device-selection.md) — device picker
- [spec 0017](0017-blob-integrity-signature.md) — blob integrity verdicts
- [spec 0021](0021-firmware-5.7-management-key.md) — management key algorithm, ADMIN DATA
- [spec 0022](0022-format-sequence.md) — format execution order, key/certificate check
- [spec 0024](0024-default-credential-policy.md) — default-credential policy
- [spec 0025](0025-actionable-errors.md) — error message layout
- [spec 0027](0027-management-key-rotation.md) — replacing a protected management key
- ykman 5.9.1 `ykman/_cli/piv.py` (`_do_change_pin_puk`), `yubikit/management.py` (`TAG_PIN_COMPLEXITY`)
