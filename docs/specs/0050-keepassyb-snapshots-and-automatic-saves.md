<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0050 — KeePassYB: Snapshots and Automatic Saves

**Status:** draft
**App:** KeePassYB (`douzebis/keepassyb`, branch `keepassyb`)
**Implemented in:** <!-- YYYY-MM-DD, fill after implementation -->

## Problem

Spec 0047's host test (post-quantum store, KDBX 4 vault):

- **Opening costs four whole-store reads:** the listing, the store kind
  and the read at the unlock dialog (2.9 s), and a listing again at
  unlock (0.96 s), because each libyubiblob call reads the whole store
  and KeePassYB's listing cache lives 3 s.
- **A save costs three:** a listing before, the store, a listing after
  (2.1 s of YubiKey time).
- **Saving is explicit only** (spec 0047 S3): changes wait for Save, or
  for "Save changes?" at lock and exit.  It was chosen because a change
  of view (an expanded group) used to mark the vault modified.  The
  unchanged-content check (a hash of the normalized content, spec 0047
  S2) now tells a real change from a change of view, so automatic saves
  no longer cost useless writes.
- **Another program writing the same vault** (KeePassYB on another
  computer, `yb store`) is overwritten silently.

## Goals

- **One whole-store read to open a vault, none to unlock it:** a
  snapshot session per YubiKey (spec 0049), kept while KeePassYB runs.
- **A save reads the store once** (no listing before or after), and
  costs one touch on a post-quantum store.
- **Automatic saves:** a vault on a YubiKey is saved by itself, after a
  quiet delay, when its normalized content changed; never for a change
  of view.
- **A vault changed on the YubiKey by someone else is never overwritten
  silently:** the user chooses.
- File databases: unchanged.

## Non-goals

- **Saving after the window has closed** (spec 0047).
- **Merging without asking.**
- **Refreshing by polling:** no timer reads the YubiKey.

## Specification

### S1. A snapshot session per YubiKey

- **`DeviceStorage`'s backend** keeps one libyubiblob session per serial,
  opened with `YUBIBLOB_OPEN_SNAPSHOT`, and closes it when the YubiKey
  goes away (`YUBIBLOB_ERR_NO_DEVICE`, `YUBIBLOB_ERR_CARD_REMOVED`) or at
  exit; the next operation opens a new one.
- **The listing cache, the store-kind cache and their 3 s lifetime**
  (spec 0047 S2) are removed: the snapshot answers.
- **Refresh points** (one whole-store read each):
  - the "Open from YubiKey" dialog, when it opens;
  - the unlock dialog of a vault, when it opens (the snapshot then
    serves the header read, the listing, the store kind, the password
    status and the read at unlock);
  - after `YUBIBLOB_ERR_CHANGED` or `YUBIBLOB_ERR_NOT_FOUND`.
  No refresh at unlock: the snapshot is seconds old, and a change since
  is caught at the first save (S3).
- **The log** (spec 0047 S1) says, for each operation, whether it read
  the card or answered from the snapshot.

### S2. Automatic saves

- **KeePassXC's settings apply again** to vaults on a YubiKey (spec
  0047 S3's " (not for databases on a YubiKey)" is removed):
  - "Automatically save after every change": on (KeePassXC's default),
    a vault on a YubiKey is saved after a quiet delay;
  - "Automatically save when locking or exiting": on (KeePassXC's
    default), lock and exit save without asking; off, they ask "Save
    changes?" as in spec 0047.
- **The quiet delay:** the database's own autosave delay, but at least
  `D` seconds after the last change for a vault on a YubiKey (see Open
  questions); each change restarts it.  A burst of edits makes one save.
- **When the delay ends:** the normalized-content hash (spec 0047) is
  compared with the last read or saved one:
  - equal: the vault is marked clean, nothing is written, the log says
    so;
  - different: the vault is saved (S3).
- **Never during an unlock, a lock, or a dialog of KeePassYB's own** (a
  PIN prompt already open, a save failure dialog): the save waits for
  them.

### S3. Saving

- **The store asks to fail on a change:** `YUBIBLOB_STORE_IF_UNCHANGED`
  (spec 0049 S4).
- **PIN and touch:** the FIDO2 PIN (or PIV PIN) is asked at the first
  save of the unlocked session and kept until lock (spec 0047); a
  post-quantum store asks one touch per save, with the progress dialog
  (spec 0047 S4).
- **`YUBIBLOB_ERR_CHANGED`:** "Passwords.kdbx was changed on the YubiKey
  since it was opened."
  - **Merge:** read the YubiKey's version (the master key is the same,
    or the user is asked for it), merge it into the open vault
    (KeePassXC's merge, as for a file changed on disk), then save;
  - **Overwrite:** save without the flag;
  - **Save as a file**;
  - **Cancel:** the vault stays open and modified.
- **A failed automatic save** (PIN prompt cancelled, touch timeout,
  YubiKey absent): the vault stays modified, the database's message bar
  says why, with a Retry button.  No new attempt until the next change,
  an explicit Save, a lock or an exit, so a refused touch never becomes a
  loop of prompts.
- **A failed save at lock or exit:** spec 0047's dialog (Retry, Save as
  a file, Discard confirmed, Cancel).

### S4. Expected YubiKey interactions

Post-quantum store, KDBX 4 vault, YubiKey 5, 32 objects:

| Action | Card reads | PIN | Touch |
|---|---|---|---|
| Open from YubiKey dialog | 1 whole store (about 1 s) | no | no |
| Unlock dialog, then unlock | 1 whole store | no | no |
| A change of view | 0 | no | no |
| Edits, then the quiet delay | 1 whole store + the writes | first save only | 1 |
| Lock or exit, nothing changed | 0 | no | no |
| Lock or exit, unsaved change | 1 whole store + the writes | if not yet asked | 1 |

A legacy store: the same, with the PIV PIN and no touch.

## Tests

In `tests/TestDeviceStorage.cpp` (the fake backend gains snapshot
semantics: a refresh counter, and a way to change the store from
"another program"):

- `testOneReadToOpen`: the unlock dialog and unlock cost one refresh.
- `testSaveIsOneStoreCall`: a save is one store call, no listing or
  refresh around it.
- `testAutoSaveAfterQuietDelay`: three changes in a burst, one save
  after the delay.
- `testNoAutoSaveForViewChanges`: expand a group, select another; the
  delay ends, nothing is written, the vault is clean.
- `testChangedOnTheYubiKey`: another program stores the vault meanwhile;
  the save reports it, Overwrite writes, Cancel keeps it modified.
- `testFailedAutoSaveDoesNotRetry`: a refused touch; no second prompt
  until the next change.
- `testLockSavesWithoutAsking` and `testLockAsksWhenAutoSaveOnExitIsOff`.

## Open questions

- **Q1: `D`, the minimum quiet delay.**  Proposal: 10 s.  Shorter saves
  sooner but may ask for a touch in the middle of typing; longer leaves
  more unsaved work if the computer crashes.
- **Q2: the first automatic save asks for the PIN** in the middle of
  editing.  Accept (proposal: it is once per unlock), or ask the PIN at
  the first change rather than at the first save?
- **Q3: Merge's master key:** KeePassXC's merge of a file changed on
  disk reuses the open database's key; do the same, and ask only if it
  fails?  Proposal: yes.

## References

- [spec 0047](0047-keepassyb-and-a-slow-yubikey.md): the log, the
  progress dialog, the normalized-content check, explicit saves (S3,
  replaced here by S2).
- [spec 0048](0048-one-writer-at-a-time.md): the lock.
- [spec 0049](0049-snapshots.md): snapshots,
  `YUBIBLOB_STORE_IF_UNCHANGED`, `YUBIBLOB_ERR_CHANGED`.
- [spec 0046](0046-keepassyb.md): KeePassYB.
