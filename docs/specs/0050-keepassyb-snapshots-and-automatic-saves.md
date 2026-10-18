<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0050 — KeePassYB: Snapshots and Automatic Saves

**Status:** implemented
**App:** KeePassYB (`douzebis/keepassyb`, branch `keepassyb`)
**Implemented in:** 2026-10-18

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
- **A vault changed on the YubiKey since this database read or saved
  it:** nothing is written, and KeePassXC's own question for a file
  changed on disk follows ("was modified externally"):
  - **Merge all changes then save:** the YubiKey's version is read (with
    the same master key), merged with the open vault, and saved;
  - **Overwrite:** saved without the check;
  - **Discard unsaved changes:** the YubiKey's version is loaded;
  - **Cancel:** the vault stays open and modified.
- **How a change is found,** as for a file: the vault as KeePassYB last
  saw it (the snapshot) must still be the version this database is based
  on (the hash of its first block, KeePassXC's `fileBlockHash`); and the
  YubiKey must not have changed since the snapshot
  (`YUBIBLOB_STORE_IF_UNCHANGED`).  The first check is needed because a
  refresh (another dialog opening, a refused save) brings another
  program's change into the snapshot, after which `IF_UNCHANGED` alone
  would no longer see it.
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

The fake backend (`tests/mock/FakeDeviceBackend.h`) is a snapshot
session: questions answer from the store as last read, a write reads the
card again and honors `IF_UNCHANGED`, and a test changes the card behind
the session's back as another program would.

- `tests/TestDeviceStorage.cpp`:
  - `testOneReadToOpen`: the unlock dialog's refresh serves its
    questions, the header read and the unlock: one read;
  - `testSnapshotUntilRefresh`: another program's vault is seen after a
    refresh; a vault missing from the snapshot is looked for again;
  - `testSaveIsOneStoreCall`;
  - `testChangedOnTheYubiKey`: nothing written, the question asked,
    Overwrite writes;
  - `testChangeSeenByARefreshIsStillAConflict`.
- `tests/TestDeviceAutoSave.cpp` (a `DatabaseWidget` on the fake
  YubiKey; the quiet delay's slot is called rather than waited for):
  - `testAutoSaveAfterQuietDelay`: three changes, one save;
  - `testNoAutoSaveForViewChanges`;
  - `testFailedAutoSaveDoesNotRetry`;
  - `testLockSavesWithoutAsking`, `testLockAsksWhenAutoSaveOnExitIsOff`;
  - `testChangedOnTheYubiKeyAsks`: the automatic save asks; Overwrite
    saves.

## Implementation notes (2026-10-18)

- `DeviceStorage`'s listing cache, store-kind cache and their lifetime
  are gone; the backend keeps a libyubiblob snapshot session per serial,
  closed when the YubiKey is gone (`NoDevice`, `CardRemoved`, `NoStore`,
  `SeveralDevices`), and `DeviceStorage::refresh` reads it again.
- The refresh points: the unlock dialog (`DatabaseOpenWidget::load`), the
  "Open from YubiKey" dialog, and "Save as" (`chooseSaveLocation`); a
  read that does not find its vault refreshes once and looks again.
- Automatic saves: `DatabaseWidget::onDeviceSaveDelayTimeout`, started by
  each change for at least 10 s (the database's own autosave delay, if
  longer); postponed while a modal dialog is open or a reload or a save
  runs.  A failed automatic save puts Retry on its message and waits for
  the next change, Save, lock or exit.
- The conflict signal is sent once the save is over: sent from inside
  the save, it reached KeePassXC's reload while the save was still in
  progress, which ignored it.
- KeePassYB needs libyubiblob 0.4.0 (interface version 1).

## Open questions

None.  (Decided by implementing the proposals, 2026-10-18: Q1, 10 s; Q2,
the PIN is asked at the first save, once per unlock; Q3, the merge
reuses the open vault's master key, as KeePassXC's reload does.)

## References

- [spec 0047](0047-keepassyb-and-a-slow-yubikey.md): the log, the
  progress dialog, the normalized-content check, explicit saves (S3,
  replaced here by S2).
- [spec 0048](0048-one-writer-at-a-time.md): the lock.
- [spec 0049](0049-snapshots.md): snapshots,
  `YUBIBLOB_STORE_IF_UNCHANGED`, `YUBIBLOB_ERR_CHANGED`.
- [spec 0046](0046-keepassyb.md): KeePassYB.
