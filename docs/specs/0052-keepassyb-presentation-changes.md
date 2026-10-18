<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0052 — KeePassYB: Presentation Changes Wait, but Are Saved

**Status:** implemented
**App:** KeePassYB (`douzebis/keepassyb`, branch `keepassyb`)
**Implemented in:** 2026-10-18

## Problem

KeePassXC calls some changes "non-data": expanding or collapsing a group,
moving an entry up or down in its group (`Group::groupNonDataChange`).
With a file, KeePassXC writes them along with the next save, and at lock,
close and exit ("Automatically save non-data changes when locking", on
by default).

KeePassYB never writes them by themselves (spec 0047 S2, spec 0050 S2):
not by an automatic save, not by Save, not at lock, close or exit.  Its
aim was to spare the YubiKey's writes, but the result is that whether a
presentation change reaches the YubiKey depends on an unrelated action:
a later data change carries it, otherwise it is lost.

## Goals

- **Presentation changes wait:** the automatic save (spec 0051 S1) still
  writes only when the data changed.
- **They are saved in the regular way,** as KeePassXC does for a file:
  along with the next save, and at lock, close and exit.
- **Determinism:** a presentation change reaches the YubiKey at the next
  of these points, whatever else happens meanwhile.  A data change
  saved before it carries it earlier, as for a file; only its timing
  depends on other actions, not whether it is saved.

## Non-goals

- **What KeePassXC does not store in the database** (the selected group,
  the entry list's columns and sorting): unchanged, it lives in
  KeePassXC's own settings.
- **File databases:** unchanged.
- **Access times, usage counts and modification times** stay out of
  both comparisons (spec 0047 S2): never worth a write by themselves,
  they go along with the next save.

## Specification

### S1. What a presentation change is

- **The data** is the vault's content as compared by spec 0047 S2: the
  XML without the random padding, the custom data's last-modified stamp,
  the view state (`IsExpanded`, `LastSelectedGroup`,
  `LastTopVisibleGroup`), access times and counts, and modification
  times.
- **The presentation** is the view state and the order of entries in a
  group: the data's hash ignores that order.
- KeePassYB keeps two hashes, as last read or saved: the data's, and a
  full one (the data and the presentation; without the random padding
  and the custom data's last-modified stamp, which change at every save,
  nor access times and counts and modification times, which a
  presentation change also stamps).  A **presentation change** is pending
  when the data's hash is unchanged and the full hash differs.  Changing
  a group back as it was leaves nothing pending.

### S2. When it is written

| Trigger | Data changed | Presentation only |
|---|---|---|
| Automatic save (spec 0051 S1) | written | not written, still pending |
| Save (Ctrl+S, the menu, the toolbar), when enabled | written | written |
| Lock, close, exit | written (spec 0050 S2) | written, as KeePassXC's "Automatically save non-data changes when locking" says |

- **Save is enabled** only when the vault is marked modified, as in
  KeePassXC: a presentation change alone does not enable it.  When
  enabled (a change of view marks the vault modified, its data unchanged),
  it writes the presentation too.
- **At lock, close and exit,** a presentation-only save follows
  KeePassXC's setting "Automatically save non-data changes when
  locking" (on by default): off, nothing is written, as for a file.
- **It is a regular save:** the PIN is asked if not known yet, and a
  post-quantum store asks for a touch.
- **A failure** at lock, close or exit (PIN prompt cancelled, touch
  refused, YubiKey removed, the vault changed on the YubiKey by another
  program) does not stop the lock, the close or the exit, and asks
  nothing: nothing is written, and the presentation is lost, without
  consequence.  A failed Save is any failed save (spec 0050 S3).

## Tests

`tests/TestDeviceAutoSave.cpp`:

- `testViewStateGoesAlongWithAChange`: a group expanded, then a data
  change: the automatic save writes both.
- `testAutoSaveSkipsPresentation`: a group expanded, an entry moved:
  nothing written by the automatic save.
- `testSaveWritesPresentation`: a group expanded, the vault marked
  modified, then Save: written; reread, the group is expanded.
- `testLockWritesPresentation`: a group expanded, then lock: written,
  without a question; with the setting off, nothing written.
- `testPresentationRevertedIsNotWritten`: a group expanded then
  collapsed back: lock writes nothing.
- `testPresentationSaveFailureDoesNotStopLock`: the touch refused: the
  lock goes on, nothing asked.

## Open questions

None.  (2026-10-18: lock and close count as exit; moving an entry up or
down is a presentation change; Save is enabled as in KeePassXC.)

## References

- [spec 0047](0047-keepassyb-and-a-slow-yubikey.md) S2: the data
  comparison.
- [spec 0050](0050-keepassyb-snapshots-and-automatic-saves.md) S2, S3:
  automatic saves, conflicts.
- [spec 0051](0051-keepassyb-prompt-saves-and-smaller-vaults.md) S1: the
  quiet delay.
