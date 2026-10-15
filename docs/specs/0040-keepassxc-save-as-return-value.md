<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0040 — KeePassXC: Save As Reports Failure After a Successful Save

**Status:** draft
**App:** keepassxc (upstream fix, outside yb)
**Implemented in:** <!-- YYYY-MM-DD, fill after implementation -->

A reminder to report, and offer a fix for, a bug found in KeePassXC while
adding "save on the YubiKey" to the fork (spec 0030).  Not a yb change.

## Problem

`DatabaseWidget::saveAs()` (`src/gui/DatabaseWidget.cpp`) never sets its
result: `bool ok = false;` is returned unchanged, so Save As reports a
failure even when the database was written.  Present in release 2.7.10
and on `develop` (checked 2026-10-15):

```cpp
    bool ok = false;
    if (!newFilePath.isEmpty()) {
        QString errorMessage;
        if (!performSave(errorMessage, newFilePath)) {
            showMessage(...);
        }
    }

    return ok;
```

Callers that act on the result (from reading the code; not reproduced
yet):

- `DatabaseTabWidget::saveDatabaseAs()`: skips `updateLastDatabases()`,
  so a database saved with Save As is not added to the recent databases.
- `DatabaseWidget::save()` returns `saveAs()` for a database that has no
  file yet (a new database).  `lock()` then takes the save as failed:
  closing or locking a new, modified database asks for a file, saves,
  and asks "Save changes?" again.
- `syncWithDatabase()` (Remote Sync) reports an error if `save()` fails
  (only reachable for a database without a file, i.e. not in practice).

## Goals

- Confirm the symptoms on a release build (recent databases after Save
  As; closing a new database).
- Search KeePassXC's issues for an existing report; if none, report it.
- Offer the one-line fix upstream, as a small pull request with a test,
  following their template (description, testing, AI disclosure).

## Non-goals

- Anything else in Save As or the save flow.
- The fork's YubiKey branch of `saveAs()`, which already returns the real
  result (spec 0030).

## Specification

- In `DatabaseWidget::saveAs()`, set the result from the save:
  `ok = performSave(errorMessage, newFilePath);`, showing the error as
  today when it is false.
- A test in KeePassXC's GUI tests (`tests/gui/TestGui.cpp`, which can
  set the next file name of the file dialog): Save As to a new file
  returns true and adds the file to the recent databases.

## Open questions

- Is there already an issue or a fix in flight upstream?
- Do the "Save changes?" twice symptom and the recent-databases symptom
  both reproduce?

## References

- Spec 0030 (KeePassXC integration); the fork's `chooseSaveLocation()`.
- KeePassXC `src/gui/DatabaseWidget.cpp`, `DatabaseWidget::saveAs()`,
  `lock()`; `src/gui/DatabaseTabWidget.cpp`, `saveDatabaseAs()`.
