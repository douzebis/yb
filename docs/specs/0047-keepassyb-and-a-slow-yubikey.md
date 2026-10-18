<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0047 — KeePassYB and a Slow YubiKey

**Status:** implemented
**App:** KeePassYB (`douzebis/keepassyb`, branch `keepassyb`)
**Implemented in:** 2026-10-17

## Problem

KeePassYB (spec 0046) treats a vault on the YubiKey much like a file.
But a YubiKey is slow: a write takes seconds, and on a post-quantum store
every read and write also waits for the FIDO2 PIN and a touch.  The first
tests on a desktop (2026-10-17, post-quantum store) showed it:

- **Exit after only opening and closing a vault:** the desktop showed
  "KeePassYB is not responding" (Force Quit / Wait), then KeePassYB
  closed.  Nothing was changed, yet something waited on the YubiKey.
  The log of S1 (2026-10-17, post-quantum store) showed the cause.  It was
  not a save: the vault was not modified.  It was **repeated YubiKey
  queries on the GUI thread**:
  - every libyubiblob call opens a session and reads the whole store,
    about 1.3 s; asking the store's kind costs as much again;
  - at opening, before the PIN, KeePassYB made 5 such queries: two
    header reads without a key (which can only fail on a post-quantum
    store, 2.6 s each), two listings for `<vault>.passwd`, and one for the
    vault;
  - at exit, the locked view reloaded and queried everything again,
    about 9 to 12 s, which the desktop saw as a hang.
- **Saving:** KeePassYB saves a few seconds after each change, and at
  lock and exit.  Every save is a YubiKey write: wear, seconds of
  waiting, and on a post-quantum store a touch.
- **Opening a vault on a post-quantum store** asks for the FIDO2 PIN and
  a touch.  yb checks the blob's seal and the management key (spec 0028,
  D6, D11) before returning it.  For a KDBX 4 vault the file checks
  itself (an HMAC over every block, keyed by the master password), so
  these checks add little (S4).
- **"Hardware key error: timeout" on the console:** the unlock dialog
  scans for KeePassXC challenge-response keys, and the scan times out
  when the YubiKey is busy waiting for a touch.
- **The desktop entry** names `keepassyb` without a path.  When KeePassYB
  is installed in `~/.local`, the desktop portal (a systemd user service,
  whose `PATH` lacks `~/.local/bin`) discards it ("App info not found
  for 'io.github.douzebis.KeePassYB'").  Writing the full path fixed it
  (tested on the host).

## Goals

- G1. **Instrumentation:** every YubiKey operation KeePassYB performs can
  be logged on demand, with:
  - what triggered it;
  - how long it took;
  - and, for a save, why the vault counted as modified.
  The open-and-close case is diagnosed with it before anything else
  changes.
- G2. **Nothing is written when nothing changed.**  A vault on the
  YubiKey is never written at lock or exit unless its data changed since
  it was read or saved.
- G3. **Explicit saves for vaults on the YubiKey:**
  - no automatic saving after changes;
  - Save writes;
  - at lock, close or exit with unsaved changes, KeePassXC's own question
    (Save / Discard / Cancel).
- G4. **Slow YubiKey operations are visible, and the window stays
  responsive.**  A modal progress dialog shows while KeePassYB reads or
  saves a vault on the YubiKey: what it does, and "Touch your YubiKey"
  when it waits for a touch.  The window never freezes, so the desktop
  never offers to force-quit.
- G5. **KDBX 4 vaults are read without the PIN or a touch,** on
  post-quantum stores too: with the checksum only (yb spec 0044),
  relying on KDBX 4's own integrity check.  The FIDO2 PIN and a touch are
  then needed only to save.  KDBX 3.1 vaults keep the full check.
- G6. **No automatic challenge-response scan** in the unlock dialog of a
  vault on the YubiKey (the refresh button still scans).
- G7. **The desktop entry names the installed program by its full path.**

## Non-goals

- **Cancelling a pending touch from KeePassYB.**  libyubiblob has no
  cancel call; the YubiKey gives up by itself after about 30 seconds.
- **Changing KeePassXC's behavior for file databases.**  Auto-save
  settings keep their meaning for files.
- **Rollback protection:** an older genuine vault written back is not
  detected (neither by the seal nor by KDBX 4).  This is yb's non-goal.
- **Background saving after the window has closed.**

## Specification

### S1. Instrumentation (first)

**The logging category:** `keepassyb.yubikey`, off by default, at info
level: KeePassXC's release builds leave out debug output
(`QT_NO_DEBUG_OUTPUT`).  Turn it on with:

```shell
QT_LOGGING_RULES="keepassyb.yubikey=true" keepassyb
```

**What is logged**, one line each, to standard error with a timestamp:

- **Each `DeviceStorage` operation:**
  - list, kind, read (cached or not, with PIN, or checksum only), write,
    remove, PIN prompt;
  - the vault's name and the outcome;
  - **durations:** the total, split into the time waiting for the PIN
    prompt, waiting for a touch, and talking to the YubiKey (the actual
    read or write);
  - never the PIN, a password, or any content.
- **Each save of a vault on the YubiKey:**
  - the trigger: Save, Save As, lock, close, exit, or the automatic
    timer while it exists;
  - `isModified()` and `hasNonDataChanges()`;
  - **the cause:** the first modification since the last read or save,
    with its source.  `Database::markAsModified` logs the place that
    called it, through a small wrapper for vaults on the YubiKey: the
    signal that fired, e.g. a group's expanded state, the metadata, an
    entry.
- **Each lock and exit:** what KeePassYB decided (nothing to save, ask,
  save).

**Use:** reproduce open and close on the post-quantum store, read the
log, and record the finding here (S2 says what to do about each
possible cause).

### S2. Fewer, faster YubiKey queries (S1's finding)

S1's log found no spurious modification at exit.  The fixes, for the
queries it did find:

1. **One YubiKey query per user action.**  `DeviceStorage` keeps each
   YubiKey's listing (its blobs, with their generation, size and
   encryption) and its store kind:
   - every question asked during one action uses it: is the vault
     there, has it changed, is a `.passwd` there and usable;
   - it is dropped after KeePassYB's own writes and removals on that
     YubiKey;
   - it expires after 3 seconds, so a change made elsewhere (another
     computer) is seen at the next action.
2. **One status question for the unlock dialog:** `passwordStatus()`
   answers, from that one listing, whether a master password is stored,
   whether it is used, why not, and whether one can be remembered.
3. **Nothing at quit.**  Once KeePassYB is quitting, reads and status
   questions do not reach the YubiKey; they answer at once ("KeePassYB is
   quitting").  Writes still do, for a save asked at exit.
4. **No header read that can only fail.**  Reading only a vault's
   headers (no key, e.g. the locked view) answers from the listing and
   the store kind when the read would need the PIN, with no read of its
   own.  The store kind is kept for the whole run, since only a reformat
   changes it, so after the first time this costs no store-kind query
   either.
5. **Off the GUI thread.**  Every `DeviceStorage` operation called from
   the GUI thread runs on a worker thread, while the GUI thread keeps
   processing events.  The window never freezes, even for one slow query.
   Operations are serialized (one at a time).

**The unchanged-content check** (a second chance not to write, kept
permanently, decided 2026-10-17):
- At lock or exit, when the vault is marked modified, KeePassYB first
  serializes it and compares it with what it last read or saved.
- It compares a hash of the normalized XML content, taken when the vault
  is read and after each successful save, with the current one.  The
  normalization leaves out what changes without a data change:
  - the random padding KeePassXC adds on each save
    (`CustomData::RandomSlug`) and custom data's last-modified stamp;
  - view state: selected and top visible groups, expanded groups;
  - access times and usage counts;
  - modification times: expanding a group stamps it as modified.  A real
    change still differs, since it changes the data itself.
- Identical content: no question, no write, and the log says so, so a
  wrong "modified" mark still shows up as a bug to fix.

It is implemented with S3 (explicit saves), where the question at lock
and exit is asked.

### S2b. Expected YubiKey interactions

With S2 to S4 in place, for one vault:

| Moment | Post-quantum store | Legacy store |
|---|---|---|
| Open, KDBX 4 | read once; no PIN, no touch | read once; no PIN |
| Open, KDBX 3.1 | read with the FIDO2 PIN and a touch | read once; no PIN |
| Open with a stored master password (`.passwd`) | + the FIDO2 PIN and a touch, to decrypt it | not used (spec 0046 S3) |
| "Remember the master password" ticked at unlock | + a write: one touch | not offered |
| Unlock after a lock, vault unchanged on the YubiKey | nothing read (a listing, no PIN) | same |
| Unlock after a lock, vault changed elsewhere | read again, as at opening | same |
| Save (Ctrl+S) | a write: the FIDO2 PIN if not cached, one touch | a write: the PIV PIN if not cached |
| Lock, close or exit, unchanged | nothing | nothing |
| Lock, close or exit, changed | "Save changes?"; Save as above | same |

**The PIN:**
- it is asked only when first needed (just in time);
- it is held while the vault is unlocked, so at most once per unlocked
  session;
- it is forgotten at lock and after a wrong PIN, so a locked KeePassYB
  holds no YubiKey PIN.

  This is spec 0046's behavior, kept as it is (decided 2026-10-17).

**The touch:** exactly one per write.  The management-key check (spec
0028, D11) rides in the same touch: one FIDO2 assertion carries both
salts.

The tests of this spec check this table, with the fake backend counting
PIN prompts, touches, reads and writes.

### S3. Explicit saves

Replaced by spec 0050 S2 (automatic saves when the normalized content
changed, after a quiet delay); the unchanged-content check stays.

For a vault on the YubiKey:

- **No automatic saving:**
  - no timer after changes (spec 0046's few-seconds delay is removed);
  - KeePassXC's "Automatically save after every change" and
    "Automatically save when locking or exiting" do not apply;
  - the settings page says so next to them: "Not for databases on a
    YubiKey".
- **Save (Ctrl+S)** writes, with the progress dialog (S4).
- **Lock, close and exit with unsaved changes:** KeePassXC's own question
  ("Save changes?"):
  - Save: writes, with the progress dialog;
  - Discard: closes without writing;
  - Cancel: keeps it open.
- **A failed save** (YubiKey removed, touch refused, PIN refused, store
  full) keeps the vault open and modified.  It says why, and offers:
  - Retry;
  - Save As a file;
  - Discard, which needs a second confirmation.
  Nothing is lost silently.
- **The window title** marks unsaved changes as KeePassXC does (`*`),
  so the user sees that a Save is due.

### S4. Visible slow operations; reads without PIN for KDBX 4

**The progress dialog:**

- `DeviceStorage`'s reads and writes always run on a worker thread.  The
  GUI thread shows a modal dialog and keeps processing events:
  - "Reading Passwords.kdbx from the YubiKey…" or "Saving Passwords.kdbx
    to the YubiKey…";
  - then "Touch your YubiKey" while libyubiblob waits for a touch (its
    callback);
  - an indeterminate progress bar.
- The dialog shows only if the operation lasts more than about 300 ms,
  so a cached read never flashes it.
- **No Cancel button:** a YubiKey write must not be interrupted halfway,
  even though yb would keep the previous version.  A touch wait ends by
  itself.
- **The command line** (`keepassyb-cli`) prints "Touch your YubiKey…" on
  standard error, as it does today.

**Reads without the PIN** (on by default, no setting; decided
2026-10-17): for an unencrypted vault in a post-quantum store, KeePassYB first reads it with its checksum only
(`yubiblob_fetch_unencrypted`, no PIN, no touch), then looks at the KDBX
version in its header:

- **KDBX 4:** the vault is used as read.
  - Why this is safe: someone who changes it, or replaces it with
    another vault, without the master password makes it fail to open,
    since every block's HMAC is keyed by the master password.
  - Only replaying an older genuine version goes unnoticed, which the
    seal does not prevent either.
- **KDBX 3.1:** read again with the full check (FIDO2 PIN and touch), as
  today.  Its own integrity check is weaker, so the YubiKey's check
  matters.  If the YubiKey is locked, spec 0046's fallback, with its
  stronger warning, still applies.

The FIDO2 PIN is then asked only at the first save, and the "locked
YubiKey" fallback of spec 0046 becomes needed only for KDBX 3.1 vaults.

**Legacy stores:** unchanged.  Reads already need no PIN.

### S5. The unlock dialog's hardware-key scan

For a vault on the YubiKey, the unlock dialog does not scan for
challenge-response keys when it opens.  The "refresh" button next to
the hardware-key list still scans, for users who also use
challenge-response.  A file database's dialog is unchanged.

### S6. The desktop entry

`Exec=` and `TryExec=` give the installed program's full path,
`<prefix>/bin/keepassyb`.  The path is written at install time, since
`cmake --install --prefix` may change the prefix after configuring.  The
AppImage, Flatpak and Snap builds keep the bare name: AppImage rewrites
`Exec`, Flatpak exports it.  The application icons' install patterns
are fixed along the way (they still named `keepassx`, so a native
install had no icons).

### Order of work

1. **S1:** instrumentation; reproduce open and close on the
   post-quantum store; record the cause in S2.  Done: repeated queries.
2. **S2:** the five fixes; re-test with the log.
3. **S3 and S4:** explicit saves with the unchanged-content check, the
   progress dialog, reads without PIN for KDBX 4.
4. **S5 and S6.**

## Tests

In `tests/TestDeviceStorage.cpp` (fake backend) and the GUI tests where
they run:

- `testOneListingPerAction`: the unlock dialog's questions and a header
  read cost one listing and one store-kind query.
- `testListingIsDroppedAfterAWrite`, `testListingExpires`.
- `testNothingReachesTheYubiKeyWhenQuitting`: reads and status questions
  answer at once; a write still works.
- `testOperationsRunOffTheGuiThread`: the backend is called from a
  worker thread.
- `testNoWriteWhenUnchanged`: open, lock and close a vault; no write,
  no PIN prompt.
- `testNonDataChangesAreNotSaved`: expand a group, then lock; no write.
- `testExplicitSave`: a change, then nothing written until Save; lock
  asks (Save writes, Discard does not).
- `testKdbx4ReadsWithoutPin`: post-quantum store, KDBX 4 vault, opened
  with no PIN prompt and no touch; the first save asks.
- `testKdbx3ReadsWithFullCheck`: KDBX 3.1 vault, the PIN is asked at
  open.
- `testFailedSaveKeepsChanges`: a store refused at lock, the vault
  stays modified, the user is told.
- `testLoggingNamesTheCause`: with the category on, a save logs its
  trigger, the first modification's source, and its durations (PIN
  wait, touch wait, YubiKey time).
- `testInteractionsTable`: each row of S2b, counting PIN prompts,
  touches, reads and writes.

## Result (host test, 2026-10-17)

Post-quantum store, KDBX 4 vault:
- open, then quit: no PIN, no touch, no write; 2.9 s of YubiKey time at
  the unlock dialog (listing, store kind and read, about 0.95 s each)
  and 0.96 s at unlock (a fresh listing, data from the cache);
- a change, then quit and Save: one FIDO2 PIN prompt, one touch;
  2.1 s of YubiKey time (a listing before and after the write).

## Further optimizations (not in this spec)

Ideas kept for a later spec (user, 2026-10-17):

- **Automatic saves driven by the normalized content.**  With a reliable
  normalization, explicit saves are no longer needed: save automatically
  each time the normalized content changes, after a short delay so that
  a burst of changes makes a single write.  View changes, which leave
  the normalized content as it is, never write.
- **No greedy read of the whole store.**  Each libyubiblob call opens a
  session and reads the whole store (about 1.3 s), even to list blobs or
  learn the store kind.  Reading only what an operation needs would
  speed up every operation, if yb's sanitization (which checks the whole
  store before trusting any of it) allows it; it may not.

## Open questions

None.  (Decided 2026-10-17:
- Q1: the unchanged-content check is kept permanently;
- Q2: reads without the PIN for KDBX 4 are on by default.)

## References

- [spec 0046](0046-keepassyb.md): KeePassYB, unencrypted vaults, the
  locked-YubiKey fallback.
- [spec 0044](0044-reading-unencrypted-blobs-without-the-pin.md):
  `yubiblob_fetch_unencrypted`.
- [spec 0028](0028-post-quantum-protection.md): seals (D6), the
  management key check (D11).
- KDBX 4 format: per-block HMAC-SHA256 keyed from the master key.
- The user's idea of explicit saves: memory note, 2026-10-17.
