<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# Pull request for KeePassXC (draft)

To open as a **draft** pull request from `douzebis:feature/yubikey-storage`
to `keepassxreboot:develop`, after the feature request issue (replace
`#ISSUE` below).

**Title:** Add databases stored on a YubiKey (via libyubiblob)

---

Proposal for discussion, not for merging as is: see #ISSUE.

KeePassXC can open and save a database that lives on a YubiKey instead of
in a file.  The database is an ordinary KDBX file, kept in the YubiKey's
PIV application by [libyubiblob](https://github.com/douzebis/yb) (the C
library of yb), encrypted to a key that never leaves the YubiKey.  Opening
it needs the YubiKey and its PIN; no copy is written to the computer's
disk.

### How it works

- **Locations.**  A database on a YubiKey is named
  `yubikey:<serial>/<name>.kdbx` (`yubikey:/<name>.kdbx` for the only one
  connected), wherever KeePassXC uses a file path as an identity (tab
  titles, recent list, per-database settings).
- **One branch point in `Database`.**  `Database::open` reads such a
  location into memory and parses it with the existing reader from a
  `QBuffer`; `Database::saveAs` serializes into a `QBuffer` (as the
  DirectWrite mode does) and hands the bytes to the device.  No file, no
  file watcher, no backup.  `canonicalFilePath()` returns the location.
- **`core/DeviceStorage`** is the device side: a small backend interface
  (list, fetch, store) on libyubiblob, one session per operation; a read
  cache of the encrypted bytes, checked against the device without the PIN
  (by the blob's generation), so that unlocking after a lock needs no
  device access; write-through saves.  The PIN is asked when first needed,
  held in memory overwritten when cleared, and forgotten at lock.
- **Saving.**  A database on a YubiKey saves 5 seconds after the last data
  change (a YubiKey write takes 1–4 s), and at once on lock, close and
  quit (SIGTERM included, through the existing handling).  Non-data
  changes alone never cause a write.  An interrupted write keeps the
  previous version on the device; a failed save leaves the database
  modified.
- **Opening.**  "Open Database" asks libyubiblob, without the PIN, for the
  vaults on a connected YubiKey; if there is one set up for yb, a list
  offers its vaults, another YubiKey by serial number, or a file;
  otherwise the file dialog opens as before.  If the YubiKey also holds
  the database's master password (`<name>.passwd`), it unlocks with it.
- **Other paths:** `addDatabaseTab` skips the file checks for a location;
  YubiKey databases are not reopened at start-up; Save As, Save Backup and
  Remote Sync are disabled for them; `keepassxc-cli` opens and saves them,
  asking for the PIN on standard input.
- **Build:** `KPXC_FEATURE_YUBIBLOB`, off by default; when on, libyubiblob
  (>= 0.1) is required, through pkg-config.  Without it, the code builds
  and YubiKey operations say this build has no YubiKey storage.

libyubiblob 0.1.0 is on crates.io (crate `yubiblob`, built with cargo-c:
`cargo cinstall -p yubiblob`, or the tag `yubiblob-v0.1.0` of
douzebis/yb); its interface is specified in
[spec 0039](https://github.com/douzebis/yb/blob/main/docs/specs/0039-c-api.md).
It builds on Linux, macOS and Windows; this pull request is tried on Linux
only.

### Questions for you

1. **An in-process C library or a command?**  A first version ran the `yb`
   command through `QProcess` (branch `yb-device-storage` of the fork);
   the library avoids a subprocess, passes the PIN in memory and reports
   typed errors, but adds a Rust-built dependency.
2. **Packaging for Windows and macOS:** a vcpkg port of libyubiblob?
3. **Setting up a YubiKey** is done with `yb format` today; should
   KeePassXC offer it?
4. **The user interface:** the vault list in Open Database is a plain
   `QInputDialog`; a proper dialog, and creating a database directly on
   the YubiKey, would follow your preferences.

### Use of generative AI

The majority of this code was written with Claude (Anthropic, model
Claude Opus 5.5, through Claude Code), under my direction and review, and
tried on my own YubiKey and databases.

## Screenshots

(To add: the Open Database list, the PIN prompt.)

## Testing strategy

- **Unit tests** (`tests/TestDeviceStorage.cpp`, 13 tests, run without a
  YubiKey through a stand-in backend that follows libyubiblob's documented
  contract): locations; save and reopen through memory; the cache serving
  reopens without fetching; a database changed on the device fetched
  again; store full keeping the database modified; the PIN asked once and
  forgotten; header-only reads (start-up) never asking for the PIN; a
  missing database; a wrong PIN with tries left; the vault list; a stored
  master password.
- **The existing suite** passes with the feature on.
- **By hand, with a YubiKey 5** (firmware 5.7.1): open, edit, lock and
  unlock, close and reopen, quit and restart; `keepassxc-cli` create, add
  and show; wrong master password; a database without a stored password.
- **libyubiblob** has its own tests (Rust and C, on simulated YubiKeys),
  including interrupted writes and a card running out of memory.

## Type of change

- ✅ New feature (change that adds functionality)
