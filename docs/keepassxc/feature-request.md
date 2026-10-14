<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# Feature request for KeePassXC (draft)

To file at https://github.com/keepassxreboot/keepassxc/issues/new?template=feature_request.yml.
The form's three fields follow.

**Title:** Store a database on a YubiKey (PIV), not in a file

---

**Have you searched for an existing feature request?**
- [x] Yes, I tried searching

**Brief Summary**

Let KeePassXC open and save a database that lives on a YubiKey instead of
in a file.  The database (an ordinary KDBX file) is kept in the YubiKey's
PIV application, encrypted to a key that never leaves the YubiKey; opening
it needs the YubiKey and its PIN, in addition to the master password, and
no copy of the database is left on the computer's disk.

This is different from KeePassXC's existing YubiKey challenge-response,
which strengthens the key of a database that is still a file, copied to
every disk and sync service it goes through.

The storage side exists: [yb](https://github.com/douzebis/yb) keeps small
named blobs on a YubiKey (PIV objects), and its C library, libyubiblob,
offers it to other programs: list, fetch, store and remove, with typed
status codes and the PIN passed in memory.  A save interrupted by pulling
the YubiKey out keeps the previous version; tampering is detected by a
signature checked before use.  A YubiKey 5 holds about 50 KB, enough for
typical databases (10–20 KB with room to replace them safely).

I have a working implementation, tried with my own YubiKey and databases,
and would like to propose it as a draft pull request for discussion (see
below).

**Example**

1. Once, put the database on the YubiKey: `yb format` (guided set-up),
   then `yb store -n Passwords.kdbx ~/Passwords.kdbx`.
2. In KeePassXC, **Open Database**: with a YubiKey connected, the list
   offers `Passwords.kdbx (on the YubiKey)` next to "A file…".
3. Enter the YubiKey's PIN, then the master password (or let a master
   password stored on the YubiKey unlock it).
4. Work as usual: KeePassXC saves to the YubiKey a few seconds after the
   last change, and at once on lock, close and quit.  Non-data changes
   (an expanded group) do not cause a write.

The database identifies itself as `yubikey:<serial>/Passwords.kdbx` in the
recent list and the window title; Save As, backups and Remote Sync are
disabled for it, as they assume a file.

**Context**

- The database file is the weak point of a password manager: every copy
  (laptops, backups, sync services) can be attacked offline, without
  limit, and is only as strong as the master password.  On a YubiKey,
  there is no file to copy, and the PIN's retry counter limits attempts.
- Carrying the database between computers needs no sync service: it
  travels with the YubiKey.
- Optionally, keeping the master password on the YubiKey lets the
  database open with the YubiKey and its PIN alone, which suits users who
  would otherwise pick a short master password (an explicit trade-off).
- Most users' databases are small: mine is 2.4 KB; colleagues' are about
  10 KB; one keeps three per-context databases (9 + 10 + 3 KB) on one
  YubiKey.

Questions for the maintainers, before any pull request is considered for
merging: an in-process C library (as proposed) or calling a command; the
user interface; Windows and macOS (libyubiblob builds on both; packaging
through vcpkg); and whether setting up a YubiKey should be possible from
KeePassXC itself rather than with the `yb` command.
