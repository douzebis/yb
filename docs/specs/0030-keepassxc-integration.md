<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0030 — KeePassXC Integration

**Status:** draft
**App:** yb
**Implemented in:** <!-- YYYY-MM-DD, fill after implementation -->

> **Draft.**  Based on a study of KeePassXC's `develop` branch (commit
> `9e0f57a`, 2026-09-22; file references below are to that tree).  Scope
> decided on 2026-10-13: a **mock-up inside KeePassXC** (path 2 of the
> first draft), calling the existing `yb` command, to show KeePassXC's
> maintainers working code; the launcher outside KeePassXC (path 1) and a
> C library are left for later.  The KeePassXC part is a proposal to
> discuss with its maintainers, not a commitment on their side.

## Problem

[KeePassXC](https://keepassxc.org/) is a popular open-source password
manager (C++/Qt, GPL-2 or GPL-3).  It keeps its vault in a KDBX file on
disk, encrypted with a key derived from a master password (Argon2d +
AES-256 by default), optionally combined with a key file or a YubiKey
challenge-response (HMAC-SHA1, OTP application).

That leaves its users with three recurring problems:

- **The vault file lives on disks**, and is copied to every machine and
  sync service it travels through.  Anyone who obtains a copy can attack
  the master password offline, without limit on attempts; the vault is
  only as strong as that password.
- **Carrying the vault** between machines needs a sync service or a USB
  stick, each with its own exposure.
- **The master password must be typed** each time, which pushes users
  towards shorter passwords.

A YubiKey with yb is a natural home for a small vault: yb stores blobs on
the YubiKey's PIV application, encrypted to a key that never leaves it
(ECDH P-256, AES-256-GCM), and decrypting needs the PIN, whose retry
counter blocks it after 3 wrong attempts.

The idea: keep the KeePassXC vault as a yb blob on the YubiKey, so that
opening it needs the YubiKey and its PIN on top of the master password,
and no vault file is left on disk.  Optionally, the master password can
be kept on the YubiKey too, for unlocking with the PIN alone.

## Goals

- **G1 — Vault on the YubiKey.**  A KeePassXC vault can be opened from,
  and saved back to, a YubiKey managed by yb, with no persistent copy on
  the computer's disk.
- **G2 — Master password on the YubiKey (optional).**  If the YubiKey
  also holds the vault's master password (as an encrypted yb blob), it is
  used without asking the user: the vault opens with the YubiKey and its
  PIN alone.  If it does not, the user types the master password as
  usual, and the YubiKey and PIN come on top of it.  Keeping the master
  password on the YubiKey is the user's explicit choice, with its
  trade-offs explained (see Security trade-offs).  In v0, the user adds
  and removes it by hand with yb's existing commands (see Naming).
- **G3 — No new trust in the host.**  The integration does not weaken
  what KeePassXC and yb guarantee today: secrets are not written to disk
  in plaintext, and the vault file stays a standard KDBX file (readable
  by any KDBX application once exported).
- **G4 — Recovery.**  Losing, breaking or permanently blocking the
  YubiKey (PIN, then PUK, blocked) must not lose the vault: the
  integration documents and supports a backup kept elsewhere (a second
  YubiKey, or an exported KDBX file kept offline, still encrypted by the
  master password), and a way to restore it.
- **G5 — Fits the YubiKey, and survives interruptions.**  Saving never
  loses the stored vault: if the YubiKey is pulled out during a save, the
  previous version or the new one is intact (spec 0031).  A save that
  would not fit fails before touching the stored vault, and the user is
  told how much room is left.
- **G6 — A proposal KeePassXC can evaluate.**  A working prototype, used
  daily by its author ("eat your own dog food"), with measurements (size,
  speed, write frequency), shown to the KeePassXC maintainers before
  asking for any change on their side.
- **G7 — Reading never writes.**  A session in which the vault is only
  read (opened, searched, entries copied) writes nothing to the YubiKey.
  This matches the expected use (read daily, changed rarely) and keeps
  writes to the card's flash rare.  A launcher outside KeePassXC would
  reach it only partly (see
  "Saves without user edits"); the mock-up reaches it fully.
- **G8 — Several vaults on one YubiKey.**  A user with several vaults
  (e.g. per context) can keep them on the same YubiKey, each with its
  optional master password, as long as they fit together.

## Non-goals

- **Replacing KeePassXC's YubiKey challenge-response.**  It stays as it
  is; this is a different, complementary use of the YubiKey.
- **Keeping only a key file on the YubiKey, with the vault on disk.**
  KeePassXC accepts a key file as a second factor; keeping it as a yb
  blob would protect a vault that stays on disk or in a sync service.
  Rejected: it overlaps with KeePassXC's existing YubiKey
  challenge-response, and misses the point of this spec, which is the
  vault itself on the YubiKey.
- **Compression through shared plaintext.**  KeePassXC could hand parts
  of the vault (e.g. notes) to yb unencrypted, for yb to compress them
  better than KDBX does.  Not for a first release, and possibly never:
  KDBX already compresses its content (gzip, by default) before
  encrypting it, so the gain would be modest; and yb's encryption would
  replace KeePassXC's for that data, a change of security model that
  KeePassXC's maintainers and users would rightly question.  Size is
  managed instead with KeePassXC's own settings (history items and size
  per entry) and by keeping attachments and custom icons out of the vault
  stored on the YubiKey, documented for users.
- **Large vaults.**  Vaults with attachments, many custom icons or long
  entry histories will not fit (see Feasibility); they are out of scope,
  not a target for compression or splitting across YubiKeys.
- **Other password managers** (KeePass 2.x, KeePassDX, Strongbox…), even
  though the KDBX format would allow it later.
- **Mobile platforms** (Android, iOS): no PC/SC there in the same form.
- **Windows and macOS for the mock-up:** Linux only (decided 2026-10-13).
- **Syncing between several YubiKeys**, or between a YubiKey and a vault
  file elsewhere, beyond what recovery (G4) needs.
- **Post-quantum protection**, handled by spec 0028; this spec only
  records how the integration interacts with it.
- **A KeePassXC plugin.**  KeePassXC has no plugin interface (no
  `QPluginLoader`, `dlopen` or `Q_PLUGIN_METADATA` in `src/`); anything
  inside KeePassXC is an upstream change, decided by its maintainers.
- **For the mock-up:** a launcher outside KeePassXC (path 1 of the first
  draft), a C library or machine-readable (`--json`) output in yb,
  recovery tooling, and managing the master password from KeePassXC.
  Later, if the discussion with KeePassXC's maintainers calls for them.
- **KeePassXC talking PIV itself.**  KeePassXC has no PIV code; its PC/SC
  code only does HMAC-SHA1 challenge-response on the OTP applet, and
  skips readers named "YubiKey" (`src/keys/drivers/YubiKeyInterfacePCSC.cpp:571`).
  Reimplementing yb's on-card format in C++ is possible later, not now.

## Feasibility

### Capacity

- A YubiKey 5 has **51,200 bytes** of PIV storage, of which about
  **50 KB** is available to data objects (`docs/yubikey-nvm-internals.md`,
  measured); yb's store uses part of it for its own structure, and other
  PIV data (certificates of other slots) shares the pool.
- An empty KDBX 4 vault is about 2 KB.  Each entry adds a few hundred
  bytes compressed, more with history (KeePassXC keeps up to 10 history
  items and 6 MiB per entry by default, `src/core/Metadata.cpp:27-28`).
- **Real vaults in daily use** (2026-10, the author and colleagues):

  | Vault | Size |
  |---|---|
  | The author's (small, not representative) | 2.4 KB |
  | Colleagues', typical | about 10 KB |
  | One colleague's three per-context vaults | 9 KB + 10 KB + 3 KB = 22 KB |

- **Saves need room for two copies** of the vault being replaced: the
  new version is written before the old one is removed (G5, spec 0031).
  So what must fit is all blobs, plus one more copy of the largest vault.
  For the three-vault example: 22 KB + 10 KB = 32 KB, within the ~50 KB
  available.  Capacity is a real limit only for large vaults, a
  non-goal.
- A vault is **a single KDBX file**: groups, entries, notes, attachments
  and icons are all inside it.  yb's flat namespace (no directories) is
  therefore no obstacle: each vault is one blob, its optional master
  password another.

### One blob per vault, rewritten whole

A vault cannot be split so that a save rewrites only what changed (e.g.
per group or entry), whatever the layout on the YubiKey:

- a KDBX file is compressed, then encrypted as a single stream, and each
  save generates a new random master seed, encryption IV and KDF seed
  (`src/format/Kdbx4Writer.cpp:46-51`), so two saves of identical content
  differ in every byte;
- yb adds the same property: each store encrypts with a fresh ephemeral
  key.

Splitting would only help if KeePassXC handed yb the vault's content
before encrypting it, which is the "shared plaintext" non-goal.  The
single blob per vault is therefore not a fallback but the only option
within the security model; wear is managed by how often the vault is
written (G7), not by how much.  The vault is stored with `--no-compress`:
KDBX is already compressed and encrypted, so yb's compression gains
nothing.

### Writes: frequency and endurance

- Every save rewrites the vault blob: several PIV objects.
- The YubiKey's flash endurance and wear-leveling are not published
  (`docs/yubikey-nvm-internals.md`); hence G7.
- Entering the PIN updates the YubiKey's retry counter internally, as
  with any smart-card use (SSH, GPG, PIV); unavoidable, and what the
  hardware is designed for.
- **Measured** (YubiKey 5, firmware 5.7.1, 2026-10-13; `yb` with the PIN
  on standard input, release build):

  | Vault | First store | Replace | Fetch |
  |---|---|---|---|
  | 2 KB | 0.73 s | 0.55–0.68 s | 0.26–0.29 s |
  | 10 KB | 1.55 s | 2.46–3.64 s | 0.30–0.31 s |
  | 22 KB | 4.14 s | out of card memory | 0.41–0.55 s |

  Fetches are fast enough to be invisible at open; writes take seconds,
  hence the 5-second delay and one write per burst of edits.
- **The card's memory is the real limit, not yb's objects:** with 2, 10
  and 22 KB vaults stored (about 35 KB used), replacing the 22 KB one
  needs a second copy and runs out of the card's memory (about 51 KB,
  shared with certificates and the management key).  The save then fails
  with the previous vault intact (spec 0038), and the user is told to
  make room.

### Saves without user edits (KeePassXC behavior)

KeePassXC saves far more often than "when the user edits", by default
(`src/core/Config.cpp:61-64`):

| Setting | Default | Effect |
|---|---|---|
| `AutoSaveAfterEveryChange` | true | saves after each change (debounced) |
| `AutoSaveOnExit` | true | saves on lock, close and exit if modified |
| `AutoSaveNonDataChanges` | true | on lock, silently saves "non-data changes" |

- **Reading does not modify the vault:** copying a username or password
  only sets the clipboard; nothing updates entries' access time or usage
  count (`src/gui/DatabaseWidget.cpp:709-723`).
- **But "non-data changes" do:** expanding or collapsing a group, or
  reordering entries, updates the group's timestamps and marks a
  non-data change (`src/core/Group.cpp:392-397`); locking then saves the
  vault silently (`src/gui/DatabaseWidget.cpp:2114`).
- **And the first unlock of some vaults** adds a public UUID to KDBX 4
  vaults that lack one, marking them modified
  (`src/core/Database.cpp:1162-1178`).

Since every save re-encrypts everything, comparing file contents cannot
tell a real edit from a collapsed group.  Consequence: a launcher outside
KeePassXC would write to the YubiKey after such sessions; only code inside
KeePassXC, which sees its own "data changed" signal, can skip non-data
changes (G7).

### Security trade-offs (to be explicit with users)

- **Without the master password on the YubiKey** (the default), opening
  the vault needs the master password, the YubiKey and its PIN: strictly
  stronger than today, and no vault file exists for offline attack.
- **With it (G2),** the vault's protection becomes possession of the
  YubiKey plus its PIN (3 attempts, then blocked).  That beats a weak
  master password exposed to offline attack, but the master password no
  longer adds a separate factor.  An informed choice, offered, not
  imposed.
- **Losing or breaking the YubiKey loses the vault,** unless a backup
  exists (G4).  A blocked PIN can be reset with the PUK; a blocked PUK
  leaves only the backup.
- **Post-quantum (spec 0028):** yb's store can be read without the PIN,
  and blob encryption relies on ECDH P-256.  A vault stored alone stays
  protected by KDBX's own symmetric encryption and Argon2, which a
  quantum computer does not break; a vault stored **with** its master
  password is protected by ECDH alone.  G2 therefore lowers the
  long-term protection of copied stores until 0028 is addressed; the
  default (master password typed) does not.
- **No copy on the host's disk:** the vault goes between the YubiKey and
  KeePassXC's memory; while open, KeePassXC holds the encrypted bytes
  (read cache) and, unlocked, the decrypted database, as it does today.
- **Host compromise** (malware while the vault is open) is the same as
  with KeePassXC today, and out of scope.

### Integration with KeePassXC: what exists

- **No storage abstraction.**  Databases are identified by a file path
  everywhere: opening (`Database::open`, `src/core/Database.cpp:131-196`),
  saving (`Database::saveAs`, `:269-356`), locking (the locked tab keeps
  the path and re-reads the file at unlock,
  `src/gui/DatabaseWidget.cpp:2139-2141`), the recent-databases list.
- **Saving is safe by default:** `QSaveFile`, i.e. write a temporary file
  in the same directory, then rename (`Database.cpp:368-396`).
- **Remote Sync exists** (`src/gui/remote/`): per database, the user
  configures download and upload commands, run without a shell through
  `QProcess`, with `{TEMP_DATABASE}` substituted and optional text written
  to their standard input (`RemoteProcess.cpp:37-46`,
  `RemoteHandler.cpp:63-67`).  But it is a manual merge with a peer
  database, from a menu, not the database's storage; it uploads even when
  nothing changed, and never deletes its temporary file.  It is the
  closest precedent, and its tests mock the external process
  (`tests/mock/MockRemoteProcess.cpp`, `RemoteHandler::setRemoteProcessFunc`).
- **Command line:** `keepassxc --pw-stdin <file>` reads one password line
  per file and unlocks before showing the window.  But KeePassXC is
  single-instance by default (`SingleInstance=true`): a second launch
  forwards the file names to the running instance and **exits at once**,
  without reading the password (`src/main.cpp:156-172`).  `--config` and
  `--localconfig` select the configuration files.
- **No Rust** in KeePassXC's build (no Cargo or Corrosion in its CMake
  files), and calling external programs has precedents (Remote Sync,
  `okon` for HIBP).
- **KeePassXC's AI rule:** a submission mostly written with generative AI
  must say so, with the service or model, in the pull request
  (`.github/CONTRIBUTING.md:78-80`).  No discussion is required before a
  pull request, but the issue tracker and Matrix `#keepassxc-dev` are
  offered for it.

## Specification

### Prerequisites on the yb side: done

- **Rip-safe replace** (spec 0031): saving the vault writes the new copy
  into free objects, head last, before freeing the old one; a YubiKey
  pulled out mid-save leaves the old or the new vault (invariant 0001).
  Needs room for one more copy of the vault (invariant 0004).
- **Integrity** (spec 0033): `yb fetch` refuses a vault whose signature
  does not verify (invariant 0006).
- **Exit statuses** (spec 0032): 2 when a blob is not found, 3 when the
  store is full (checked before writing); 1 for any other error.
- **Reads never write** (invariant 0002): opening a vault writes nothing.

- **PIN and payload on one standard input** (spec 0037): documents
  and tests what `yb --pin-stdin store` already does, so that a vault goes
  from KeePassXC's memory to the YubiKey without a file.

Nothing else is needed in yb for the mock-up.

### Naming

Blob names pair each vault with its optional master password by
extension:

| Blob | Content | Stored with |
|---|---|---|
| `<vault>.kdbx` | the vault, e.g. `Passwords.kdbx` | `--encrypted --no-compress` |
| `<vault>.passwd` | its master password, optional (G2) | `--encrypted` |

`<vault>` is any valid yb blob name stem.  Several vaults coexist on one
YubiKey (G8).  In v0 the master password is managed by hand with yb's
commands:

```shell
read -rs pw && printf '%s' "$pw" | yb store -n Passwords.passwd; unset pw
yb remove Passwords.passwd
```

One final newline is stripped when reading it, so that a password typed
into `yb store` and ended with Ctrl-D also works.

### Requirements on the YubiKey

Set up with `yb format` and the management key kept on the YubiKey,
unlocked by the PIN (the guided setup does this): every operation then
needs only the PIN.

### The mock-up in KeePassXC: databases on a device

KeePassXC learns to read and write a database **on a device** instead of
a file, with no copy of the vault on the host's disk.  The YubiKey,
through `yb`, is the first device; the design keeps the device side
behind one small interface, so that others could follow.

**Location.**  A device database is identified by a location string,
`yubikey:<serial>/<vault>.kdbx`, used wherever KeePassXC uses a file path
as an identity: tab and window titles, the recent-databases list,
per-database settings.

**One branch point.**  KeePassXC's format code already reads and writes
streams (`KdbxReader::readDatabase(QIODevice*, …)`,
`KdbxWriter::writeDatabase(QIODevice*, …)`).  `Database` gains a storage
backend, file or device, chosen by the location:

| | File (today) | Device |
|---|---|---|
| read | open the file | fetch the bytes from the device into memory, parse from a `QBuffer` |
| write | `QSaveFile`: temporary file, then rename | serialize into a `QBuffer`, send the bytes to the device (rip-safe on the device, spec 0031) |

Every other use of the path is either identity (works with the location
string) or a file-only feature, turned off for device databases; the
inventory below lists them.

**Read cache.**  `Database` keeps the encrypted KDBX bytes last read from
or written to the device, never anything decrypted.  Unlocking after a
lock decrypts the cache (KeePassXC re-reads the file there today): no
device access, no PIN.  Before using the cache, KeePassXC checks that the
vault on the device is unchanged (size and modification time, from
`yb ls -l`, without the PIN); otherwise it fetches it again.

**Write-through, after a short delay.**  Every save KeePassXC makes goes
to the device, and updates the cache once the device confirms.  Writes to
a YubiKey are slow, so a device database saves **5 seconds after the
last data change** (decided 2026-10-13): a burst of edits makes one
write.  Pending changes are written **at once** when the database is
locked or closed, and when KeePassXC exits or is asked to (SIGTERM,
logout, closing the window; KeePassXC already turns SIGINT, SIGTERM,
SIGHUP and SIGQUIT into a normal quit, `src/gui/Application.cpp:256-275`).  A process killed outright (SIGKILL, power
loss) loses at most the last 5 seconds of edits; the device keeps the
previous vault, whole (spec 0031).  KeePassXC's own per-database delay
counts in minutes (`autosaveDelayMin`), so the device delay is a timer of
its own.  For device databases, non-data changes alone never cause a save
(G7).  A failed write leaves the
database modified, so KeePassXC's handling of unsaved changes applies,
with a retry; the device keeps the old or the new vault.

**PIN.**  Asked when opening; held in zeroizing memory while the database
is unlocked (write-through needs it); dropped at lock and close, and
asked again at the next unlock if a fetch is needed (a changed vault) or
at the next save.

**Calling yb** (the device side, for the YubiKey).  Through `QProcess`, as
Remote Sync runs its commands: no shell, no file, the PIN on the first
line of standard input (`--pin-stdin`, spec 0037), never on the command
line or in the environment; outcomes from the exit status (0, 2 not
found, 3 store full, 1 anything else, with yb's message shown).

| Operation | Command | Standard input | Standard output |
|---|---|---|---|
| list vaults | `yb [--serial S] ls -l '*.kdbx'`, and `ls '*.passwd'` | — | names, sizes, times |
| check unchanged | `yb [--serial S] ls -l <vault>.kdbx` | — | size, time |
| fetch the vault | `yb --pin-stdin [--serial S] fetch -p <vault>.kdbx` | PIN | the vault |
| fetch the master password | `yb --pin-stdin [--serial S] fetch -p <vault>.passwd` | PIN | the password |
| store the vault | `yb --pin-stdin [--serial S] store --encrypted --no-compress -n <vault>.kdbx` | PIN, then the vault | — |

**Opening:** "Open from YubiKey…", next to "Open Database…":
1. the YubiKey: none to choose when one is connected; with several, the
   user gives its serial, passed as `--serial` and kept in the location;
2. the PIN;
3. the vault, from the list (those with a stored master password marked);
4. if `<vault>.passwd` exists, unlock with it; otherwise KeePassXC's usual
   unlock screen.

**Errors shown:** wrong PIN (tries left), PIN blocked, YubiKey absent or
removed, vault not found, not enough room on the YubiKey (with what a
save needs), and any other yb message as is.

**Command line.**  `keepassxc-cli` goes through the same `Database`
functions, so it opens and saves device locations too, asking for the
PIN on standard input (after the master password).  Not planned at
first; it makes the mock-up testable without a display, and scriptable.

### Inventory: where KeePassXC uses a database's path

Studied at `9e0f57a`, over `src/` (the command-line tool `keepassxc-cli`
goes through the same `Database` functions).  About 125 call sites:

| Kind | Sites | For a device database |
|---|---|---|
| Identity or display (titles, recent lists, settings keys, comparisons) | ~63 | works with the location string |
| Real file operations on the database | ~26 | a device branch, in the few functions below |
| File-only features (file watcher, backups, safe-save modes, Save As, relative paths) | ~32 | turned off or hidden |
| Not the database (key files, attachments, exports) | ~15 | unchanged |

**Branch points** (file:line at `9e0f57a`):
1. `Database::open(path, key, error)` (`src/core/Database.cpp:131`):
   get a `QIODevice` from the storage, a `QFile` or a `QBuffer` filled
   from the device, and keep the reader code as is.  Covers every read:
   tab creation, unlock, the re-reads at lock.
2. `Database::saveAs` / `performSave` (`Database.cpp:269`, `:358`): for a
   device, before the path is resolved (`:327`), serialize as the
   existing DirectWrite mode does (a `QBuffer`, `:442-454`) and send the
   bytes to the device; no watcher, permissions, backup or restore.
3. `Database::canonicalFilePath()` (`Database.cpp:709`): returns the
   location unchanged for a device (today it returns "" for anything
   that is not an existing file, which breaks deduplication, tooltips,
   settings headlines and the Secret Service collection name).
4. `DatabaseTabWidget::addDatabaseTab` (`src/gui/DatabaseTabWidget.cpp:156`):
   no native-separator conversion and no file-existence check for a
   device location (today: "Failed to open … does not exist").
5. Entry filters that drop non-files: command-line arguments
   (`src/main.cpp:147-152`), the second-instance message
   (`src/gui/Application.cpp:335-338`), databases reopened at start-up
   (`src/gui/MainWindow.cpp:677`).
6. A helper, `isDeviceLocation()`, for the file-only features: hide Save
   As, Save Backup and Remote Sync (`MainWindow.cpp:992-1001`); no file
   watcher (`Database.cpp:192`, `:349`); no backup or "disable safe
   saves" prompt (`src/gui/DatabaseWidget.cpp:2522-2534`, `:2610-2627`);
   no paths relative to the database's directory (`{DB_DIR}`,
   `src/core/Entry.cpp:1186`; KeeShare, `src/keeshare/ShareObserver.cpp:29`;
   SSH agent, `src/sshagent/KeeAgentSettings.cpp:445`); "last saved" from
   the device, not a file time (`src/core/DatabaseStats.cpp:21`).

**What the inventory changes in the design:**
- **Reads are more frequent than "open and unlock":** creating a tab
  reads the database's headers twice, locking twice more, unlocking once
  in full (`DatabaseWidget.cpp:101-103`, `:2137-2141`;
  `src/gui/DatabaseOpenWidget.cpp:249`, `:348`).  The read cache serves
  them all: one fetch per open, none at lock or unlock unless the vault
  changed on the device.
- **Every edit is a save:** with the defaults (auto-save after every
  change, no delay), each edit reaches `save()` about 150 ms later
  (`Database.cpp:1081-1088`, `DatabaseWidget.cpp:1852-1869`); hence the
  5-second device delay (see Write-through).
- **Non-data changes:** with `AutoSaveNonDataChanges` off, KeePassXC turns
  a non-data change into a data change (`DatabaseWidget.cpp:1893-1899`),
  hence a write; with it on, it saves silently at lock (`:2114-2117`).
  Neither suits a device: a device database never saves for non-data
  changes alone (G7).
- **Two uses of the YubiKey:** KeePassXC never accesses the YubiKey for
  the vault (everything goes through `yb`), but a vault may also use
  KeePassXC's own YubiKey challenge-response (OTP application, an
  existing feature, unchanged).  They coexist: over USB, KeePassXC skips
  PC/SC readers named "YubiKey" and uses the YubiKey's HID interface
  (`src/keys/drivers/YubiKeyInterfacePCSC.cpp:571`), while `yb` uses
  PC/SC (CCID); over NFC both use PC/SC in shared mode, each selecting its
  application.  The combination is redundant (the same YubiKey becomes a
  factor twice), which the documentation says.
- An unrelated existing bug: `DatabaseWidget::saveAs()` always returns
  false (`DatabaseWidget.cpp:2575`, `bool ok = false;` never set), so
  "Save As" never updates the recent-databases list.  Worth reporting to
  KeePassXC separately.

### Tests

- yb side: the invariants above, with their regression tests.
- KeePassXC side: unit tests of the YubiKey storage layer with a mocked
  `yb` process, following `tests/mock/MockRemoteProcess.cpp`: list, open,
  save only after data changes, no save after non-data changes, errors
  by exit status.
- On a real YubiKey 5 (2026-10-13), through `keepassxc-cli`: create a
  vault at `yubikey:/Demo.kdbx`, add an entry, read it back from a new
  process (fetched with the PIN), and refuse a wrong master password.
- By hand, daily ("eat your own dog food"): the author's vault, with
  measurements (sizes, fetch and store times, writes per week).

### Recovery (G4), by hand in v0

- **Backup:** `yb fetch <vault>.kdbx -o <file>` produces a standard KDBX
  file, still encrypted by the master password, which any KDBX
  application opens; or a second YubiKey: `yb --serial <S2> store
  --encrypted --no-compress -n <vault>.kdbx <file>`.
- **Restore:** store the backup onto a (new) YubiKey under the same name.

### Later, depending on the discussion with KeePassXC

- A C library wrapping `yb-core` (`extern "C"`, `cbindgen` header), for
  calls in-process instead of a subprocess; it would add a Rust-built
  dependency to KeePassXC's builds, and commit yb to a stable C
  interface.
- Machine-readable output (`--json`) in yb.
- Extending Remote Sync instead; or reading yb's on-card format in C++.
- A launcher outside KeePassXC, for users of an unmodified KeePassXC.
- Recovery reminders; managing the master password from KeePassXC.

## Plan

1. ~~Rip-safe replace in yb (spec 0031).~~ Done, with the integrity,
   exit-status and hardening specs 0032–0034, and spec 0037 (PIN and
   payload on one standard input).
2. Build the mock-up in a KeePassXC branch (`~/code/keepassxc`, branch
   `yb-device-storage`): built, unit-tested, tried on a YubiKey through
   `keepassxc-cli`; the GUI to try on a desktop.  Then use it daily;
   measure.
3. Open a **draft** pull request to KeePassXC, explicitly a mock-up for
   discussion, not for merging, stating the use of AI as their
   contribution guide requires; open a feature request linking it, and
   mention it on Matrix `#keepassxc-dev`.  Offer the C library as the
   alternative.
4. Discuss with the KeePassXC team what to do next.
5. (Optional, independent) the nixpkgs update carrying yb's new version.

## Open questions

- Windows (after the mock-up): device locations must escape
  `QDir::toNativeSeparators` (`DatabaseTabWidget.cpp:161`, `:889`;
  `MainWindow.cpp:1513`; `main.cpp:150`).

## References

- KeePassXC: https://keepassxc.org/ and https://github.com/keepassxreboot/keepassxc
  (studied at `develop`, commit `9e0f57a`).
- KDBX 4 format: https://keepass.info/help/kb/kdbx_4.html
- Specs 0031–0034; `docs/invariants/`.
- Spec 0028 — post-quantum protection of blobs.
- `docs/yubikey-nvm-internals.md` — measured PIV storage capacity.
