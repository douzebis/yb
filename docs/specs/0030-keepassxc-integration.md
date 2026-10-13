<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0030 — KeePassXC Integration

**Status:** draft
**App:** yb
**Implemented in:** <!-- YYYY-MM-DD, fill after implementation -->

> **Draft.**  Goals, feasibility and a first design, based on a study of
> KeePassXC's `develop` branch (commit `9e0f57a`, 2026-09-22; file
> references below are to that tree).  Not ready for implementation: it
> depends on spec 0031 (rip-safe replace) and on the open questions
> below.  The KeePassXC part (path 2) is a proposal to discuss with its
> maintainers, not a commitment on their side.

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
  writes to the card's flash rare.  Path 1 reaches it only partly (see
  "Saves without user edits"); path 2 reaches it fully.
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
- **Syncing between several YubiKeys**, or between a YubiKey and a vault
  file elsewhere, beyond what recovery (G4) needs.
- **Post-quantum protection**, handled by spec 0028; this spec only
  records how the integration interacts with it.
- **A KeePassXC plugin.**  KeePassXC has no plugin interface (no
  `QPluginLoader`, `dlopen` or `Q_PLUGIN_METADATA` in `src/`); anything
  inside KeePassXC is an upstream change, decided by its maintainers.
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
- A save of 10 KB through PC/SC takes about a second (to be measured):
  acceptable at lock or exit, not on every change.

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
tell a real edit from a collapsed group.  Consequence: path 1 writes to
the YubiKey after such sessions; only path 2, which sees KeePassXC's own
"data changed" signal, can skip non-data changes (G7).

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
- **The working copy on the host** is the encrypted KDBX file, as with
  KeePassXC today, but in a private RAM-backed directory, deleted at the
  end of the session.
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

### Prerequisite on the yb side: rip-safe replace (spec 0031)

Today `yb store` over an existing blob is not interruption-safe: it
requires room for the new blob, but frees the old blob's objects in
memory first, may allocate the new chunks into them, and writes changed
objects in index order (`yb-core/src/orchestrator/mod.rs:86-106`,
`yb-core/src/store/mod.rs:485-535`).  A YubiKey pulled out mid-save can
lose both versions.  Spec 0031 (to be written) makes a replace write the
new chunks into objects outside the old chain, write the new head last,
and only then free the old chain, with a rule for which copy wins if both
are found after an interruption.  Path 1 may be prototyped before 0031
lands, but must not be offered to anyone else until it does.

### Naming

Blob names pair each vault with its optional master password by
extension:

| Blob | Content | Stored with |
|---|---|---|
| `<vault>.kdbx` | the vault, e.g. `Passwords.kdbx` | `--no-compress` |
| `<vault>.passwd` | its master password, optional (G2) | default (encrypted) |

`<vault>` is any valid yb blob name stem.  Several vaults coexist on one
YubiKey (G8).

In v0, the master password is managed by hand with yb's existing
commands, e.g.:

```shell
read -rs pw && printf '%s' "$pw" | yb store -n Passwords.passwd; unset pw
yb remove Passwords.passwd
```

(`read -rs` keeps it out of the shell history and off the screen;
`printf '%s'` stores no trailing newline.  The integration strips one
final newline anyway, so that a password typed into `yb store` and ended
with Ctrl-D also works.)

### Requirements on the YubiKey

- Set up with `yb format` with its management key kept on the YubiKey,
  unlocked by the PIN (yb's guided setup does this): every operation of
  the integration then needs only the PIN.
- The PIN is passed in memory (library) or on standard input
  (`--pin-stdin`, command), never as a command-line argument or in the
  environment.

### The vault operations, defined once in yb-core

yb is two crates: `yb-core`, a library (published on crates.io), and
`yb`, the command-line tool built on it.  The integration needs a small
set of operations, defined once in `yb-core` and exposed both ways
(see "How KeePassXC calls yb"):

| Operation | Purpose |
|---|---|
| list vaults | blobs ending in `.kdbx`, with size and modification time, and whether `<vault>.passwd` exists |
| free space | bytes left, and whether a vault of a given size can be replaced in place (all blobs plus one more copy of it) |
| fetch | the vault, and the master password if present |
| store | the vault, rip-safe (spec 0031), uncompressed; fails before writing if it does not fit |
| remove | a vault and its master password |

Errors are distinguished, not just messages: wrong PIN (with tries
left), PIN blocked, YubiKey absent or removed during the operation, not
enough room, blob not found, store damaged.

### Path 1 — `yb-keepassxc`, copy in and out (prototype)

A command shipped with yb (a script at first, a `yb` subcommand if it
proves itself): `yb-keepassxc [--serial S] <vault>`.

1. **Recover first.**  If a working directory of a previous session for
   this vault is left (see 7), offer to store it, discard it, or stop.
2. **PIN.**  Ask for the YubiKey PIN once (terminal or graphical prompt),
   keep it in memory for the session.
3. **Working directory.**  Create a private directory, mode 0700, in
   `$XDG_RUNTIME_DIR` (RAM-backed on Linux with systemd); refuse to run if
   no RAM-backed location is available, unless the user explicitly
   accepts a disk location.
4. **Fetch.**  Fetch `<vault>.kdbx` into `<dir>/<vault>.kdbx`, and
   `<vault>.passwd` into memory if it exists.  Record the SHA-256 of the
   vault as fetched.
5. **Run KeePassXC** in its own process, waiting for it to exit:
   - with a private configuration: `--localconfig <dir>/local.ini`, and
     `--config` pointing to a copy of the user's configuration with these
     overrides: `SingleInstance=false` (so this process does not hand the
     vault to an already-running KeePassXC and exit),
     `BackupBeforeSave=false`, `OpenPreviousDatabasesOnStartup=false`,
     `GUI/MinimizeOnClose=false` and no tray icon (so closing the window
     ends the process), and no recent-databases list (so the temporary
     path does not leak into the user's settings);
   - with `--pw-stdin` and the master password on its standard input if
     `<vault>.passwd` exists; otherwise without it, and the user types the
     master password in KeePassXC's unlock screen.
6. **Store back.**  When KeePassXC exits, compare the vault's SHA-256 with
   the one recorded at fetch.  If it differs, store it (rip-safe, spec
   0031) and log the store (time, size, duration) for the measurements of
   G6.  If it fails (YubiKey removed, not enough room), keep the working
   directory and say so.
7. **Clean up.**  Delete the working directory after a successful store or
   when nothing changed.  A directory left behind by a crash survives in
   RAM until the session ends (logout or reboot), and step 1 offers to
   recover it.

Known limitations, documented: the vault reaches the YubiKey only when
KeePassXC exits; non-data changes (e.g. a group expanded) cause a write
(see "Saves without user edits"); the first unlock of a vault may add an
identifier and cause one write; KeePassXC's own settings are a copy for
the session (changes to them are not kept).

### Path 2 — vault on the YubiKey inside KeePassXC (proposal)

A mock-up for discussion with KeePassXC's maintainers, not a final
design; their preferences decide.  The proposal keeps KeePassXC's
file-based model and adds a storage layer around it:

- **Opening:** "Open from YubiKey…" lists the vaults on the connected
  YubiKeys, asks for the PIN, fetches the chosen vault into a private
  working file (as in path 1), and opens it as a database marked as
  YubiKey-backed (YubiKey serial, blob name).  If `<vault>.passwd`
  exists, KeePassXC unlocks with it; otherwise it shows its usual unlock
  screen.
- **Saving:** KeePassXC keeps saving to the working file as usual (safe
  save, auto-save).  The YubiKey is written only when the database is
  locked, closed, or KeePassXC exits, **and** a data change happened
  since the last write to the YubiKey: KeePassXC's own modified signal,
  ignoring non-data changes (G7, fully).
- **Recent databases:** a YubiKey-backed database appears as
  `YubiKey <serial>: <vault>`, never by its working-file path.
- **Working file:** in a private RAM-backed directory, deleted when the
  database is closed.

### How KeePassXC calls yb

Two ways, offering the same operations (see "The vault operations"):

1. **The `yb` command,** run through `QProcess` as Remote Sync does: PIN
   on standard input, machine-readable output (`--json`, to be added) for
   listing and free space, distinct exit codes for the errors above.
   Nothing changes in KeePassXC's build; the user installs `yb`, as for
   `okon`.  Tested in KeePassXC with a mocked process
   (`tests/mock/MockRemoteProcess.cpp` pattern).
2. **A C library,** a new crate (e.g. `yb-capi`) wrapping `yb-core`:
   `extern "C"` functions with a `cbindgen`-generated header, built as a
   shared or static library.  No subprocess or output parsing, the PIN
   stays in KeePassXC's memory, typed error codes, one PC/SC session per
   operation instead of one process.  Costs: KeePassXC's build would
   depend on a Rust-built library (there is no Rust in it today), either
   built by them (a Rust toolchain in their Windows, macOS and Linux
   release pipelines) or installed from distributions and bundled in
   their Windows and macOS installers; and yb commits to a stable C
   interface (versioning, memory ownership, error codes), which
   `yb-core`'s Rust API (e.g. `anyhow` errors) is not designed for today.
   Licensing is no obstacle: MIT code fits in KeePassXC's GPL-2/GPL-3
   code base.

The mock-up uses the command (1): the easiest for the maintainers to try,
with no build change.  The library (2) is offered as the in-process
alternative in the discussion; their build constraints decide.  Because
the operations are defined once in `yb-core`, either choice costs no
rewrite.  Further alternatives for them to weigh: extending Remote Sync
itself (automatic download on open, upload on lock only if data
changed), or reading yb's on-card format directly in C++ over PC/SC,
reusing the `winscard` patterns of `YubiKeyInterfacePCSC.cpp`.

### Recovery (G4)

- **Backup:** `yb fetch <vault>.kdbx -o <file>` produces a standard KDBX
  file, still encrypted by the master password; it opens in any KDBX
  application.  A second YubiKey holds a copy with `yb --serial <S2>
  store --no-compress`.
- **Reminder:** path 1 and path 2 remind the user when the vault on the
  YubiKey has changed since the last backup they declared (e.g. a
  `<vault>.backup` blob holding the date and SHA-256 of the last backup).
- **Restore:** storing the backup file onto a (new) YubiKey with the same
  name.

### Tests

- yb side: spec 0031's interruption tests (a simulated card failing after
  N writes during a replace); the vault operations with the simulated
  card (`YB_FIXTURE`); path 1 with a stub in place of `keepassxc`,
  checking the fetch → compare → store-only-if-changed logic and crash
  recovery.
- KeePassXC side (path 2 mock-up): unit tests with a mocked `yb` process,
  following `tests/mock/MockRemoteProcess.cpp`.

## Plan

1. (Optional) Wait until the current yb update is merged into nixpkgs;
   independent work.
2. Spec and implement 0031 (rip-safe replace) in yb.
3. Add the vault operations to `yb-core`, and their machine-readable
   form to the `yb` command.
4. Build path 1 (`yb-keepassxc`); use it daily, measure (sizes, fetch and
   store times, write frequency, how often non-data changes cause a
   write).
5. Open a **draft** pull request to KeePassXC with a minimal path 2
   (calling the `yb` command), explicitly a mock-up for discussion, not
   for merging, stating the use of AI as their contribution guide
   requires; open a feature request issue linking it, and mention it on
   Matrix `#keepassxc-dev`.  Offer the C library as the alternative.
6. Discuss with the KeePassXC team what to do next, with the prototype,
   the mock-up and the measurements as the basis.

## Open questions

- How much store space is left after `yb format` with the default object
  count, for vault-sized blobs?  Confirm the 32 KB example fits with room
  to grow.
- Write cost: time of a fetch and a store of 2, 10 and 22 KB.
- The machine-readable form of the operations: `--json` on existing
  commands (`yb ls`, `yb fsck`), or a dedicated `yb vault …` group?
- How does `--pin-stdin` combine with `yb store` reading the payload from
  standard input?  The integration stores from a file, avoiding the
  question; to be confirmed and documented.
- Path 1's configuration copy: which other KeePassXC settings must be
  overridden or preserved (browser integration, SSH agent, Secret
  Service)?  Running a second KeePassXC beside the user's usual one may
  conflict with browser integration's socket.
- Recovery reminder: is a `<vault>.backup` blob the right place for the
  last-backup record?
- After v0: should the integration offer to add or remove the master
  password, and show its trade-offs at that moment?

## References

- KeePassXC: https://keepassxc.org/ and https://github.com/keepassxreboot/keepassxc
  (studied at `develop`, commit `9e0f57a`).
- KDBX 4 format: https://keepass.info/help/kb/kdbx_4.html
- Spec 0028 — post-quantum protection of blobs.
- Spec 0031 — rip-safe replace (to be written).
- `docs/yubikey-nvm-internals.md` — measured PIV storage capacity.
- README — store layout and capacity.
