<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0046 — KeePassYB: KeePassXC With Databases on a YubiKey

**Status:** draft
**App:** the KeePassXC fork (`douzebis/keepassyb`, formerly `douzebis/keepassxc`), with yb's libyubiblob
**Implemented in:** <!-- YYYY-MM-DD, fill after implementation -->

## Problem

KeePassXC with databases stored on a YubiKey exists as a fork branch,
`feature/yubikey-storage`, on top of upstream `develop`.  Upstream will
not merge it: #13786 was closed, and the maintainers asked for fork-first
development.  Users need something they can install, not a branch to
build.

**What exists today:**

- the fork `douzebis/keepassxc`, whose `develop` is 5 commits behind
  upstream;
- `feature/yubikey-storage`, 4 commits, through libyubiblob;
- two superseded mock-up branches, `yb-device-storage` and
  `yb-libyubiblob`;
- the open personal PR #1;
- the upstream bug fix #13788 (Save As), still open, also carried in
  `feature/yubikey-storage`.

**What it lacks:**

- a release base: `develop` is not a release;
- its own identity: it calls itself KeePassXC and would share
  KeePassXC's settings, sockets and desktop ID;
- CI and releases.

It also stores the database **encrypted** on the YubiKey, so a blocked
PIN locks the user out of a database that the master key already
protects.  And it uses a stored master password (`<db>.passwd`) whatever
its protection.

## Goals

- G1. **A release line, `keepassyb`,** based on the latest upstream
  release that the code applies to: `2.8.0-beta1` now, then `2.8.0`
  when it ships.
- G2. **The fork kept current:**
  - the fork's `develop` follows upstream;
  - `feature/yubikey-storage` is rebased on it, and stays the reference
    for upstream (PR #1).
- G3. **The database is written to the YubiKey unencrypted, always,** so
  a locked YubiKey never locks the user out of it.  When the YubiKey is
  locked, the database is read without a PIN (spec 0044), once the user
  agrees.
- G4. **A stored master password is used only when it is safe:**
  `<db>.passwd` is used only if it is encrypted **and** the store is
  post-quantum.
  - Otherwise it is ignored, with a warning and an offer to delete it.
  - KeePassYB offers to store one only under the same conditions.
- G5. **Its own identity,** following open-source etiquette towards
  KeePassXC (S5): name, icon, IDs, settings and sockets, links, and
  disclaimers.  It can be installed next to KeePassXC without either
  disturbing the other.
- G6. **CI and releases on GitHub:**
  - CI on Linux, macOS and Windows on each push;
  - on a tag, an AppImage, a Windows zip and a macOS disk image, behind
    an approval gate, as for yb (spec 0043).
  - Not on crates.io, which is for Rust crates.

## Non-goals

- Merging into upstream KeePassXC.  The fork stays offered (PR #1, the
  Ideas post) but does not wait.
- Translations of the new strings: English only at first.
- Signed and notarized macOS builds, signed Windows builds: later, with
  yb's signing (spec 0041).
- A Microsoft Store, Flathub or Snap listing.
- Browser integration, the Secret Service, and update checks (S5.4).

## Specification

### S1. Repository and branches

| Branch | Base | Role |
|---|---|---|
| `develop` | upstream `develop`, fast-forwarded | mirror |
| `feature/yubikey-storage` | rebased on `develop` | the upstream-facing branch, PR #1 |
| `keepassyb` | tag `2.8.0-beta1` | **the release line, made the fork's default branch** |
| `fix/save-as-return-value` | unchanged | upstream #13788; deleted once merged |
| `yb-device-storage`, `yb-libyubiblob` | — | superseded mock-ups: tagged `archive/…`, then deleted |

**The `keepassyb` branch:**

1. starts at `2.8.0-beta1`;
2. gets `feature/yubikey-storage`'s 4 commits, cherry-picked (they apply
   cleanly);
3. then this spec's changes, as separate commits.

**Upstream releases:** when upstream releases (`2.8.0`, then later
ones), `keepassyb` is rebased onto the new tag, never onto `develop`.
The release tags stay as they are.

**The repository is renamed** `douzebis/keepassxc` → `douzebis/keepassyb`
(decided 2026-10-17), in step 1.
- GitHub redirects the old URLs (web, git, API), and the repository
  stays a fork of `keepassxreboot/keepassxc`, so PR #1 and the
  cross-references keep working.
- The local remotes are updated to the new URL.
- yb's `contrib/keepassxc/README.md` and `contrib/keepassxc/shell.nix`
  are updated to the new name and URL.

**History rewriting:** every rebase checks `git stash list` first, and
force-pushes only the branch rebased, with `--force-with-lease`.

### S2. Storing the database unencrypted

- **Saving:** every database is saved to the YubiKey unencrypted
  (`yubiblob_store` flags `0`).  A KDBX file is already encrypted by its
  master key, and compressed, so there is no compression either.
- **Existing databases** stored encrypted are read as before (PIN).  On
  their next save they are rewritten unencrypted, and KeePassYB says so
  once.
- **Opening:** `yubiblob_fetch` as today.  If it fails because the
  YubiKey is locked, KeePassYB asks:
  > The YubiKey is locked (…).  Open the database anyway?  Its content
  > is protected by your master password; the YubiKey's own integrity
  > check will be skipped.

  With Yes, it reads with `yubiblob_fetch_unencrypted` (spec 0044).
  "Locked" means `PIN_BLOCKED`, `REPLUG`, `FEW_PIN_ATTEMPTS`,
  `NO_CREDENTIAL` or `NO_FIDO2_ACCESS`.
  - The database then opens read-only.  Saving to a locked YubiKey
    would fail anyway; "Save As" to a file works.
  - **KDBX 4** databases authenticate every block with an HMAC keyed by
    the master key, so a modified file fails to open.
  - **KDBX 3.1** databases have no such MAC: AES-CBC, a header hash and
    "stream start bytes" catch some changes, not all.  The fallback is
    allowed for them too (decided 2026-10-17), with a stronger warning:
    > This database uses the older KDBX 3.1 format, which does not fully
    > detect changes to its content.  Without the YubiKey's check, a
    > modified database might open without notice.  Open it anyway?
    > (To avoid this, convert it: Database settings → Encryption →
    > KDBX 4.)
- **Legacy stores:** an unencrypted database never needs the PIN to
  open, so the fallback is never needed there.

### S3. The stored master password (`<db>.passwd`)

**When opening `<db>`, its `<db>.passwd` is used only if:**

1. the blob is encrypted (`yubiblob_blob_info_t.encrypted`), **and**
2. the store is post-quantum (`yubiblob_store_info_t.kind ==
   YUBIBLOB_KIND_POST_QUANTUM`).

Reading it then takes the FIDO2 PIN and a touch.  The FIDO2 PIN plus the
YubiKey thus replace typing the master password.

**Otherwise it is ignored,** and KeePassYB says, once per database:

> `<db>.passwd` on this YubiKey is not used: it is stored unencrypted
> (anyone holding the YubiKey can read it) / in a legacy store
> (classical encryption).  Delete it?

Deleting needs the store's PIN; it is the user's choice.

**Storing:** the database settings offer "Remember the master password
on this YubiKey" only on post-quantum stores.  It writes `<db>.passwd`
encrypted.  The option is absent elsewhere.

**Windows:** post-quantum stores are not supported there yet (spec 0041
phase 2).  So no `.passwd` is ever used on Windows until they are, and
the option is not offered.

### S4. Name

**KeePassYB**:

- it is not taken: no GitHub repository or account, nothing on PyPI or
  crates.io, no Flathub ID, no web results (checked 2026-10-17);
- it follows the convention of independent KeePass-family apps
  (KeePassDX, KeePassium);
- it stays clear of "KeePassXC", the upstream team's product name, which
  they have defended (the copycat Microsoft Store listing).

No KeePassXC trademark policy was found.  The maintainers are told of
the name (S5.7).

### S5. Identity and etiquette

#### S5.1 Name and IDs

| Item | KeePassXC | KeePassYB |
|---|---|---|
| Application name (`setApplicationName`) | `KeePassXC` | `KeePassYB` |
| Desktop ID (`setDesktopFileName`, `.desktop`, AppStream) | `org.keepassxc.KeePassXC` | `io.github.douzebis.KeePassYB` (decided 2026-10-17) |
| Executables | `keepassxc`, `keepassxc-cli`, `keepassxc-proxy` | `keepassyb`, `keepassyb-cli` (no proxy, S5.4) |
| macOS bundle | `KeePassXC.app`, `org.keepassxc.keepassxc` | `KeePassYB.app`, `io.github.douzebis.keepassyb` |
| Windows | `KeePassXC.exe` | `KeePassYB.exe` |
| polkit policy (Linux) | `org.keepassxc.KeePassXC.policy` | renamed likewise |

#### S5.2 Settings, data and single instance

These follow the application name:

- the configuration files (`~/.config/keepassyb/`, and the Windows and
  macOS equivalents);
- the cache and data folders;
- the single-instance lock and the local socket.

Every place that hard-codes "keepassxc" for them is changed.  A test
checks that KeePassYB never opens KeePassXC's configuration file.  Both
apps can then run at the same time, each with its own settings.

#### S5.3 Icon

- A **new icon** in `share/icons/application/…/apps/keepassyb*.svg` and
  the macOS and Windows equivalents.
- It is visibly distinct from KeePassXC's: a different shape and colors.
  A key with a YubiKey-like token is one idea.  It is **not** a recolor
  of their logo.
- KeePassXC's branding files are not used for KeePassYB's identity.

#### S5.4 Features off

These are switched off in KeePassYB's builds (CMake options):

- **`KPXC_FEATURE_BROWSER`:** the browser extension talks to the native
  messaging host `org.keepassxc.keepassxc_browser`.  Two apps answering
  to it would fight, and the official extension is KeePassXC's.
- **`KPXC_FEATURE_FDOSECRETS`:** only one application can own the
  `org.freedesktop.secrets` D-Bus name.
- **`KPXC_FEATURE_UPDATES`:** it checks KeePassXC's releases.

#### S5.5 Words and links

- **About dialog, window title, tray tooltip, desktop entry, release
  notes:** "KeePassYB".  The About dialog says: "KeePassYB is an
  unofficial fork of KeePassXC that can keep databases on a YubiKey
  (yb). It is not affiliated with or endorsed by the KeePassXC Team.
  Report problems to https://github.com/douzebis/keepassyb/issues, not
  to KeePassXC."
- **"Report a bug" and "Request a feature"** point to the fork's issues.
  The fork enables Issues.
- **The donation links** are removed.
- **Documentation links** stay KeePassXC's, labeled "KeePassXC
  documentation".
- **Other strings** (about 400 mentions of "KeePassXC" in sources, many
  in copyright headers): only the **identity points** are changed. These
  are the places where the name is shown to users as the name of the
  running application:
  - the window title, the About dialog, the tray tooltip;
  - the desktop menu entry and AppStream metadata;
  - the macOS menu bar and bundle name, the Windows executable and file
    properties;
  - notification titles, the command-line `--version` and `--help`
    headers;
  - release notes.

  Sentences that mention KeePassXC inside dialogs and help texts stay as
  they are (decided 2026-10-17), to keep the diff small and the
  translations intact.  For example "KeePassXC-Browser", or settings
  descriptions.

#### S5.6 Licenses and credits

- GPL-2.0/3.0 as upstream.  `COPYING` and every copyright header are
  unchanged.
- New files carry our copyright and the GPL notice.
- The README is replaced by KeePassYB's. It credits KeePassXC, explains
  the fork, links upstream, and says where to report problems.

#### S5.7 Telling the maintainers

- The planned combined comment on #13786 and the Ideas post announce
  KeePassYB under that name.
- They ask whether the name or anything in S5 bothers them, and S5 is
  adjusted if so.
- Issues filed with upstream are never about KeePassYB.

### S6. CI

`.github/workflows/keepassyb.yaml` on the `keepassyb` branch, on push and
pull request:

- **Linux** (ubuntu-latest):
  - KeePassXC 2.8's build dependencies, as its `INSTALL.md` lists them,
    Qt 6 included;
  - libyubiblob built from yb's crates with cargo-c, at a pinned yb
    version;
  - build, unit tests (`TestDeviceStorage` against a simulated YubiKey,
    `YB_FIXTURE`), and the GUI tests that do not need a display.
- **macOS** (macos-15): Homebrew dependencies; build and unit tests.
- **Windows** (windows-latest):
  - vcpkg, per KeePassXC's `vcpkg.json`;
  - libyubiblob from yb's release zip (spec 0043), with its SHA-256
    pinned;
  - build and unit tests.

**Upstream's workflows:** on `keepassyb`, they are restricted to the
upstream repository (`if: github.repository ==
'keepassxreboot/keepassxc'`), so they do not run in the fork.  This is a
one-line change per workflow.

### S7. Releases

**Tags:** `v<upstream>-yb.<n>`, e.g. `v2.8.0-beta1-yb.1`.  KeePassYB's
version string is the same.

**The release workflow** (`keepassyb-release.yaml`) follows yb's
`publish.yaml`:

1. A pushed tag runs the build jobs:
   - **Linux:** an AppImage, x86-64;
   - **Windows:** a portable zip, with `yubiblob.dll`;
   - **macOS:** a disk image, arm64, unsigned (Gatekeeper warns).
     KeePassXC ships separate arm64 and x86_64 images; KeePassYB ships
     arm64 only for now (decided 2026-10-17).
2. Each produces `SHA256SUMS` lines and a provenance attestation.
3. **`publish`** runs in the fork's `github-release` environment (your
   approval, `v*` tags only). It creates the release, with the notes
   from the fork's `CHANGELOG-keepassyb.md`, and uploads the files.
4. **Release notes** say:
   - "unofficial fork of KeePassXC <upstream version>";
   - what yb version is inside;
   - Windows: legacy stores only.

The **one-time setup** is the same as yb's (spec 0043 S6), in
`douzebis/keepassyb`.

### S8. Order of work

1. **Fork upkeep (G2):**
   - fast-forward `develop`;
   - rebase `feature/yubikey-storage` and force-push it (PR #1 follows);
   - archive the mock-ups;
   - rename the repository, and update yb's `contrib/keepassxc/`.
2. **yb:** spec 0044 (`--checksum-only`, libyubiblob 0.3.0), released.
3. **`keepassyb` branch:** from `2.8.0-beta1`, with the 4 commits; then
   S2, S3, S5.
4. **CI (S6),** then the release workflow and a dry run (S7).
5. **The README and About text; the message to the maintainers
   (S5.7).**
6. **First release:** `v2.8.0-beta1-yb.1`.

## Invariants

The fork has no invariants directory.  Its guarantees are tested in
`tests/TestDeviceStorage.cpp`:

- a saved database is unencrypted on the YubiKey;
- a `.passwd` that is unencrypted, or in a legacy store, is never read;
- KeePassYB's configuration path never equals KeePassXC's.

yb's own invariants (0001, 0002, 0006 as amended by spec 0044) apply to
what libyubiblob does.

## Open questions

None.  Decided 2026-10-17:

- the repository is renamed `douzebis/keepassyb`;
- the fallback is allowed for KDBX 3.1, with a stronger warning;
- only the identity points are renamed;
- the desktop ID is `io.github.douzebis.KeePassYB`;
- macOS is built for arm64 only.

## References

- [spec 0043](0043-windows-phase-1-legacy-stores-ci-and-preview-releases.md):
  the release pattern, libyubiblob for Windows.
- [spec 0044](0044-reading-unencrypted-blobs-without-the-pin.md):
  `yubiblob_fetch_unencrypted`.
- [spec 0040](0040-keepassxc-save-as-return-value.md): upstream #13788.
- [spec 0039](0039-c-api.md): libyubiblob.
- `contrib/keepassxc/README.md`; keepassxreboot/keepassxc#13786 and
  #13788; douzebis/keepassxc#1.
