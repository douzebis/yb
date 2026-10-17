<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0041 — Windows: Full Support and a Release Channel

**Status:** draft
**App:** yb, yb-core, yubiblob (repo-wide)
**Implemented in:** <!-- YYYY-MM-DD, fill after implementation -->

## Problem

yb is not shipped for Windows.  Today:

- **yb-core and libyubiblob** build on Windows, legacy stores only: the
  `fido2` module and everything post-quantum are compiled out
  (`#[cfg(not(windows))]`, spec 0028 D9 "Exception, for now").  The CI
  job `windows-libyubiblob` runs libyubiblob's tests and builds the C
  library with cargo-c, against the simulated YubiKey.
- **The `yb` command** is neither built nor tested on Windows.
- **There is no Windows release:** no binaries, no signing, no package
  manager entry.  `cargo install yb` is the only route, and it needs the
  MSVC build tools.

Two needs push for more:

1. **keepassxc-yb**, the planned KeePassXC fork, will be built for Windows,
   on libyubiblob.  It needs post-quantum stores there too: the guided
   format recommends them, and a store made on Linux must open on Windows.
2. **Users of the `yb` command on Windows**, for scripts and backups.

The hard part is FIDO2.  Since Windows 10 1903, a process that is not
elevated cannot open a FIDO security key over HID.  It must go through
Windows' WebAuthn API (`webauthn.dll`).  That API shows its own dialogs
for choosing the key, typing the PIN and touching.  So on Windows:

- yb would not receive the FIDO2 PIN;
- yb cannot list the FIDO2 devices;
- yb cannot send Yubico's vendor command, which reads the serial for
  pairing.

It is also not known yet whether the API gives the **raw `hmac-secret`
output for yb's own salts**.  It may give only the WebAuthn PRF
derivation: the salts hashed with a "WebAuthn PRF" prefix first.  That
would make stores made elsewhere unreadable.

## Goals

**Part 1: full support**

- G1. **`yb` on Windows:** every command, on legacy and post-quantum
  stores, x86-64 first.
- G2. **Stores are portable across systems:** a store made on Linux or
  macOS opens on Windows, and the reverse, with the same format and
  without migration (spec 0028 D9 lifted).
- G3. **No administrator rights** are needed, for yb or for programs
  using libyubiblob.
- G4. **The same security guarantees:**
  - the invariants of `docs/invariants/` hold on Windows;
  - every deviation is named here, decided, and documented for users
    (see "Deviations on Windows").
- G5. **libyubiblob on Windows:** post-quantum stores, with the same
  interface as on Linux (0.x: changes allowed only where Windows forces
  them, listed here).
- G6. **CI on Windows:**
  - the workspace's tier-1 tests;
  - the in-process FIDO2 emulator tests;
  - the build of `yb.exe` and of the C library.

**Part 2: a release channel**

- G7. **Every yb release (a `v*` tag) also publishes Windows artifacts,**
  built by CI from the tagged commit:
  - `yb.exe`;
  - libyubiblob (DLL, import library, header);
  - checksums;
  - build provenance.
- G8. **Users install and upgrade** with one command (winget) or a
  download, without SmartScreen warnings once the signing (D8) is in
  place.
- G9. **Developers can build from source** with documented steps
  (libfido2 from vcpkg).

## Non-goals

- Bash completion on Windows.  Spec 0036's completer is bash-specific;
  PowerShell completion may come later, in its own spec.
- Manual pages on Windows: `yb --help` and the website cover it.
- The command-line test suite (`yb_cli_tests`) on Windows: it stays in
  the NixOS VM.
  - Windows runs the tier-1 tests and the in-process emulator tests.
  - The emulator's Unix-socket server is not ported.
- Hardware tests in CI: Windows checks on a real YubiKey are manual (see
  "Tests").
- An MSI installer for yb: a portable zip is enough for a command-line
  tool.  An MSI for keepassxc-yb belongs to that project.
- Windows on Arm (aarch64): later, once x86-64 works (open question Q5).
- Chocolatey, the Microsoft Store, MSYS2.
- Crash-dump hygiene (Windows Error Reporting may capture memory with
  secrets).  It is the Windows counterpart of spec 0034's deferred
  core-dump suppression, and is handled with it.
- Using libfido2's direct-HID backend when the process happens to be
  elevated.  One path only (D1).

## Specification

### Part 1: full support

#### D1. FIDO2 through Windows' WebAuthn API

On Windows, yb-core reaches FIDO2 only through libfido2's Windows Hello
backend.  That backend wraps `webauthn.dll`, and its device path is
`windows://hello`.  The rest of yb-core keeps one code path:

- the same `fido2::Device`;
- the same `hmac_secret`, `make_credential` and `find_credential`;
- the same descriptor and HKDF labels.

What differs is confined to:

- `fido2::pairing`;
- the PIN: Windows asks for it;
- the touch notifier: Windows shows its own dialog.

**Step 0 is a spike, and it decides whether D1 is possible (go/no-go).**
On a Windows 11 machine with the test YubiKey, a small program linked
with libfido2's Windows Hello backend must:

1. create a non-resident ES256 credential with `hmac-secret` and
   `credProtect` level 3, RP ID "yb", user verification required;
2. get an assertion with **two raw salts** in one touch, and check that
   the outputs equal those of the same credential on Linux, for the same
   salts (the cross-check of G2);
3. refuse, or never use, a platform authenticator (Windows Hello on the
   TPM), so that a post-quantum store is bound to the YubiKey and not to
   the PC.

The spike also records:

- what Windows' dialogs say;
- how a cancel is reported;
- whether the PIN attempts left are shown;
- the minimum Windows version (WebAuthn API version) that passes.

If the spike fails:

- on point 2, only PRF outputs are available, or the outputs differ;
- or on point 3.

Then post-quantum stores stay unavailable on Windows (status quo for
them), the rest of this spec proceeds, and the choice goes back to the
user (open question Q1).

#### D2. Pairing on Windows

Windows does not list FIDO2 devices to applications.  Instead, its dialog
asks to touch a key, which is spec 0028's touch selection, done by
Windows.  The rules:

- **`yb format --post-quantum`** requires exactly one YubiKey on the PIV
  side.  It says "Touch the YubiKey with serial N" before Windows'
  dialog.
  - The risk: another FIDO2 key is touched.  The credential would then be
    on the wrong key, and the store would need both keys plugged in.
  - So the guided format warns to plug in only that YubiKey.
  - Open question Q2: can yb check it?
- **Fetch, store, remove, fsck and `management-key set`** use the
  descriptor's credential ID as the allow list.  Touching any other key
  fails with "no credential", so nothing is read or written wrongly.

#### D3. The FIDO2 PIN on Windows

Windows' dialog asks for the PIN.  The consequences:

- **yb never sees the FIDO2 PIN:**
  - `--pin-stdin` and `YB_PIN` apply to the PIV PIN only;
  - for a post-quantum store, yb says so if they are given;
  - libyubiblob's `pin` argument is ignored for a post-quantum store on
    Windows. It may be empty; nothing is written.
- **Non-interactive use of post-quantum stores is impossible on
  Windows:** scripts must use legacy stores there.  This is documented.
- **The low-attempts rule (spec 0028 D10) cannot be enforced by yb.**
  Whether Windows shows the attempts left is recorded by the spike, and
  the documentation warns either way.
- **`yubiblob_last_pin_tries()`** returns -1 for the FIDO2 PIN on
  Windows.

#### D4. Touch notification on Windows

- **yb:** `Context::on_touch` is still called, but yb's own "Touch your
  YubiKey…" message is not printed on Windows, because Windows' dialog
  says it.
- **libyubiblob:** the callback is still called, so keepassxc-yb can show
  its own status, e.g. "Waiting for the YubiKey".
- **The dialog's parent window:** libfido2's Windows Hello backend needs
  a parent window for the dialog.
  - For `yb.exe` in a console: the console window.
  - For libyubiblob: the foreground window.
  - Open question Q3: whether libyubiblob 0.3 should take a window
    handle.

#### D5. Building with libfido2 on Windows

- **Where libfido2 comes from:** yb-core's build script finds it through
  pkg-config on Unix; on Windows (MSVC), through vcpkg.
  - The triplet is `x64-windows-static-md`: libfido2, libcbor, zlib and
    OpenSSL's libcrypto are linked statically, the C runtime
    dynamically.
  - So `yb.exe` and `yubiblob.dll` need no extra DLL.
  - `YB_FIDO2_LIB_DIR` overrides the search, for Yubico's prebuilt
    libfido2.
- **When libfido2 is missing,** the build fails with the same message as
  on Unix, plus the vcpkg command.
- **The `cfg(not(windows))` gates of spec 0028 are removed:**
  - post-quantum code builds everywhere;
  - only pairing, the PIN and the touch message (D2–D4) have Windows
    branches;
  - `fido2::socket` stays Unix-only (test fixture).

#### D6. Other Windows details of the `yb` command

- **Reader names and the device picker:** WinSCard's reader names differ
  from pcsc-lite's.  The picker shows serials, as it does today.
- **Exit statuses:** unchanged (0 to 4).
- **Paths:** `fetch -o` writes with the default permissions of the user's
  profile.  No Unix modes are used today, so nothing changes.
- **Console:**
  - PIN prompts go through `rpassword`, which works on the Windows
    console;
  - colors through `crossterm`;
  - output is UTF-8 (`SetConsoleOutputCP(65001)` at start), so that blob
    names print correctly.
- **Line endings:** `fetch` writes bytes as stored, with no CRLF
  translation.  A test covers it.

#### Deviations on Windows

| Rule | Elsewhere | On Windows |
|---|---|---|
| FIDO2 PIN entry | yb's prompt, `--pin-stdin`, `YB_PIN`, libyubiblob argument | Windows' dialog only (D3) |
| Low-attempts refusal (0028 D10) | enforced by yb | not enforceable (D3) |
| Pairing check by serial | vendor command | none; one YubiKey required at format (D2) |
| Touch message | yb's | Windows' dialog (D4) |

Each deviation goes into the user documentation and into invariant 0015
(or whichever invariant states the rule), as a "Windows" note.

### Part 2: the release channel

#### D7. Artifacts

A tag `vX.Y.Z` runs a release workflow (`.github/workflows/release.yaml`)
on `windows-latest`, target `x86_64-pc-windows-msvc`.  It publishes to
the GitHub release of that tag:

- **`yb-X.Y.Z-windows-x86_64.zip`:** `yb.exe`, `LICENSE`, `README.md`;
- **`libyubiblob-A.B.C-windows-x86_64.zip`**, built with `cargo cinstall`:
  - `bin/yubiblob.dll`;
  - `lib/yubiblob.dll.lib`;
  - `lib/yubiblob.lib` (static);
  - `include/yubiblob.h`;
  - `lib/pkgconfig/yubiblob.pc`;
  - `LICENSE`;
- **`SHA256SUMS`;**
- **a build provenance attestation** (GitHub's
  `actions/attest-build-provenance`) for each zip, which users can check
  with `gh attestation verify`.

The workflow builds only from the tag's commit, with `--locked`, and runs
the Windows tests first.  A failed test publishes nothing.

#### D8. Signing

- **What is signed:** `yb.exe` and `yubiblob.dll`, with Authenticode,
  before zipping.
- **The service:** **SignPath Foundation** (free code signing for open
  source projects, certificate held by the foundation, signing from
  GitHub Actions).  The application is made once.
- **Fallback, if refused:** Azure Trusted Signing, if eligible
  (individual eligibility depends on the country), else unsigned, with
  the SmartScreen warning and the checksums documented (open question
  Q4).
- **Until signing is in place,** the Windows zips are published
  unsigned, with their checksums and provenance, and the README says how
  to check them.

#### D9. Distribution

1. **GitHub Releases:** the zips, the source of truth.  The other routes
   deliver the same signed zip, or build from the same sources.
2. **winget:** package `douzebis.yb`, a portable zip install (`yb.exe` on
   the PATH).
   - **Free:** no fee and no Microsoft account.
   - **How:** a manifest (a few YAML files pointing to the release zip
     and its hash) goes to `microsoft/winget-pkgs` by pull request, one
     per release, opened by `wingetcreate` in the release workflow.
     Microsoft's pipeline checks the hash and scans the zip (Defender),
     then a moderator merges it, usually within hours to days.
   - **Unsigned binaries are accepted**, so winget does not wait for
     signing (D8).  Signing still reduces SmartScreen and Defender
     suspicion of a new executable.
   - Users install with `winget install douzebis.yb` and upgrade with
     `winget upgrade`.
3. **cargo-binstall:** `cargo binstall yb` downloads the release zip
   instead of compiling.
   - It needs no compiler and no libfido2 on the user's machine.
   - `yb/Cargo.toml` gains `[package.metadata.binstall]`, with the URL
     template of the zips (`pkg-url`, `pkg-fmt = "zip"`, `bin-dir`) and
     a per-target override for Windows.
   - The same metadata serves the Linux and macOS archives, if those are
     published later.
   - binstall checks the zip against the release's checksums; when no
     zip fits the platform, it falls back to `cargo install`.
4. **From source:** `cargo install yb`, for developers.
   - It needs the Rust toolchain, the MSVC build tools and libfido2 from
     vcpkg (D5), documented in the README.
   - No release work beyond publishing to crates.io: the Windows CI job
     checks that the published crate builds there.
5. **libyubiblob** is distributed only as a zip.  Its consumer,
   keepassxc-yb, bundles the DLL in its own installer.

Not used for yb:

- **Microsoft Store:** it needs a developer account (Partner Center)
  and an MSIX or installer package, and suits GUI applications rather
  than command-line tools.  It may suit keepassxc-yb later.
- **Scoop:** may be added later, as a JSON manifest in our own bucket, if
  users ask for it.

#### D10. Versions and support

- Windows artifacts carry the same version as the other platforms; there
  is no separate Windows version.
- **Supported:** Windows 11, and Windows 10 22H2 where the WebAuthn API
  version found by the spike is available; x86-64.
- **Older versions:**
  - legacy stores keep working;
  - for post-quantum stores, yb says the WebAuthn API is too old, with
    the version needed.

### Tests

- **CI, `windows-latest`** (the job `windows-libyubiblob` becomes
  `windows`):
  - workspace tier-1 tests (`cargo test --workspace --locked`, minus the
    Unix-only socket tests);
  - the in-process emulator tests, which use libfido2's custom I/O and
    so need no device and no `webauthn.dll`;
  - cargo-c build;
  - libfido2 from vcpkg, cached.
- **Manual, before each release that changes FIDO2 code,** on a Windows
  machine with the test YubiKey, following a checklist in
  `docs/testing-windows.md`:
  - format (guided and flags);
  - store, fetch, ls, fsck, rm, on both kinds of store;
  - a store made on Linux opened on Windows, and the reverse (G2);
  - a refused touch;
  - a wrong PIN;
  - the wrong YubiKey touched.
- **Regression test for G2,** without Windows: fixed vectors (credential
  secret, salts, expected K2) shared by the Linux and Windows test
  suites.  The emulator produces them on both, so a change of salt
  handling on either side fails.

### Order of work

0. **Spike (D1):** go/no-go for post-quantum stores on Windows.  Report
   the result and the Windows dialogs; decide Q1–Q3.
1. **libfido2 through vcpkg** in yb-core's build script; remove the
   `cfg(not(windows))` gates; the Windows CI job runs the workspace tests
   and the emulator tests.
2. **Windows branches** for pairing, the PIN and the touch message
   (D2–D4); the `yb` details (D6).  Manual checklist on the test
   YubiKey.
3. **libyubiblob on Windows** with post-quantum stores (G5).
4. **Release workflow:** zips, checksums and provenance (D7), tried
   first on a test tag published as a GitHub pre-release.
5. **winget and cargo-binstall (D9)**, then signing (D8).

## Invariants

- Existing invariants hold on Windows, with the deviations of the table
  above stated in the invariants they touch (0015 for D10's rule, 0012 for
  test fixtures, which stay out of shipped Windows builds).
- New: **portable post-quantum stores (G2):** the same credential and
  salts give the same keys on every platform.  To be written as
  `docs/invariants/0018-portable-post-quantum-stores.md`, with the
  vector tests above.
- New: **release artifacts are built from the tagged commit only, after
  the tests pass, and are checksummed and attested (D7).**  To be written
  as `docs/invariants/0019-release-artifacts.md`.  Its regression check
  is the release workflow's own test step; a dry run on a test tag.

## Open questions

- **Q1. If the spike fails** (only PRF outputs through `webauthn.dll`):
  - (a) no post-quantum stores on Windows;
  - (b) post-quantum stores on Windows only when elevated (direct HID),
    against G3;
  - (c) a Windows-specific store variant using PRF, against G2.
  Recommended: (a), and revisit as Windows' API evolves.
- **Q2.** Can yb check, at format, that the touched key is the selected
  YubiKey?  Attestation certificates of YubiKeys do not carry the serial
  (except enterprise attestation, which Windows restricts).  If not, D2's
  warning stays the only protection.
- **Q3.** Should libyubiblob take a parent window handle (an API change,
  0.3.0), so that Windows' dialog appears over KeePassXC's window and
  not behind it?
- **Q4.** Signing: is SignPath Foundation acceptable (they hold the key;
  their name may appear as publisher), or should the certificate be in
  the author's name (paid)?
- **Q5.** Windows on Arm: when?  libfido2 builds for it (vcpkg
  `arm64-windows-static-md`), and GitHub has Arm Windows runners.
- **Q6.** Is a Windows test machine available for the spike and the
  manual checklist (a VM with USB passthrough of the test YubiKey is
  enough)?

## References

- [spec 0028](0028-post-quantum-protection.md): post-quantum stores; D9
  (libfido2 hard dependency, Windows exception), D10 (PIN attempts),
  pairing.
- [spec 0039](0039-c-api.md): libyubiblob; G7 (ABI versioning).
- [spec 0034](0034-secrets-hygiene-and-hardening.md): secrets hygiene;
  core-dump suppression deferred.
- [spec 0036](0036-bash-completion-from-the-raw-command-line.md): bash
  completion.
- libfido2: Windows Hello backend (`winhello.c`), Windows builds,
  vcpkg port `libfido2`.
- Microsoft: WebAuthn API (`webauthn.h`), hmac-secret salts in
  `WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS`.
- winget: `microsoft/winget-pkgs`, `wingetcreate`, portable installers.
- cargo-binstall: `[package.metadata.binstall]`.
- SignPath Foundation; Azure Trusted Signing.
- GitHub: artifact attestations (`actions/attest-build-provenance`).
