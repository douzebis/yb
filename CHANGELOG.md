<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# Changelog

All notable changes to yb are recorded here.  The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and yb uses
[semantic versioning](https://semver.org/).

## [0.5.2] — 2026-10-10

### Fixed

- The tier-2 PIV tests (`hardware_piv_tests`) never ran in the NixOS VM
  test: they skipped silently and were reported as passing.  The VM did not
  load the vpcd driver, and the harness could not start its emulated card.
  They now run (10 tests through `pcscd` against an emulated card), and a
  missing vpcd fails them in the VM instead of skipping.

### For packagers

- `nixosTests.yb`: the VM loads the virtual reader driver with
  `services.vsmartcard-vpcd.enable` (listing it in `services.pcscd.plugins`
  had no effect), and runs `hardware_piv_tests` with `YB_REQUIRE_VSC=1`.

## [0.5.1] — 2026-10-09

### Fixed

- The installation instructions cover NixOS and the build requirements
  of `cargo install` (shown on crates.io), with the error you get without
  them; `--locked` is recommended rather than required.
- The `yb` and `yb-core` crates include the MIT license text.

## [0.5.0] — 2026-10-09

### Upgrade notes

- **Bare `yb format` in a terminal is now interactive.**  It starts a
  guided setup and asks before writing anything.  Scripts that ran bare
  `yb format` from an interactive shell should use `yb format --yes`.
  Without a terminal (CI, pipes, cron), nothing changes.
- **`yb format --protect` keeps a management key that is already kept on
  the YubiKey.**  It used to replace it.  To replace it on purpose, use
  the new `yb rotate-management-key`.
- **Factory-default credentials are handled per command.**  yb refuses
  only when it is about to put a secret behind a credential that does not
  protect it: `yb store`, `yb format --protect` and
  `yb rotate-management-key` refuse while the PIN or PUK is the factory
  value; `fetch`, `rm` and `format` warn; `ls` says nothing.  Previously every command refused.  `--allow-defaults` still
  turns refusals into warnings.
- **`yb fsck` output starts with a YubiKey section**, and `fsck` exits
  with status 1 on card-level errors too (e.g. a blocked PIN, or a slot
  key that does not match its certificate).  The store part of the output
  is unchanged.  `yb ls` remains the command meant for scripts.
- **YubiKeys set up with yb 0.4.x `--protect`** are migrated to the
  ykman-compatible metadata on their first write, with a one-line note.

### Added

- **Guided setup:** bare `yb format`, from a terminal, shows the state of
  the YubiKey, changes a factory PIN and PUK, keeps or replaces the key in
  slot 0x82, keeps the management key on the YubiKey (unlocked by the
  PIN), shows the plan, and asks for confirmation.  When blobs or an
  existing key would be destroyed, the confirmation is the YubiKey's
  serial number.
- `yb format --plan`: run the checks and show what the format would do,
  without writing anything.
- `yb format --yes`: format without the guided setup.
- `yb rotate-management-key`: replace the management key with a random
  one, kept on the YubiKey and unlocked by the PIN, without touching the
  store.  It also sets this up on a YubiKey that does not keep its key
  yet, which previously required erasing the store or using ykman.
- `yb fsck` reports the YubiKey itself: PIN and PUK status and tries
  left, management key algorithm and how it is kept, and the key and
  certificate in the store slot.  It runs on a factory-fresh YubiKey and
  on one without a store.  `yb fsck --check-key` also checks that the
  slot key matches its certificate (asks for the PIN).
- Support for YubiKey firmware 5.7 and later, whose management key is
  AES-192 by default (0.4.2 failed on them with `SW 6A80`).  yb reads the
  key's algorithm from the YubiKey and keeps it when it sets a new key.

### Changed

- **Error messages** say what failed, why, and what to do, with a short
  details line (operation and status word).  They no longer include the
  YubiKey's serial number or the reader name; the firmware version
  appears only in reports of unexpected errors.
- **`yb format` checks everything before writing** (PIN, management key,
  slot key against its certificate, blobs about to be destroyed, listed
  even with `--quiet`), then writes in an order where no failure leaves
  blobs behind a replaced key.  If it stops partway, it says what was
  done.
- **Changing the management key is interruption-safe:** the new key is
  saved on the YubiKey before the switch, together with the old one, so
  a YubiKey pulled out mid-way never ends up with a key that exists
  nowhere.  The next yb write finishes any leftover cleanup.
- The metadata recording a management key kept on the YubiKey follows
  ykman's layout (ADMIN DATA flag `0x02`), so ykman and yb agree on it.
- Output says "kept on the YubiKey, unlocked by the PIN" instead of
  "PIN-protected".

### Fixed

- `yb format --generate --protect` on a YubiKey whose management key was
  already kept on the YubiKey replaced the store key, then failed with
  `SW 6982`, leaving the existing blobs undecryptable.
- `yb store` refuses to write when the key in the store slot does not
  match its certificate, instead of storing blobs nobody could decrypt.
- A YubiKey whose PUK is really blocked is no longer mistaken for one
  whose management key is kept on the YubiKey.
- Blob-name completion honors `--serial` and `--reader`; with several
  YubiKeys connected and no selector, it offers no names instead of names
  from the wrong key.
- The tests of the published `yb` and `yb-core` crates pass from the
  crates.io tarballs alone (they read files outside their package, or
  lost a feature they needed), for distributions that build from them.

### For packagers

- The tier-2 test programs (`hardware_piv_tests`, `yb_cli_tests`) are
  binaries of the `yb-piv-harness` crate (feature `integration-tests`),
  built by a plain `cargo build`; they need pcscd with a virtual smart
  card (vsmartcard-vpcd), and take `--test-threads=1`.
- Test fixtures are compiled into `yb-core` (feature `virtual-piv`); the
  `YB_FIXTURE_DIR` variable is gone.  `YB_BIN` still points
  `yb_cli_tests` at the `yb` binary under test.
- The version is set once, in `rust/Cargo.toml` (`workspace.package`).
- yb's own repository builds and tests with the nixpkgs recipe, staged in
  `nixpkgs/` (see `nixpkgs/README.md`).

## [0.4.2] — 2026-04-30

A rewrite of yb in Rust.  Reconstructed from the git history; the
intermediate tags (0.3.0 to 0.4.1) were not released on nixpkgs.

### Upgrade notes

- **Stores written by 0.1.0 remain readable**, including blobs encrypted
  with the old scheme.  New blobs use the new encryption and carry a
  signature; older blobs show as UNVERIFIED, not CORRUPTED.
- **Pass credentials through the environment:** `YB_PIN`,
  `YB_MANAGEMENT_KEY` or `--pin-stdin`.  `--pin` and `--key` still work
  but print a deprecation warning.
- **`--object-size` is gone:** objects are sized to their content.  The
  default object count is 32 (was 20).

### Added

- **Blob signatures:** every stored blob is signed (ECDSA P-256) with the
  YubiKey's key.  `yb ls` and `yb fsck` check them without a PIN, report
  VERIFIED, UNVERIFIED or CORRUPTED, and exit with status 1 on a
  corrupted blob.
- **Transparent compression** (brotli or xz, whichever is smaller), with
  `yb store --no-compress` to turn it off.
- `yb format --protect`: set up the management key kept on the YubiKey,
  unlocked by the PIN.
- `yb store` reads files or stdin; `yb fetch` saves to files by default,
  with `--output`, `--stdout` and glob patterns.
- `yb fsck --nvm` estimates how the YubiKey's storage is used;
  `yb fsck --verbose` adds structural checks and a per-object dump.
- `yb select` prints the serial of a YubiKey chosen interactively, for
  scripts (`yb --serial "$(yb select)" …`).
- Shell completion for bash, zsh and fish, including blob names.
- Man pages.
- macOS support.

### Changed

- **Rewritten in Rust:** a single binary that talks to the YubiKey
  directly through PC/SC.  It no longer needs `yubico-piv-tool`, `ykman`,
  `pkcs11-tool` or `openssl`.
- **Encryption** uses AES-256-GCM (authenticated) instead of AES-256-CBC
  for new blobs.
- **Storage:** each object is written at the size its content needs
  (9 bytes when empty, up to 3,063 bytes), which leaves more room for
  blobs.
- Blob names containing a NUL byte or `/` are rejected; names with shell
  special characters are shown quoted.

## [0.1.0] — 2025-11-23

First release (Python), submitted to nixpkgs.

### Added

- `yb format`, `store`, `fetch`, `ls`, `rm` and `fsck`: named blobs stored
  in custom PIV data objects of a YubiKey.
- Hybrid encryption: an ephemeral P-256 key, ECDH with a P-256 key that
  never leaves the YubiKey, HKDF-SHA256 and AES-256.
- Several YubiKeys: `--serial`, and an interactive selector that blinks
  the chosen YubiKey.
- Reading a management key kept on the YubiKey (set up with ykman),
  unlocked by the PIN.
- Shell completion for `--serial`.
- `yb self-test`: a destructive end-to-end test on a real YubiKey.
