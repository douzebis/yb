<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# Changelog

All notable changes to yb are recorded here.  The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and yb uses
[semantic versioning](https://semver.org/).

## [Unreleased]

No change to yb, yb-core or libyubiblob: this release is for packagers.

### Changed

- **Builds:** the FIDO2 emulator of the tests takes OpenSK from
  crates.io (`opensk` 0.1, with `sk-cbor` 0.2), no longer from a fork
  pinned to a git commit.  A build that vendors the workspace's
  dependencies (nixpkgs) no longer fetches OpenSK's repository, nor
  OpenSSL, which OpenSK no longer declares.
- **Documentation:** `file` recognizes post-quantum stores too (magic
  `0xF2EDF0B2`, bug #813 of its magic database): "yblob post-quantum
  object store image data", then "store descriptor, version 1, 16
  chunks", or "chunk, in use" or "chunk, empty".

## [0.7.1] — 2026-10-18

### Fixed

- **A YubiKey not set up for yb:** `yb store`, `yb ls` and `yb fetch`
  said "the YubiKey rejected read object 0x5F0000 (this is unexpected —
  please report it…)".  They now say that there is no store on this
  YubiKey, and to run `yb format`, as `yb fsck` does.
- **Install instructions:** building yb needs libfido2's development
  files since 0.7.0 (post-quantum stores); the README did not say so
  (Debian and Ubuntu: `libfido2-dev`; Fedora: `libfido2-devel`; Arch,
  Homebrew, nixpkgs: `libfido2`).

### Changed

- **crates.io pages:** `yb` and `yb-core` each have a README of their
  own, instead of the repository's, and libyubiblob's is rewritten: what
  the crate is for, its guarantees, an example (yb-core's is compiled as
  a doctest), how to build it.

## [0.7.0] — 2026-10-18

### Upgrading

- **`--pin` and `--key` are removed,** as 0.5 and 0.6 announced: a
  secret on the command line is visible to other users.  yb now refuses
  them, naming the replacement: `YB_PIN`, `--pin-stdin` or the prompt for
  the PIN; `YB_MANAGEMENT_KEY`, or the key kept on the YubiKey
  (`yb rotate-management-key`), for the management key.
- **Update every program that writes to the same YubiKey** (yb,
  libyubiblob's programs such as KeePassYB): concurrent access is now
  safe (see Added), but only between programs of this version or later;
  older versions take no lock.
- **libyubiblob 0.5.0, interface version 1:** `yubiblob_remove` takes a
  `flags` argument.  Programs built for an older libyubiblob must be
  rebuilt; they refuse the new library rather than call it wrongly.
- **`yb fsck`'s output** is reworded (see Changed): scripts that read it
  may need adjusting.

### Added

- **Post-quantum stores** (spec 0028): `yb format --post-quantum` makes a
  store protected by the YubiKey's FIDO2 application (its `hmac-secret`
  extension and the FIDO2 PIN) rather than by PIV's elliptic-curve
  cryptography, which a quantum computer could break.  Each blob needs
  the FIDO2 PIN and one touch to read or write; `yb management-key set`
  follows a management key changed with ykman; `--allow-low-pin-attempts`
  lets yb try a FIDO2 PIN with 3 attempts or fewer left; `yb fsck
  --seals` checks the credential, the management key and every blob's
  seal.
- **Concurrent access** (spec 0048): yb holds the YubiKey's PC/SC lock
  for every whole-store read and every write, so several programs using
  one YubiKey at once get the outcome of running one at a time
  (invariant 0020).  A program waiting for another one says so after a
  second.  A seeded concurrency fuzzer checks it, with a nightly long
  run.
- **Reading unencrypted blobs without any PIN** (spec 0044): `yb fetch
  --no-check` reads an unencrypted blob of a post-quantum store with its
  checksum only (a legacy store's signature needs no PIN anyway), for a
  YubiKey whose PIN is blocked or whose FIDO2 application was reset
  (invariant 0019).
- **`yb fsck`'s report by application** (spec 0045): the PIV and FIDO2
  applications, what each holds or protects, their PINs and keys.
- **libyubiblob 0.2 to 0.5:** post-quantum stores
  (`yubiblob_store_info`'s kind, `yubiblob_set_touch_callback`), reads
  without any PIN (`yubiblob_fetch_unencrypted`), snapshot sessions
  (`YUBIBLOB_OPEN_SNAPSHOT`, `yubiblob_refresh`; spec 0049),
  `YUBIBLOB_STORE_IF_UNCHANGED` and `YUBIBLOB_REMOVE_IF_UNCHANGED`
  (`YUBIBLOB_ERR_CHANGED` when the blob changed since the snapshot), and
  `yubiblob_set_touched_callback` (the YubiKey no longer waits for a
  touch).
- **Windows** (spec 0043, a preview): yb and libyubiblob for legacy
  stores, tested in CI and attached to the GitHub release as zip files.

### Changed

- **`yb fsck`'s wording:** PINs as `set, 3/3 tries left` (or `factory
  default`, `blocked`), the management key's state first, one "Not
  checked" line pointing to `yb fsck --seals`, and `YubiKey memory: …`
  instead of `NVM: …`.  `--seals` announces its touches, then numbers
  each one with what it checks.
- **Faster:** a whole-store read uses one connection, about 65 ms on a
  YubiKey 5 instead of about a second; a connection that only read
  leaves the card as it is instead of resetting it.
- **`yb fsck --nvm`** scans the YubiKey's memory under the lock, with the
  store read under the same lock.
- **Builds:** the FIDO2 emulator of the tests takes OpenSK from a fork
  without its 750 MB of submodules; nothing shipped depends on it.

### Fixed

- **Several programs using one YubiKey at once** could lose a blob, read
  a store in the middle of a write, or fail; a connection that finds the
  card reset by another program reconnects.

## [0.6.0] — 2026-10-14

### Upgrading

- **Update yb on every computer that uses the same YubiKey.**  Blobs
  stored by this version (or by a program using libyubiblob) carry a new
  signature (version 2, which also covers the blob's name and metadata).
  yb 0.5 does not know it and marks those blobs **CORRUPTED** in `yb ls`
  and `yb fsck`, which then exit with an error; they are not corrupted,
  and yb 0.5's `yb fetch` still reads them.  From this version on, a
  signature version yb does not know is reported as "signed by a newer
  version of yb", not as corruption.
- **Scripts:** `yb` now exits with status 2 when a blob is not found and
  3 when the store is full (1 remains every other error).
- **The deprecated `--pin` and `--key` options** still work, and now say
  that they will be removed in yb 0.7.
- **`YB_FIXTURE`** (a simulated YubiKey for tests) is ignored by release
  builds.

### Added

- **CI** checks that the crates build and pass their tests with Rust
  1.86, the oldest version they declare, and builds libyubiblob on
  Windows.
- **libyubiblob, a C library** (`rust/yubiblob`, spec 0039): yb's blob
  store for C and C++ programs, built and installed with `cargo-c`
  (`yubiblob.h`, `libyubiblob`, pkg-config `yubiblob`).  Its own version,
  0.1.0; tested on Linux and, in CI, Windows.
- **`--pin-stdin` with a payload:** the first line of standard input is
  the PIN, and a payload read from standard input (`yb store`) is
  everything after it, byte for byte, so that a program can store a blob
  with no file and no PIN in its arguments or environment.  Documented and
  tested (spec 0037).
- **Exit statuses:** `yb` exits with status 2 when a blob name or pattern
  matches nothing (`fetch`, `rm` without `-f`), and 3 when the store has
  no room (`store`, before writing anything); 1 remains every other error.

### Changed

- A signature version yb does not know (written by a newer yb) is no
  longer reported as corruption: the blob is listed and fetched, with a
  warning that a newer yb wrote it (`UNVERIFIABLE` in `yb fsck`).
- The deprecated `--pin` and `--key` options announce their removal in
  yb 0.7.
- **`YB_FIXTURE` is for tests only.**  Only a yb built with the new
  `test-fixture` feature uses the simulated YubiKey this variable names;
  release and debug builds ignore it, so that a stray variable can no
  longer redirect yb, and its secrets, to a file (spec 0034).  Packagers:
  the NixOS VM test now builds its own `yb` with that feature.
- `yb fetch` asks for the PIN only when a matched blob is encrypted.
- `yb ls`, `yb fsck` and `yb fetch` flag blobs encrypted with the legacy,
  unauthenticated AES-CBC scheme of the Python predecessor (`LEGACY`);
  store them again.
- The management key is held in memory that is overwritten after use,
  including when read from the YubiKey.
- `yb store` refuses, before writing, a write that would overflow the
  store's 24-bit age counter; `yb fsck` warns as it nears its end.
- Objects that record another object count than the store's are ignored
  by yb and reported by `yb fsck` as errors.
- **`yb self-test` starts from a PIV reset** and relies on no credential of
  the user's: it resets the PIV application (erasing every PIV key and
  certificate, not only yb's store, as its prompt says), sets PIN 654321
  and PUK 87654321 and a management key kept on the YubiKey, and resets
  the PIV application again after a successful run (spec 0032).

- **`yb fetch` verifies signatures** before writing or decrypting
  anything, without the PIN, and refuses a blob that is corrupted or was
  tampered with, fetching nothing.  Unsigned blobs (written before 0.3)
  are fetched with a warning (spec 0033).
- **Signatures now cover the blob's name and metadata** (key slot,
  compression, sizes, modification time), so blobs can no longer be
  swapped between names or have their metadata altered unnoticed.  New
  blobs get a version 2 signature; version 1 signatures still verify.
- `yb ls` and `yb fsck` mark unsigned blobs `UNSIGNED` (formerly
  "unverified", shown only by `fsck`); `fsck` prints "unsigned" in its
  integrity summary.
- `yb store` fails, storing nothing, if it cannot sign the blob; it used
  to store it unsigned with a warning.
- The README states what signatures protect against, and that yb has no
  rollback protection; earlier design notes claimed replay protection
  that no version provided.

### Fixed

- **A store that ran out of the YubiKey's memory made the whole store
  unreadable** (found on a YubiKey 5, replacing a 22 KB blob).  The card
  deletes the object of a write it refuses for lack of memory, and yb
  stopped on any absent object.  yb now reads an absent object as empty,
  `yb fsck` reports it, and the next write frees the interrupted write's
  leftovers before writing new data.  The blobs keep their previous
  content (spec 0038).
- **Replacing a blob was not safe against interruption** (since 0.3.0, the
  Rust rewrite).  `yb store` over an existing blob wrote the new copy into
  the old copy's objects; a YubiKey pulled out during the write could lose
  both versions.  The new copy now goes into free objects, its head written
  last, and the old copy is removed only afterwards, as in 0.1.x.  An
  interrupted store, replace or remove now always leaves the old or the
  new content (spec 0031).
- After an interrupted write, `yb fetch` and `yb ls` could see both copies
  of a blob, or an incomplete one; they now see the blobs a later write
  keeps, without writing anything.
- A replace in a nearly full store now fails cleanly before writing, saying
  that it needs room for the new copy before the old one is removed,
  instead of "store is full while writing … — this should not happen"; a
  multi-file `yb store` that does not fit stores nothing.
- `yb rm` writes the blob heads first, so an interrupted removal leaves each
  blob whole or gone.
- `yb fsck` no longer crashes on a store with a corrupt chunk pointer.
- `yb fetch` of several blobs could write some before finding that a
  later one was tampered with; it now checks them all first.
- `yb self-test` measured free memory on the first YubiKey found, not
  necessarily the one selected with `--serial`, writing temporary objects
  to it; an error during that measurement could leave them behind.  It
  now uses the selected YubiKey only, and always removes them, or names
  those it could not remove.
- `yb self-test` took any failed fetch for "not found", any failed remove
  for "nothing to remove", and any message mentioning "store is full" for
  a full store, so that real errors passed; it now reads `yb`'s exit
  statuses, checks each "store full" against the store, stops on any
  other error, gives each `yb` it runs 30 seconds, and honors `--quiet`.

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
