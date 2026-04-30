<!--
SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0019 — macOS Support (x86_64-darwin, aarch64-darwin)

**Status:** draft
**App:** yb
**Implemented in:** <!-- YYYY-MM-DD, fill after implementation -->

## Problem

`yb` currently builds and runs only on Linux. The `default.nix` dev shell and
the nixpkgs `package.nix` both restrict to `lib.platforms.linux` and set
`badPlatforms = lib.platforms.darwin`. However:

- The Rust code has no Linux-specific logic: it uses the `pcsc` crate (v2)
  which already links against `libpcsclite.so` on Linux and Apple's
  `PCSC.framework` on macOS transparently.
- The GitHub Actions CI already builds and runs `yb --help` on `macos-15`
  (aarch64-darwin) and `macos-15-intel` (x86_64-darwin) successfully.
- YubiKeys work natively on macOS via the built-in PC/SC stack.

The only missing pieces are packaging (nix) and CI verification with a real
YubiKey on macOS.

## Goals

- `cargo build --release -p yb --features self-test` succeeds on macOS
  (aarch64-darwin, x86_64-darwin) without any Rust code changes.
- `nix-shell` on macOS enters the dev environment successfully.
- `nix-build` produces a working `yb` binary on macOS.
- The nixpkgs `package.nix` supports macOS: `badPlatforms` and `platforms`
  updated, darwin `buildInputs` use `PCSC.framework` instead of `pcsclite`.
- `yb` passes basic functional tests on a MacBook M1 with a real YubiKey.
- GitHub Actions CI adds macOS build jobs to the yb repo CI matrix.

## Non-goals

- Tier-2 VM integration tests on macOS (`vsmartcard-vpcd` and
  `piv-authenticator` are Linux-only; macOS lacks NixOS VM support).
- macOS pkg/Homebrew formula packaging.
- Windows support.

## Specification

### 1. Rust / Cargo

No changes required. The `pcsc` crate handles platform differences internally:
- Linux: links `libpcsclite` via pkg-config.
- macOS: links `PCSC.framework` via `-framework PCSC`.

Verify by running on the MacBook M1:
```bash
cargo build --release -p yb --features self-test
./target/release/yb --version
./target/release/yb self-test   # requires a YubiKey inserted
```

### 2. `default.nix` dev shell

Add a darwin branch to `buildInputs` and `nativeBuildInputs`:

```nix
buildInputs = [ pkgs.pcsclite ]
  ++ lib.optionals pkgs.stdenv.isDarwin [
    pkgs.darwin.apple_sdk.frameworks.PCSC
  ];
```

Remove `pkgs.pcsclite` from the darwin path (it is Linux-only).
The `pkg-config` wrapper for pcsclite is not needed on macOS.

### 3. nixpkgs `package.nix`

- Add `darwin.apple_sdk.frameworks.PCSC` to the function arguments
  (conditionally available).
- Replace the static `buildInputs = [ pcsclite ]` with:
  ```nix
  buildInputs = [ pcsclite ]
    ++ lib.optionals stdenv.isDarwin [ darwin.apple_sdk.frameworks.PCSC ];
  ```
  and remove `pcsclite` from the darwin path.
- Update `platforms`:
  ```nix
  platforms = lib.platforms.unix;
  ```
- Remove `badPlatforms` entirely (or restrict to non-unix platforms if needed).

### 4. GitHub Actions CI

Add `macos-15` and `macos-15-intel` to the `check` and `build` job matrices
in `.github/workflows/` (they may already be present — verify).

### 5. Functional test plan (MacBook M1)

With a YubiKey inserted on the MacBook M1, run:

```bash
# Basic smoke tests (no YubiKey needed)
yb --version
yb --help
yb self-test

# YubiKey functional tests (YubiKey required)
yb init
yb put myblob <<< "hello world"
yb get myblob
yb ls
yb rm myblob
yb ls   # should be empty
```

All commands must exit 0 and produce correct output.

### 6. Tier-2 tests on macOS

Not applicable. `vsmartcard-vpcd` and `piv-authenticator` require Linux.
The NixOS VM test in `passthru.tests.integration` remains Linux-only.

## Open questions

- Does `nix-shell` work on the MacBook M1 out of the box, or does it need
  nix-darwin / home-manager setup first?
- Does `piv-authenticator` have any macOS support that could enable
  virtual-card tests on macOS in the future?

## References

- `pcsc` crate: https://docs.rs/pcsc
- nixpkgs `PCSC.framework` usage examples: search `apple_sdk.frameworks.PCSC`
  in nixpkgs
- Spec 0005: nix integration test build (Linux VM tests)
- nixpkgs PR #514826: current Linux-only package.nix
