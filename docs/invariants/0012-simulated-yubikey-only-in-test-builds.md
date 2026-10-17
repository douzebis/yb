<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0012 — A Simulated YubiKey Only in Test Builds

**Sources:** spec 0034 G3

## Invariant

Only a yb built with the `test-fixture` feature uses the simulated
YubiKey named by `YB_FIXTURE`; every other build ignores the variable and
uses real YubiKeys.

## Why

In a user's environment, a stray `YB_FIXTURE` would silently redirect
yb, and the secrets it stores, to a file.

## Where the code keeps it

- `yb_core::fixture_path` and `yb_core::open_backend`, the only readers
  of the variable.

## Limits

- The NixOS VM test also runs the packaged `yb` with `YB_FIXTURE` set to
  a nonexistent file and expects success (`nixpkgs/nixos/tests/yb.nix`).

## Post-quantum stores (spec 0028)

The same for the FIDO2 emulator: only a `test-fixture` build has the
module that reads `YB_FIDO2_SOCKET` (`yb_core::fido2::socket`), and
`Device::open_with_io` exists only in test builds; any other build talks
to real FIDO2 devices.

## Regression tests

- `rust/yb-core/src/piv/mod.rs`: `fixture_path_follows_the_feature`
