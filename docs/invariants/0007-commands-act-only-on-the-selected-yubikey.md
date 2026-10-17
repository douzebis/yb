<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0007 — Commands Act Only on the Selected YubiKey

**Sources:** spec 0013, spec 0032 G1

## Invariant

Every operation of a command reaches the YubiKey selected by
`--serial`, `--reader` or the picker, and no other, even when other
readers are listed first.

## Why

With several YubiKeys connected, writing to another one destroys data
the user never pointed at (the self-test's probe once did, spec 0032).

## Where the code keeps it

- Commands use `ctx.reader` for every card operation; there is no
  "first reader" fallback.

## Limits

- The self-test's NVM probe opens PC/SC itself (on `ctx.reader`); it is
  exercised only on real hardware.

## Post-quantum stores (spec 0028)

The FIDO2 side too: the FIDO2 device whose serial (Yubico's vendor
command) is the selected YubiKey's; else the only one, when one YubiKey
is connected; else the one the user touches (no PIN); else refused.  The
FIDO2 PIN is never sent to several devices in turn.

## Regression tests

- `rust/yb-core/src/fido2/pairing.rs`: `tests::by_serial`, `tests::a_different_serial_rules_out`, `tests::one_yubikey_on_each_side`, `tests::several_unknown`
- `rust/yb-fido2-emulator/tests/socket_tests.rs`: `served_emulator`
- `rust/yb/tests/cli_tests.rs`: `commands_act_only_on_the_selected_yubikey`
