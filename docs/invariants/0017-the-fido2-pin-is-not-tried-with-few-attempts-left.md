<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0017 — The FIDO2 PIN Is Not Tried With Few Attempts Left

**Sources:** spec 0028 (D10)

## Invariant

Before using the FIDO2 PIN, yb reads the attempts left (no attempt
used) and refuses when 3 or fewer remain, unless
`--allow-low-pin-attempts` is given.  The PIN given for a post-quantum
store is never tried as the PIV PIN, nor the reverse.

## Why

The FIDO2 PIN has no unblocking code: 8 wrong PINs block it for good,
and only a FIDO2 reset clears it, which destroys every post-quantum
store on the key.

## Where the code keeps it

- `Context::check_fido2_pin_attempts`, called by
  `Context::post_quantum_session` and the guided format;
  `Context::require_fido2_pin`, separate from the PIV PIN; `yb format
  --post-quantum` takes the management key from `YB_MANAGEMENT_KEY`
  only, so it never reads PRINTED with that PIN.

## Regression tests

- `rust/yb-piv-harness/src/bin/yb_cli_tests.rs`: `pq_low_pin_attempts`
