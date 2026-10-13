<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0032 — Self-Test Integrity

**Status:** implemented
**App:** yb
**Implemented in:** 2026-10-13

## Problem

`yb self-test` (spec 0015) runs random store, fetch, remove and list
operations against a real YubiKey, through `yb` subprocesses (by design:
it tests the command as a user runs it), and compares the results with an
in-memory model.  The audit of 2026-10-13
(`docs/reviews/2026-10-python-design-audit.md`, findings 1.1.7, 1.1.8,
1.3) found that it can both damage and deceive:

- **It probes the wrong YubiKey.**  Its free-space measurement uses the
  first PC/SC reader (`self_test.rs`, "single device assumed"), not the
  YubiKey selected with `--serial`, and fills every empty yb object to its
  maximum size before clearing them.  With several YubiKeys connected, it
  writes to one the user did not select.  An error midway skips the
  clean-up, leaving junk objects.
- **It hides errors.**  Any failed `fetch` counts as "blob not found", any
  failed `rm` as "nothing to remove", any message containing "store is
  full" as a valid full store.  A decryption, signature, PIN or PC/SC error
  on those paths passes as an expected outcome.  It would have hidden the
  "store is full while writing … this should not happen" defect fixed by
  spec 0031.
- **It diverges from spec 0015 without a record:** capacity 25 for a
  20-object store (spec: 15), no timeout on child processes (spec: 30 s),
  `--quiet` ignored, stores without `--no-compress` (spec: with), format
  through a subprocess (spec: through `ctx.piv`).

## Goals

- **G1 — Only the selected YubiKey.**  Every operation of the self-test,
  including free-space measurement, acts on the YubiKey selected by the
  global options (`ctx.reader`), and on no other.
- **G2 — No residue.**  The free-space probe restores every object it
  fills, also when it fails midway (clean-up on all paths), or reports
  exactly which objects it could not restore.
- **G3 — Expected outcomes only.**  An outcome counts as "not found" or
  "store full" only if `yb` reports exactly that, by exit status, and the
  model agrees; any other failure stops the test with full context.
- **G4 — "Store full" is checked.**  A store reported full is accepted
  only if the store genuinely lacked room (`objects_needed` > free objects,
  spec 0031), read by the parent from the card.
- **G5 — Spec and code agree:** a timeout on each child, `--quiet`
  honored, and spec 0015 updated to what the code does by design:
  compression on (the default path users run), format through a `yb`
  subprocess (it tests the command), capacity derived from the store.

- **G6 — Start from a reset** (decided 2026-10-13).  The self-test does
  not rely on existing credentials: it starts by resetting the YubiKey's
  PIV application (block the PIN and the PUK, then PIV RESET), then runs
  with its own credentials.  This erases **all** PIV data,
  every slot's keys and certificates (e.g. an SSH or signing key in
  9a/9c), not only yb's store; OTP, FIDO2 and OATH are unaffected.  The
  confirmation prompt says so.  After the reset: PIN 654321, PUK
  87654321, and the management key kept on the YubiKey, unlocked by the
  PIN (spec 0027), the configuration users run.  A successful run ends
  with another PIV reset; a failed one leaves the YubiKey as it is, for
  inspection.

## Non-goals

- Changing what the self-test exercises (random operations through the
  full command-line stack, as subprocesses, on a formatted YubiKey).
- Keeping the PIN and management key out of the children's environment.
  The self-test passes them as `YB_PIN` and `YB_MANAGEMENT_KEY`; a
  process's environment is readable only by the same user, who can read
  the parent's anyway, and the YubiKey under test is one the user agreed
  to erase.
- Running the self-test in CI (it needs a real YubiKey).

## Specification

### Exit statuses of `yb` (needed by G3)

`yb` gains documented exit statuses, so callers need not parse messages:

| Status | Meaning |
|---|---|
| 0 | success |
| 1 | error (any other) |
| 2 | blob not found (`fetch`, `rm` without `-f`) |
| 3 | store full (`store`, before writing) |

### Self-test

- **Device:** the free-space probe uses `ctx.reader`.  It runs inside a
  guard that clears the filled objects on drop, including on error; if the
  clean-up itself fails, the self-test stops and lists the objects left.
- **Outcomes:** `fetch` exit 2 → not found; exit 0 → content; anything
  else → failure.  `rm` likewise.  `store` exit 3 → full, then checked
  against the store as read by the parent (G4); anything else → failure.
- **Timeout:** 30 s per child; a timeout stops the test with context.
- **`--quiet`:** suppresses progress output; the final report and any
  failure are still shown.
- **Capacity:** the generator's capacity follows the formatted store's
  object count (spec 0015 updated accordingly); "store full" outcomes are
  expected and checked (G4).

### PIV reset

`PivBackend::reset_piv(reader)`, in yb-core, by APDUs on the given reader
only (no `ykman`, which picks its own device): wrong PIN VERIFYs until
`SW 6983`, wrong PUK CHANGE REFERENCE DATAs until `SW 6983`, then RESET
(`00 FB 00 00`).  A "wrong" value that happens to be right is replaced by
another.  `VirtualPiv` refuses the RESET unless both are blocked, as the
card does.

### NVM measurements

Kept (decided 2026-10-13): they reveal memory that removing blobs does
not give back.  On the selected reader only (G1).  The probe records each
object before writing to it, and empties every recorded object whatever
happens (G2); objects it cannot empty are listed in the error.  Skipped
on a simulated YubiKey.

### Tests

- `yb/tests/self_test_tests.rs` (feature `self-test`): the whole
  self-test against a simulated YubiKey (`YB_FIXTURE`), which the parent
  and its `yb` children share through its file (the parent saves its view
  before each child and reloads it after): passes, refuses stores that
  are checked as genuinely full, and leaves a factory-reset card;
  `--quiet`; cancellation changes nothing.
- `yb/tests/exit_status_tests.rs`: statuses 2 and 3 through the binary.
- `yb-core/tests/virtual_piv_tests.rs`: RESET refused unless blocked;
  `reset_piv` restores the factory state, also when the PIN is one of the
  "wrong" values.
- G1 holds by construction (every card operation takes `ctx.reader`);
  G2's clean-up path needs a real YubiKey's memory limit, and is not
  tested.

## Open questions

None.  Testing G1 without hardware: by construction, see Tests.

## References

- Spec 0015 — `yb self-test`.
- Spec 0031 — rip-safe replace, `objects_needed`.
- `docs/reviews/2026-10-python-design-audit.md`.
