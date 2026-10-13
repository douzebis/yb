<!--
SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0015 — `yb self-test` Command

**Status:** implemented
**App:** yb (Rust)
**Implemented in:** 2026-03-21

> **Amended by spec 0032** (2026-10-13): the self-test starts and ends with
> a PIV reset and sets its own credentials (§2, §3, §8); outcomes are read
> from `yb`'s exit statuses, and a "store full" is checked against the
> card (§4, §5); compression is on, the format goes through `yb`, the
> capacity follows the store (§4, §5, §9); `--quiet` is honored (§6).  It
> also runs end to end on a simulated YubiKey in the tests, despite the
> non-goal below.

## Problem

There is no way to validate that a YubiKey and its `yb` store are working
correctly end-to-end with real hardware, real NVM writes, and real PC/SC
latency.  Tier-1 tests use `VirtualPiv` (in-memory) and Tier-2 tests use a
virtual smartcard daemon — neither exercises actual NVM wear, real APDU timing,
or real management-key / PIN authentication paths.

The Python version had a `yb self-test` subcommand that addressed this by
formatting a YubiKey and running hundreds of pseudo-random store/fetch/remove/list
operations via subprocess, comparing every result against an in-memory ground
truth.

## Goals

- Add `yb self-test` as a new subcommand.
- Format the target YubiKey, run N pseudo-random operations, verify every result
  against a ground truth, report pass/fail per operation type.
- Flash the YubiKey LED during the destructive confirmation prompt so the user
  can visually identify the correct device.
- On failure, preserve YubiKey state and print diagnostic instructions.
- On success, clean up (remove all blobs).
- The command is **Tier-3**: it requires real hardware, is destructive, and is
  never run in CI.

## Non-goals

- Running in CI or against `VirtualPiv`.
- Non-destructive mode (the format step is required for a clean baseline).
- Parallel operation execution.

---

## Specification

### 1. Subcommand definition

```
yb [global options] self-test [--count N] [--seed S] [--no-cleanup] [--no-flash]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--count N` | 200 | Number of store/fetch/remove/list operations to run |
| `--seed S` | 42 | RNG seed for `OperationGenerator`; use a different seed to get a different sequence |
| `--no-cleanup` | false | Keep blobs after a successful test (for post-test inspection) |
| `--no-flash` | false | Suppress LED flashing during confirmation prompt |

Global `--serial` / `--reader` select the target device.  If multiple devices
are present and no `--serial` is given, the interactive picker (spec 0013) is
invoked first.

### 2. Execution flow

```
1. [select device]          — spec 0013 picker if multiple devices
2. [confirm]                — destructive warning, LED flash, "yes" prompt
3. [reset]                  — PIV reset; PIN 654321, PUK 87654321;
                              yb rotate-management-key (kept on the YubiKey)
4. [format]                 — yb format --generate --object-count 20
5. [run operations]         — N operations via SubprocessExecutor (§4)
6. [cleanup or preserve]    — on success: remove all blobs, then PIV reset;
                              on failure: keep the state
7. [report]                 — per-type statistics, pass/fail, error list

Free NVM is measured after the format, after the operations and after the
clean-up (real YubiKeys only), to reveal memory that removing blobs does
not give back.
```

### 3. Confirmation prompt

Printed to stderr before any destructive action:

```
══════════════════════════════════════════════════════════════════════
WARNING: DESTRUCTIVE OPERATION
══════════════════════════════════════════════════════════════════════

YubiKey to test:
  Serial:  12345678
  Version: 5.4.3

This self-test will:
  1. RESET the YubiKey's PIV application
  2. Set PIN 654321, PUK 87654321, a management key kept on the
     YubiKey, and format a store
  3. Run 200 store/fetch/remove/list operations, stopping on
     the first error (the YubiKey is then left as it is)
  4. On success, reset the PIV application again

ALL PIV DATA WILL BE PERMANENTLY LOST: every key and certificate
(e.g. SSH or signing keys in slots 9a, 9c), not only yb's store.
OTP, FIDO2 and OATH are not affected.

YubiKey LED is flashing to help you identify the correct device...

Type 'yes' to proceed: _
```

LED flashing (spec 0013 `PivBackend::start_flash`) runs in a background thread
from when the prompt is printed until the user responds.  If `--no-flash` is
given, the flash line is omitted and no thread is started.

The only accepted confirmation is the string `yes` (case-sensitive, no trailing
whitespace).  Any other input (including `y`, `YES`, empty) cancels with exit
code 1.

### 4. Operation executor (`SubprocessExecutor`)

Operations are executed by invoking the `yb` binary as a subprocess — the same
binary that is running — so the test exercises the full CLI stack including
argument parsing, PIN resolution, and PC/SC connection management.

```rust
struct SubprocessExecutor {
    yb_bin: PathBuf,   // path to self (std::env::current_exe())
    serial: u32,
    pin: String,
    mgmt_key: String,
}
```

Each operation maps to one subprocess call:

| Operation | Command |
|-----------|---------|
| Store | `yb --serial S store --encrypted\|--unencrypted --name N < payload` |
| Fetch | `yb --serial S fetch --stdout N` |
| Remove | `yb --serial S rm N` |
| List | `yb --serial S ls` |

The PIN is passed as `YB_PIN`; the management key is read by each `yb`
from the YubiKey.  Stores compress, as users' stores do.

Outcomes are read from `yb`'s exit statuses (spec 0032): 2 "not found"
for fetch and remove, 3 "store full" for store; any other non-zero status
is a failure.  A "store full" is accepted only if the store, read by the
self-test from the card, lacks the objects the blob needs.

Subprocess timeout: 30 seconds per operation.

### 5. Ground truth and verification

Uses `ToyFilesystem` and `OperationGenerator` from spec 0014.

```
OperationGenerator::new(seed, max_capacity=<the store's object count>)
    .generate(count, encryption_ratio=0.5)
```

Half of store operations are encrypted, half unencrypted.  Encryption ratio 0.5
exercises the full decrypt path on fetch.

Verification rules (identical to Python):

- **Store**: if `yb store` succeeds → update `ToyFilesystem`.  Exit 3
  ("store full", checked as above) → no update.  Any other non-zero exit →
  failure.
- **Fetch**: compare `yb fetch --stdout` stdout bytes against
  `ToyFilesystem::fetch`.  If toy says blob doesn't exist, `yb fetch` must exit
  with status 2.
- **Remove**: `yb rm` exit 0 iff `ToyFilesystem::remove` returns true, exit 2
  otherwise.
- **List**: `yb ls` stdout (one name per line, sorted) must match
  `ToyFilesystem::list()`.

Stop on the first failure — state after a failure is unknown and further
operations would produce misleading results.

### 6. Progress display

One line per operation, updated in place:

```
[  1/200,  199 remaining]  STORE(config)...      OK
[  2/200,  198 remaining]  FETCH(config)...       OK
[  3/200,  197 remaining]  REMOVE(nonexistent-4421)...  OK
...
[ 47/200,  153 remaining]  STORE(secret)...      FAIL
  Error: Op #47 STORE(secret): exit 1 — store is full (unexpected)
Stopping at operation 47/200.
State preserved — run 'yb --serial 12345678 fsck -v' to inspect.
```

In `--quiet` mode (global option), suppress per-operation and progress
lines; the confirmation prompt, any failure and the final report are still
printed.

### 7. Final report

```
══════════════════════════════════════════════════════════════════════
YB SELF-TEST REPORT
══════════════════════════════════════════════════════════════════════

Device:  serial=12345678  version=5.4.3
Seed:    42
Count:   200 operations  (completed: 200)
Duration: 312.4 seconds

Results:
  STORE:   82 ops   82 passed   0 failed
  FETCH:   72 ops   72 passed   0 failed
  REMOVE:  30 ops   30 passed   0 failed
  LIST:    16 ops   16 passed   0 failed
  ──────────────────────────────────────
  TOTAL:  200 ops  200 passed   0 failed

Result: ALL TESTS PASSED
══════════════════════════════════════════════════════════════════════
```

On failure, list up to 10 individual failure messages below the totals.

Exit code 0 on full pass, 1 on any failure or cancellation.

### 8. Credential resolution

None of the user's credentials is used (spec 0032 G6): after the reset,
the self-test sets PIN 654321 and PUK 87654321, and `yb
rotate-management-key` replaces the factory management key with a random
one kept on the YubiKey, unlocked by the PIN.  Subprocesses get the PIN
as `YB_PIN`, set in their environment, not on the command line.

### 9. `self-test` and `Context`

Unlike other subcommands, `self-test` constructs its own `SubprocessExecutor`
rather than using `ctx.piv` directly for the test operations.  `Context` is
still constructed (for device selection and credential resolution) but is not
used for the actual store/fetch/remove/list calls — those go through subprocess.

The format step goes through a `yb format` subprocess too, so that it is
tested.  The reset, the PIN and PUK changes, the "store full" checks and
the NVM measurements use `ctx.piv` and `ctx.reader`: the selected YubiKey,
and no other.  Each subprocess has a 30-second timeout.

### 10. Feature flag

`self-test` is compiled only when the `self-test` feature is enabled on the `yb`
binary crate:

```toml
# yb/Cargo.toml
[features]
self-test = ["yb-core/test-utils"]
```

The nix build enables it:

```nix
cargoExtraArgs = "--features self-test";
```

This keeps the `test-utils` / `rand` dependency out of the default release
binary.

---

## References

- Python `self_test.py`: `run_self_test`, `SubprocessExecutor`, `confirm_destructive_test`
- Python `test_helpers.py`: `ToyFilesystem`, `OperationGenerator`
- Spec 0013: interactive device selection and LED flash
- Spec 0014: `ToyFilesystem` and `OperationGenerator` (required dependency)
- `yb-core/src/context.rs`: `Context::new`, device selection
