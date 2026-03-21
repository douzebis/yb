<!--
SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
SPDX-FileCopyrightText: 2025 - 2026 Thales Cloud Sécurisé

SPDX-License-Identifier: MIT
-->

# 0015 — `yb self-test` Command

**Status:** implemented
**App:** yb (Rust)
**Implemented in:** 2026-03-21

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
3. [request credentials]    — PIN if not provided; mgmt key if not provided
4. [format]                 — yb format --generate --object-count 20
5. [run operations]         — N operations via SubprocessExecutor (§4)
6. [cleanup or preserve]    — remove all blobs on success; keep on failure
7. [report]                 — per-type statistics, pass/fail, error list
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
  1. FORMAT the YubiKey  (destroys all existing blob data)
  2. Run 200 store/fetch/remove/list operations (unencrypted + encrypted)
  3. Stop on the first error

ALL EXISTING BLOB DATA WILL BE PERMANENTLY LOST.

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
| Store | `yb --serial S --pin P store [--no-compress] --name N < payload` |
| Fetch | `yb --serial S --pin P fetch --stdout N` |
| Remove | `yb --serial S --pin P rm N` |
| List | `yb --serial S --pin P ls` |

Store uses `--no-compress` so payloads round-trip exactly (random bytes don't
compress, but avoiding compression keeps the test independent of spec 0012).
Encrypted stores use the normal encrypted default.

The executor detects "store is full" from stderr (`"store is full"`,
case-insensitive) and treats it as a valid non-error outcome, rolling back the
ground-truth update (same logic as the Python version).

Subprocess timeout: 30 seconds per operation.

### 5. Ground truth and verification

Uses `ToyFilesystem` and `OperationGenerator` from spec 0014.

```
OperationGenerator::new(seed, max_capacity=15)
    .generate(count, encryption_ratio=0.5)
```

Half of store operations are encrypted, half unencrypted.  Encryption ratio 0.5
exercises the full decrypt path on fetch.

Verification rules (identical to Python):

- **Store**: if `yb store` succeeds → update `ToyFilesystem`.  If "store full"
  → roll back toy update.  Any other non-zero exit → failure.
- **Fetch**: compare `yb fetch --stdout` stdout bytes against
  `ToyFilesystem::fetch`.  If toy says blob doesn't exist, `yb fetch` must exit
  non-zero.
- **Remove**: `yb rm` exit-0 iff `ToyFilesystem::remove` returns true.
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

In `--quiet` mode, suppress per-operation lines; print only the final report.

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

- **PIN**: resolved via the normal `Context` PIN chain (env var → `--pin-stdin`
  → interactive prompt).  Because self-test runs many subprocesses, the PIN is
  passed to each subprocess via the `YB_PIN` environment variable (set in the
  subprocess environment, not on the command line, to avoid shell history
  exposure).
- **Management key**: resolved from `YB_MANAGEMENT_KEY` env var or prompted
  interactively if not set.  Passed to subprocesses via `YB_MANAGEMENT_KEY`.

### 9. `self-test` and `Context`

Unlike other subcommands, `self-test` constructs its own `SubprocessExecutor`
rather than using `ctx.piv` directly for the test operations.  `Context` is
still constructed (for device selection and credential resolution) but is not
used for the actual store/fetch/remove/list calls — those go through subprocess.

The format step at the start uses `ctx.piv` directly (via `Store::format`) to
avoid a subprocess round-trip for the single format call.

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
