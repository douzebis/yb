<!--
SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
SPDX-FileCopyrightText: 2025 - 2026 Thales Cloud Sécurisé

SPDX-License-Identifier: MIT
-->

# yb Test Harness — Architecture and Test Taxonomy

## Overview

The yb test suite is organized in three tiers, each trading execution speed and
hardware access for broader coverage.

```
nix-build -A integration-tests   # Tier-1 + Tier-2
```

Tier-1 runs during the nix build phase (fast, no hardware); Tier-2 runs inside a
NixOS VM that brings up a virtual PC/SC stack.  Local development uses
`cargo test --features virtual-piv`.  Tier-3 requires a real YubiKey and is run
manually via `yb self-test`.

---

## Tier-1 — Unit and CLI-level Tests (no hardware)

### Mechanism

Tier-1 tests use **`VirtualPiv`**, an in-memory `PivBackend` implementation that
performs real P-256 cryptography against in-memory key material.  No PC/SC daemon
or YubiKey is required.  Tests are compiled and run in the nix `cargoTest`
derivation (`rustTests`) before the package is built.

`VirtualPiv` state is serialized to/from YAML *fixture files*
(`rust/yb-core/tests/fixtures/`):

| Fixture | Contents |
|---|---|
| `default.yaml` | Default management key, PIN=`123456`, no keys |
| `with_key.yaml` | Pre-generated P-256 key in slot 0x82, same PIN/mgmt key |

### Test locations

| File | Test binary name | What is tested |
|---|---|---|
| `rust/yb-core/src/store/mod.rs` | `yb_core` (lib) | Object serialization, `sanitize`, `chunk_chain` cycle guard, `alloc_free`, `format` |
| `rust/yb-core/src/crypto.rs` | `yb_core` (lib) | GCM encrypt/decrypt, legacy CBC, tamper detection, version dispatch |
| `rust/yb-core/src/orchestrator.rs` | `yb_core` (lib) | `validate_name` boundaries, `store_blob` full-store return |
| `rust/yb-core/tests/virtual_piv_tests.rs` | `virtual_piv_tests` | `VirtualPiv` operations, Store+orchestrator integration, `Context::with_backend` |
| `rust/yb/tests/cli_tests.rs` | `cli_tests` | CLI `run()` functions called directly with constructed `Args` + `Context` |

### How `cli_tests` work

Each `cli_tests` test:
1. Loads `with_key.yaml` into a `VirtualPiv`.
2. Wraps it in a `Context` via `Context::with_backend` (skips real device selection
   and default-credential checks).
3. Calls the `cli::<cmd>::run(&ctx, &args)` function directly with hand-constructed
   `Args` structs.
4. Inspects the in-memory store state via `Store::from_device` or the returned
   `Result`.

This layer covers argument validation, error messages, and store mutations without
forking a subprocess, making tests fast and inspectable.

---

## Tier-2 — Subprocess and Hardware-Emulation Tests (NixOS VM)

### Mechanism

Tier-2 runs inside a NixOS VM configured with:

```
services.pcscd.plugins = [ pkgs.ccid pkgs.vsmartcard-vpcd ];
```

`vsmartcard-vpcd` is a virtual PC/SC reader daemon; `piv-authenticator` (the
`yb-piv-harness` crate) talks to it to emulate a real YubiKey at the APDU level.

The two test binaries (`hardware_piv_tests`, `yb_cli_tests`) are compiled in the
nix `harnessTestBin` derivation (with `--features integration-tests`) and
injected into the VM image.  They are never run locally by `cargo test`.

### Test locations

| File | Binary | What is tested |
|---|---|---|
| `rust/yb-piv-harness/tests/hardware_piv_tests.rs` | `hardware_piv_tests` | Real APDU round-trips via vsmartcard-vpcd: key gen, ECDH, object read/write, PIN verify |
| `rust/yb-piv-harness/tests/yb_cli_tests.rs` | `yb_cli_tests` | End-to-end subprocess tests: the compiled `yb` binary is invoked via `std::process::Command`; stdout/stderr and exit codes are checked |

### How `yb_cli_tests` work

Each test:
1. Copies `with_key.yaml` into a per-test `TempDir` (from `YB_FIXTURE_DIR` in the
   VM, or from `CARGO_MANIFEST_DIR` in a local run).
2. Runs `yb` with `YB_FIXTURE=<tmpdir>/fixture.yaml`, `YB_MANAGEMENT_KEY`, and
   `YB_PIN` set.
3. After each command the fixture file is updated in-place (via `save_fixture`) so
   the next subprocess sees the mutated state.
4. Asserts exit code, stdout content, and stderr content.

This layer catches argument-parsing bugs, shell-completion output, PIN/key
env-var resolution, deprecation warnings, and `--quiet` behavior — none of which
are reachable from the direct-call tier.

### Fixture path resolution

`YB_FIXTURE_DIR` is injected by the nix VM test script:

```python
"YB_FIXTURE_DIR=${testFixtures}"
```

where `testFixtures` is a nix derivation that copies the YAML files into the nix
store (needed because `CARGO_MANIFEST_DIR` is a build-sandbox path that doesn't
exist at VM runtime).

---

## Test Taxonomy

### Store layer (`rust/yb-core/src/store/`)

| Test | Tier | What is covered |
|---|---|---|
| `round_trip_empty` | 1 | Empty object serializes and deserializes identically |
| `round_trip_head` | 1 | Head chunk round-trip including all header fields |
| `round_trip_continuation` | 1 | Continuation chunk round-trip |
| `python_compat_vector` | 1 | Binary compatibility with the Python implementation |
| `sanitize_keeps_newer_duplicate` | 1 | T1a: `sanitize` keeps higher-age head when two share a name |
| `sanitize_resets_orphaned_continuation` | 1 | T1b: `sanitize` resets continuation with no reachable head |
| `sanitize_noop_on_clean_store` | 1 | T1c: `sanitize` does not dirty objects in a clean store |
| `chunk_chain_cycle_terminates` | 1 | T2: cycle guard prevents infinite loop on corrupt `next_chunk` |
| `format_zero_objects` | 1 | T12: `format` with `object_count=0` returns a valid empty store |
| `alloc_free_returns_none_when_full` | 1 | T13: `alloc_free` returns `None` on a fully occupied store |

### Crypto layer (`rust/yb-core/src/crypto.rs`)

| Test | Tier | What is covered |
|---|---|---|
| `encrypt_decrypt_roundtrip` | 1 | GCM encrypt→decrypt happy path; version byte; output length |
| `encrypt_decrypt_legacy_cbc` | 1 | Legacy CBC format still decrypts; `hybrid_decrypt` routes on `0x04` |
| `tampered_ciphertext_fails_authentication` | 1 | T3: flipped ciphertext byte triggers AES-GCM auth failure |
| `unknown_version_byte_rejected` | 1 | T4: `0x03` first byte produces "unknown version byte" error |
| `empty_blob_rejected` | 1 | T5: zero-length input returns "empty" error before any field access |

### Orchestrator layer (`rust/yb-core/src/orchestrator.rs`)

| Test | Tier | What is covered |
|---|---|---|
| `validate_name_invalid_chars` | 1 | Null byte and `/` rejected; Unicode, spaces, emoji accepted |
| `validate_name_length_boundaries` | 1 | T6: empty rejected; 255-byte accepted; 256-byte rejected |
| `store_blob_returns_false_when_full` | 1 | T14: `store_blob` returns `Ok(false)` when store is full; store unchanged |

### VirtualPiv + integration (`rust/yb-core/tests/virtual_piv_tests.rs`)

| Test | Tier | What is covered |
|---|---|---|
| `test_list_devices` | 1 | `list_readers` and `list_devices` on the virtual device |
| `test_read_object_missing` | 1 | Unknown object ID returns error |
| `test_write_read_object` | 1 | Write + read round-trip with correct management key |
| `test_write_wrong_mgmt_key` | 1 | Wrong management key is rejected |
| `test_verify_pin` | 1 | Correct PIN succeeds; wrong PIN fails |
| `test_pin_retry_and_block` | 1 | Retry counter decrements; card blocks at 0 |
| `test_pin_retry_resets_on_success` | 1 | Correct PIN resets retry counter |
| `test_generate_key` | 1 | Key generation with correct management key returns 65-byte point |
| `test_generate_key_no_auth` | 1 | Key generation without management key fails |
| `test_ecdh` | 1 | ECDH with pre-loaded key returns 32-byte shared secret |
| `test_read_certificate_missing` | 1 | Missing certificate returns error |
| `test_generate_certificate` | 1 | Certificate generation + read-back round-trip |
| `test_wrong_reader` | 1 | Unknown reader name fails all operations |
| `test_fixture_with_key_loaded` | 1 | `with_key.yaml` fixture loads with expected serial and usable ECDH key |
| `test_store_list_fetch_plain` | 1 | `store_blob` + `list_blobs` + `fetch_blob` round-trip (unencrypted) |
| `test_store_fetch_encrypted` | 1 | `store_blob` + `fetch_blob` round-trip (GCM encrypted) |
| `test_remove_blob` | 1 | `remove_blob` removes blob; `list_blobs` returns empty |
| `test_context_with_backend` | 1 | `Context::with_backend` works with `VirtualPiv` |
| `test_remove_nonexistent` | 1 | `remove_blob` returns `false` for a non-existent blob |
| `test_from_device_missing_objects` | 1 | T8: `from_device` errors when claimed object count exceeds written objects |
| `test_with_backend_multiple_devices_errors` | 1 | T11: `Context::with_backend` errors on a multi-device backend |
| `test_random_operations` | 1 | 300 pseudo-random store/fetch/remove/list ops (seed=42) via `OperationGenerator`; every result verified against `ToyFilesystem` ground truth |

### CLI direct-call tests (`rust/yb/tests/cli_tests.rs`)

| Test | Tier | What is covered |
|---|---|---|
| `store_single_file_by_basename` | 1 | Store a file using its basename; encrypted by default |
| `store_single_file_with_name_override` | 1 | `--name` overrides the blob name |
| `store_multiple_files` | 1 | Multiple files stored in one call; each gets its basename |
| `store_multiple_files_name_flag_rejected` | 1 | `--name` with multiple files is an error |
| `store_duplicate_basename_rejected` | 1 | Two files with the same basename in one call error |
| `fetch_to_file_default` | 1 | Fetch writes file to `--output-dir` with blob name |
| `fetch_to_explicit_output` | 1 | `--output` writes to a specific file path |
| `fetch_glob_pattern` | 1 | `key-*` glob selects matching blobs only |
| `fetch_stdout_multi_match_rejected` | 1 | `--stdout` with multiple matches is an error |
| `fetch_missing_blob_errors` | 1 | Fetching a non-existent blob fails |
| `fetch_output_and_output_dir_mutually_exclusive` | 1 | `--output` + `--output-dir` together is an error |
| `list_empty_store` | 1 | `list` on empty store succeeds without output |
| `list_glob_filter` | 1 | `--pattern foo-*` filters output to matching blobs |
| `remove_single_blob` | 1 | Remove a blob by exact name |
| `remove_glob_pattern` | 1 | `tmp-*` glob removes matching blobs, leaves others |
| `remove_missing_errors_without_flag` | 1 | Missing blob without `--ignore-missing` is an error |
| `remove_missing_ok_with_ignore_flag` | 1 | Missing blob with `--ignore-missing` succeeds |
| `remove_deduplicates_overlapping_patterns` | 1 | Overlapping patterns don't double-remove |
| `fsck_clean_store` | 1 | `fsck` on a healthy store exits 0 |
| `fsck_verbose` | 1 | T9a: `fsck -v` runs without error on a populated store |
| `fsck_detect_duplicate_name_anomaly` | 1 | T9b: `detect_anomalies` reports two heads with the same name |
| `fsck_detect_orphaned_continuation` | 1 | T9c: `detect_anomalies` reports a continuation with no reachable head |
| `format_key_slot_hex_prefix` | 1 | `--key-slot 0x82` is parsed correctly |
| `format_key_slot_decimal` | 1 | `--key-slot 130` (decimal 0x82) is parsed correctly |
| `format_key_slot_invalid_rejected` | 1 | Non-numeric `--key-slot` is an error |

### CLI subprocess tests — `yb_cli_tests` (Tier-2, NixOS VM only)

| Test | What is covered |
|---|---|
| `format_creates_store` | `yb format` writes a valid store to the fixture |
| `store_and_list` | `yb store` + `yb list` round-trip |
| `store_and_fetch_to_output_dir` | `yb store` + `yb fetch --output-dir` |
| `store_and_fetch_stdout` | `yb store` + `yb fetch --stdout` |
| `store_name_override` | `yb store --name` overrides the blob name |
| `store_multiple_files_list` | Multiple files stored and listed |
| `store_no_name_stdin_exits_1` | `yb store` from stdin without `--name` exits 1 |
| `store_duplicate_basename_exits_1` | Duplicate basename exits 1 |
| `store_encrypted_fetch_with_pin` | Encrypted store + fetch with PIN via env var |
| `fetch_missing_exits_1` | Missing blob exits 1 |
| `fetch_glob_pattern` | Glob pattern fetches matching blobs |
| `fetch_stdout_multi_match_exits_1` | `--stdout` with multiple matches exits 1 |
| `remove_single_blob` | Remove by exact name |
| `remove_glob` | Glob remove |
| `remove_missing_exits_1` | Missing blob without `--ignore-missing` exits 1 |
| `remove_ignore_missing` | `--ignore-missing` suppresses the error |
| `fsck_clean_store` | `fsck` exits 0 on a clean store |
| `fsck_verbose` | `fsck -v` prints per-object detail |
| `list_long_format` | `list -l` prints mtime and size columns |
| `list_sort_reverse` | `list --sort-time --reverse` reverses order |
| `list_readers_with_fixture` | `list-readers` works with fixture |
| `pin_from_env` | `YB_PIN` env var is used for PIN |
| `pin_from_stdin` | `--pin-stdin` reads PIN from stdin |
| `quiet_suppresses_stderr` | `-q` suppresses informational stderr |
| `deprecated_pin_flag_warns` | `--pin` flag prints deprecation warning |
| `deprecated_key_flag_warns` | `--key` flag prints deprecation warning |
| `deprecated_extract_flag_warns` | `--extract` (removed) warns appropriately |
| `completion_script_bash_exits_0` | `YB_COMPLETE=bash yb` exits 0 |
| `completion_script_zsh_exits_0` | `YB_COMPLETE=zsh yb` exits 0 |
| `completion_script_fish_exits_0` | `YB_COMPLETE=fish yb` exits 0 |
| `completion_subcommands_listed` | Completion lists all subcommands |
| `completion_blob_names_fetch` | Completion returns blob names for `fetch` |
| `completion_blob_names_list` | Completion returns blob names for `list` |
| `completion_blob_names_remove` | Completion returns blob names for `remove` |
| `completion_blob_names_prefix_filtered` | Completion filters by typed prefix |
| `completion_no_blobs_returns_empty` | Completion returns empty on empty store |

---

## Tier-3 — Real Hardware, Destructive Tests

### Mechanism

Tier-3 consists of a single interactive command, `yb self-test`, that runs on a
real YubiKey.  It is **never run in CI**.  It exercises the full PC/SC stack,
real NVM writes, and real management-key/PIN authentication paths that neither
Tier-1 (VirtualPiv) nor Tier-2 (vsmartcard-vpcd) can reproduce.

```bash
yb --serial <S> self-test [--count N] [--seed S] [--no-cleanup] [--no-flash]
```

### Flow

1. Print a destructive-operation warning and prompt for `yes`.
2. Resolve PIN and management key.
3. Format the YubiKey (`yb format --generate --object-count 16`).
4. Run N pseudo-random store/fetch/remove/list operations via `SubprocessExecutor`
   (each operation invokes the `yb` binary as a child process).
5. Verify every result against a `ToyFilesystem` ground truth.
6. Stop on the first failure, preserving YubiKey state for inspection.
7. On full pass, remove all blobs and print a final report.

### Test infrastructure reuse

The command reuses the `ToyFilesystem` and `OperationGenerator` primitives from
`yb-core/src/test_utils.rs` (compiled in when the `self-test` feature is enabled
on the `yb` binary crate, which transitively enables `yb-core/test-utils`).

### Hardware PIV tests — `hardware_piv_tests` (Tier-2, NixOS VM only)

These tests use `piv-authenticator` over a live `vpcd` connection and exercise the
actual APDU chaining logic in `HardwarePiv`:

- PC/SC connection and reader enumeration
- Management key authentication (3DES)
- Object write (including the CLA=`0x10` chaining path for objects > 255 bytes — T15 coverage)
- Object read
- Key generation (GENERATE ASYMMETRIC KEY PAIR command)
- Certificate storage and retrieval
- PIN verify, PIN retry counter, PIN block/unblock
- ECDH GENERAL AUTHENTICATE
- End-to-end store/fetch/remove via the orchestrator (same flow as Tier-1, but through real APDUs)

---

## Coverage Map

| Subsystem | Tier-1 | Tier-2 | Tier-3 |
|---|---|---|---|
| Object serialization (YBLOB format) | Full | Via hardware_piv_tests writes | Via self-test store ops |
| Store operations (format, sanitize, alloc) | Full | Via yb_cli_tests | format at start of self-test |
| Crypto (GCM, CBC legacy, ECDH+HKDF) | Full (mock ECDH) | Real ECDH in hardware_piv_tests | Real encrypt/decrypt via self-test |
| Orchestrator (store/fetch/remove/list) | Full | Via yb_cli_tests | Full via subprocess |
| PivBackend trait (VirtualPiv) | Full | N/A | N/A |
| PivBackend trait (HardwarePiv) | Not tested | Full via hardware_piv_tests | Full via self-test |
| APDU chaining (CLA=0x10) | Not tested (VirtualPiv stores directly) | Covered by hardware_piv_tests large-object writes | Exercised by self-test large payloads |
| CLI argument parsing | Partial (direct-call skips clap) | Full via yb_cli_tests | Full via subprocess |
| Exit codes | Not covered (run() returns Result) | Full via yb_cli_tests | N/A |
| Env var resolution (YB_PIN, YB_MANAGEMENT_KEY) | Not covered | Full via yb_cli_tests | Full via self-test subprocesses |
| Shell completion | Not covered | Full via yb_cli_tests | N/A |
| PIN-protected management key mode | Not covered (VirtualPiv stub) | Could be added to hardware_piv_tests | N/A |
| Real NVM wear / PC/SC latency | Not tested | Not tested (vsmartcard is in-process) | Covered by self-test |
| ToyFilesystem / OperationGenerator | `test_random_operations` (300 ops) | N/A | Core of self-test |

---

## Running Tests

```bash
# Tier-1 only (fast, no hardware, no VM):
cargo test --features virtual-piv

# Full suite (Tier-1 + Tier-2, requires nix):
nix-build -A integration-tests

# Tier-1 only via nix (skips VM):
nix-build -A rust-tests

# Tier-3 (real YubiKey, destructive — manual only):
yb --serial <SERIAL> self-test [--count 200] [--seed 42]
```
