<!--
SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
SPDX-FileCopyrightText: 2025 - 2026 Thales Cloud Sécurisé

SPDX-License-Identifier: MIT
-->

# 0008 — CLI integration tests

**Status:** implemented
**App:** yb
**Implemented in:** 2026-03-21

## Problem

After implementing spec 0007 (CLI improvements), the only automated tests
were in `yb-core`: pure library unit tests (`crypto`, `store`, `orchestrator`)
and `VirtualPiv`-backed orchestrator tests.  The CLI layer — argument
validation, command dispatch, error messages, flag interactions — had zero
coverage.  Bugs in `cli/store.rs`, `cli/fetch.rs`, etc. would be invisible
to `cargo test`.

## Goals

- Every CLI command (`store`, `fetch`, `list`, `remove`, `fsck`, `format`)
  has at least one passing integration test.
- Error paths (bad arguments, missing blobs, constraint violations) are
  covered alongside the happy path.
- Tests run without hardware, without network access, and without spawning
  a subprocess — they call `run()` directly.
- The test suite integrates with `cargo test` and passes in CI.

## Non-goals

- Exhaustive coverage of every flag combination.
- Testing the `list-readers` command (it calls `HardwarePiv::new()` directly
  and is inherently hardware-dependent).
- Testing PIN/key resolution from env vars or TTY (that logic lives in
  `main.rs` and is exercised manually).
- Output format assertions (stdout/stderr content is not captured or
  checked — behavior is verified through side effects: store state, files
  written).

## Specification

### Structure

Tests live in `rust/yb/tests/cli_tests.rs` (Cargo integration test).

The `yb` crate is a binary-only crate; to make `cli::*` importable from
the integration test, a thin `src/lib.rs` is added that re-exports `pub mod
cli`.  The binary `src/main.rs` imports `cli` via `use yb::cli`.

### Backend

All tests use `VirtualPiv` loaded from the existing `with_key.yaml` fixture
(`rust/yb-core/tests/fixtures/with_key.yaml`).  This fixture provides:

- Serial `88888888`, reader `"Virtual YubiKey 00 01"`
- PIN `123456`, management key `010203040506070801020304050607080102030405060708`
- Pre-loaded P-256 private key in slot `0x82` (no certificate)

### Context construction

A `make_ctx(piv: VirtualPiv) -> Context` helper wraps `Context::with_backend`,
pre-injects the management key, and sets `quiet = true` to suppress
informational stderr output during tests.

A `format_store(ctx)` helper calls `Store::format` with 8 objects × 512 bytes,
slot `0x82`, before each test that needs a writable store.

### store tests

| Test | What it verifies |
|---|---|
| `store_single_file_by_basename` | File stored under its basename; `is_encrypted = true` when encrypted flag set (requires pre-generated cert) |
| `store_single_file_with_name_override` | `-n NAME` overrides basename; `is_encrypted = false` when `-u` set |
| `store_multiple_files` | Two files stored in one call; both appear in `list_blobs` |
| `store_multiple_files_name_flag_rejected` | `--name` with multiple files returns `Err` |
| `store_duplicate_basename_rejected` | Two files with same basename return `Err` containing `"duplicate blob name"` |

### fetch tests

| Test | What it verifies |
|---|---|
| `fetch_to_file_default` | Blob written to `--output-dir / blob_name` |
| `fetch_to_explicit_output` | Blob written to `-o FILE` |
| `fetch_glob_pattern` | `key-*` matches `key-a` and `key-b` but not `other`; files written |
| `fetch_stdout_multi_match_rejected` | `--stdout` with multi-match glob returns `Err` |
| `fetch_missing_blob_errors` | Plain name not in store returns `Err` |
| `fetch_output_and_output_dir_mutually_exclusive` | Both `-o` and `-O` returns `Err` |

### list tests

| Test | What it verifies |
|---|---|
| `list_empty_store` | Returns `Ok` on an empty store |
| `list_glob_filter` | Returns `Ok` with a glob pattern (output not captured) |

### remove tests

| Test | What it verifies |
|---|---|
| `remove_single_blob` | Blob removed; `list_blobs` returns empty |
| `remove_glob_pattern` | `tmp-*` removes two blobs; `keep` survives |
| `remove_missing_errors_without_flag` | Missing plain name returns `Err` |
| `remove_missing_ok_with_ignore_flag` | Missing plain name with `-f` returns `Ok` |
| `remove_deduplicates_overlapping_patterns` | `["x", "*"]` both matching `x` removes it once without error |

### fsck tests

| Test | What it verifies |
|---|---|
| `fsck_clean_store` | Returns `Ok` on a store with one blob |

### format tests

| Test | What it verifies |
|---|---|
| `format_key_slot_hex_prefix` | `"0x82"` parsed correctly; format succeeds |
| `format_key_slot_decimal` | `"130"` (= `0x82`) parsed correctly; format succeeds |
| `format_key_slot_invalid_rejected` | `"notanumber"` returns `Err` |

### Cargo changes

- `[lib]` target added to `rust/yb/Cargo.toml` pointing to `src/lib.rs`.
- `yb-core` added as a `[dev-dependency]` with features `["chrono", "virtual-piv"]`.
- `tempfile` added as a `[dev-dependency]` for temporary directories.

## Open questions

None.

## References

- `rust/yb/tests/cli_tests.rs` — implementation
- `rust/yb-core/tests/virtual_piv_tests.rs` — model for VirtualPiv test pattern
- `docs/specs/0007-cli-improvements.md` — CLI commands under test
