# 0009 — CLI subprocess tests

**Status:** implemented
**App:** yb
**Implemented in:** 2026-03-21

## Problem

The direct-call tests added in spec 0008 (`rust/yb/tests/cli_tests.rs`)
exercise the command handler functions in isolation.  They bypass:

- `main.rs` argument parsing (clap configuration, flag aliases, env var
  mapping)
- PIN resolution order (`--pin-stdin` > `YB_PIN` > TTY prompt > `None`)
- Management key resolution (`YB_MANAGEMENT_KEY` env var)
- `list-readers` short-circuit (pre-`Context` dispatch)
- Exit codes (`std::process::exit(1)` on error)
- The `--quiet` flag's effect on stderr
- Any wiring bug that lives specifically in `run()` / `main()`

A subprocess test suite — using `std::process::Command` to invoke the
compiled `yb` binary — closes this gap.  It also gives confidence that
clap is configured correctly (e.g. that `--pin` really is hidden, that
`-q` really suppresses output, that `YB_PIN` really is picked up).

The binary currently hard-codes `HardwarePiv::new()`.  Running it against
a real YubiKey in tests is impractical.  The binary needs a test escape
hatch: a hidden env var (`YB_FIXTURE`) that, when set, loads a `VirtualPiv`
from the named YAML fixture file instead of opening a hardware card.

## Goals

1. A hidden `YB_FIXTURE=path/to/fixture.yaml` env var makes the binary use
   `VirtualPiv` instead of `HardwarePiv`.  When set, all PC/SC calls go to
   the virtual backend; no real card is needed.
2. A `yb-cli-tests` integration test binary (in `yb-piv-harness/tests/`)
   exercises the `yb` binary end-to-end via `std::process::Command`, using
   the `YB_FIXTURE` mechanism.  Gated on the `integration-tests` feature,
   same as the existing `hardware_piv_tests`.
3. The subprocess tests cover:
   - All six commands (`format`, `store`, `fetch`, `list`, `remove`, `fsck`)
   - Argument parsing: flag aliases, `YB_PIN` env var, `--pin-stdin`,
     `YB_MANAGEMENT_KEY`, `--quiet`
   - Exit codes (0 on success, 1 on error)
   - `list-readers` (works without a store; does not need `YB_FIXTURE`)
4. The new test binary is compiled (but not run) in the `harnessTestBin`
   Nix derivation, installed alongside `hardware_piv_tests`, and run in the
   NixOS VM test script.
5. Tier-1 `cargo test` (without `integration-tests` feature) is unaffected.

## Non-goals

- Testing `rpassword` interactive TTY prompt (requires a real TTY; manual
  testing only).
- Fuzzing or property-based testing.
- Testing the Python `yb` CLI.

## Specification

### `YB_FIXTURE` escape hatch (S1)

Add to `yb-core/src/context.rs`, inside `Context::new`:

```rust
let piv: Arc<dyn PivBackend> = if let Ok(path) = std::env::var("YB_FIXTURE") {
    Arc::new(VirtualPiv::from_fixture(std::path::Path::new(&path))?)
} else {
    Arc::new(HardwarePiv::new())
};
```

`VirtualPiv` is gated on the `virtual-piv` feature in `yb-core`.  The `yb`
binary must enable this feature in its dependency on `yb-core`.  Since `YB_FIXTURE`
is only ever set in tests, the feature needs to be compiled in but the code path
is dead in production use.

The `list-readers` command bypasses `Context::new` entirely and calls
`HardwarePiv::new()` directly (spec 0007, S7).  For subprocess tests, a
separate mechanism is needed: `list-readers` should also check `YB_FIXTURE`
and, if set, use the fixture's reader list instead.

Concretely: `cli/list_readers.rs::run()` checks `YB_FIXTURE`; if set,
instantiates `VirtualPiv::from_fixture` and calls `list_readers()` on it.

`YB_FIXTURE` is never documented in `--help` output.

### Subprocess test binary (S2)

New file: `rust/yb-piv-harness/tests/yb_cli_tests.rs`

Gated with:
```rust
#![cfg(feature = "integration-tests")]
```

The binary path is obtained via:
```rust
const YB_BIN: &str = env!("CARGO_BIN_EXE_yb");
```

This requires `yb` to be a `[[bin]]` in the same workspace, which it already
is.  Cargo populates `CARGO_BIN_EXE_yb` automatically for integration tests
in the same workspace.

A helper runs a command and returns `(exit_code, stdout, stderr)`:
```rust
fn yb(fixture: &str, env: &[(&str, &str)], args: &[&str])
    -> (i32, String, String)
```
It sets `YB_FIXTURE=fixture`, `YB_SKIP_DEFAULT_CHECK=1`, and merges any
additional env vars, then runs `Command::new(YB_BIN)`.

A `formatted_fixture` helper writes a `with_key.yaml`-derived fixture to a
`TempDir`, calls `yb format` on it (via `YB_FIXTURE`), and returns the
`TempDir` (keeping it alive for the test duration).

#### Test matrix

**format**
- `format_creates_store`: `yb format -g` with `YB_MANAGEMENT_KEY` set →
  exit 0; subsequent `yb list` succeeds.

**store / fetch / list / remove round-trip**
- `store_and_list`: store a file unencrypted → `yb list` output contains
  the blob name.
- `store_and_fetch_stdout`: store a file → `yb fetch -p NAME` → stdout
  matches file contents.
- `store_and_fetch_to_file`: store → `yb fetch -O DIR NAME` → file written
  with correct contents.
- `store_encrypted_fetch`: store encrypted (`-e`) → `yb fetch -p NAME` with
  `YB_PIN` set → plaintext recovered.
- `store_glob_fetch`: store three blobs → `yb fetch -O DIR 'key-*'` →
  two matching files written, third absent.
- `remove_and_list`: store two blobs → `remove NAME` → `yb list` no longer
  shows removed blob.
- `remove_glob`: store `tmp-a`, `tmp-b`, `keep` → `remove 'tmp-*'` →
  only `keep` remains in `yb list`.
- `remove_missing_errors`: `yb remove ghost` → exit 1.
- `remove_ignore_missing`: `yb remove -f ghost` → exit 0.

**argument / flag tests**
- `quiet_suppresses_stderr`: `yb -q store FILE` → exit 0, stderr empty.
- `pin_from_env`: store encrypted blob; fetch with `YB_PIN=123456` → exit 0.
- `pin_from_stdin`: store encrypted blob; echo PIN | `yb --pin-stdin fetch -p` → exit 0.
- `deprecated_pin_flag_warns`: `yb --pin 123456 fetch -p NAME` → exit 0,
  stderr contains `"Warning: --pin is deprecated"`.
- `deprecated_key_flag_warns`: `yb --key HEXKEY ...` → exit 0, stderr
  contains `"Warning: --key is deprecated"`.
- `deprecated_extract_flag_warns`: `yb fetch -x NAME` with `-O DIR` →
  exit 0, stderr contains `"Warning: --extract is deprecated"`.

**fsck**
- `fsck_clean`: store a blob → `yb fsck` → exit 0, stdout contains
  `"Status: OK"`.
- `fsck_verbose`: → `yb fsck -v` → stdout contains `"Object 0:"`.

**list-readers**
- `list_readers_with_fixture`: `YB_FIXTURE` set → `yb list-readers` →
  exit 0, stdout contains the virtual reader name from the fixture.

**error paths**
- `fetch_missing_exits_1`: `yb fetch ghost` → exit 1.
- `store_no_name_stdin_exits_1`: `yb store` (no files, no `--name`) → exit 1.
- `store_duplicate_basename_exits_1`: two files with same basename → exit 1.
- `fetch_stdout_multi_match_exits_1`: `yb fetch --stdout '*'` with multiple
  blobs → exit 1.

### Nix changes (S3)

In `harnessTestBin`, the `installPhase` currently extracts only
`hardware_piv_tests`.  Extend it to also extract `yb_cli_tests`:

```nix
installPhase = ''
  mkdir -p $out/bin

  for name in hardware_piv_tests yb_cli_tests; do
    bin=$(find target -name "$name-*" -executable -type f \
            ! -name '*.d' ! -name '*.rmeta' \
            -printf '%T@ %p\n' | sort -rn | head -1 | cut -d' ' -f2-)
    if [ -z "$bin" ]; then
      echo "ERROR: $name binary not found under target/" >&2
      exit 1
    fi
    echo "Installing $bin -> $out/bin/$name"
    cp "$bin" $out/bin/$name
  done
'';
```

The VM `testScript` gains a second run step:

```python
# Tier-2: hardware PIV tests
out = machine.succeed("RUST_TEST_THREADS=1 hardware_piv_tests 2>&1")
print(out)
if "test result: ok" not in out:
    raise Exception("Tier-2 hardware_piv_tests failed:\n" + out)

# Tier-2: CLI subprocess tests
out = machine.succeed(
    f"RUST_TEST_THREADS=1 YB_BIN={ybRustBin}/bin/yb yb_cli_tests 2>&1"
)
print(out)
if "test result: ok" not in out:
    raise Exception("Tier-2 yb_cli_tests failed:\n" + out)
```

The `ybRust` derivation (the built `yb` binary) is added to
`environment.systemPackages` in the NixOS VM node so the CLI tests can
locate it via `YB_BIN` or `CARGO_BIN_EXE_yb`.

Since `CARGO_BIN_EXE_yb` is a compile-time constant baked in by Cargo, the
pre-built binary path in the Nix store will differ from the path at compile
time.  The `yb_cli_tests` binary therefore should not rely on
`CARGO_BIN_EXE_yb` when run pre-built; instead, it should check
`YB_BIN` env var first and fall back to `CARGO_BIN_EXE_yb`:

```rust
fn yb_bin() -> &'static str {
    // In the NixOS VM the binary is injected via YB_BIN.
    // In a local `cargo test` run CARGO_BIN_EXE_yb is correct.
    std::env::var_os("YB_BIN")
        .map(|p| Box::leak(p.into_string().unwrap().into_boxed_str()) as &str)
        .unwrap_or(env!("CARGO_BIN_EXE_yb"))
}
```

### Feature flags

The `virtual-piv` feature in `yb-core` is already defined but not enabled
in the `yb` crate's dependency.  Add it:

```toml
# rust/yb/Cargo.toml
yb-core = { path = "../yb-core", features = ["chrono", "virtual-piv"] }
```

`YB_FIXTURE` support in the binary is compiled in whenever `virtual-piv` is
enabled (i.e. always for the `yb` binary, since `virtual-piv` is now a
default feature of `yb`'s dependency).

### Fixture files

The subprocess tests use the existing `with_key.yaml` fixture from
`rust/yb-core/tests/fixtures/`.  Each test that needs a formatted store:
1. Copies the fixture to a `TempDir` (so each test gets a private mutable copy).
2. Calls `yb format -g` against it (generating a fresh key + cert in slot
   `0x82`) before the actual test steps.

Fixture copy is necessary because `VirtualPiv` state is in-memory and scoped
to one process invocation; each `yb` subprocess gets a fresh load from the
YAML file.  The YAML file itself is read-only — `VirtualPiv` mutations (stored
objects, generated keys) are not persisted back to disk.  Therefore, format
must be re-run in every subprocess test that needs a store.

### `YB_SKIP_DEFAULT_CHECK`

All subprocess test invocations must set `YB_SKIP_DEFAULT_CHECK=1` to
suppress the default-credentials check in `Context::new`, which would
otherwise fail against the fixture's well-known management key.

## Open questions

None.

## References

- `docs/specs/0007-cli-improvements.md` — CLI commands under test
- `docs/specs/0008-cli-tests.md` — direct-call tests (complementary)
- `docs/specs/0004-tier2-hardware-piv-tests.md` — tier-2 harness architecture
- `docs/specs/0005-nix-integration-test-build.md` — NixOS VM test wiring
- `rust/yb-piv-harness/tests/hardware_piv_tests.rs` — model for test structure
- `rust/yb-core/tests/fixtures/with_key.yaml` — fixture used by tests
