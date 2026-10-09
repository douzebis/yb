<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0029 — Build and Test with the nixpkgs Recipe

**Status:** in-progress
**App:** yb
**Implemented in:** <!-- YYYY-MM-DD, fill after implementation -->

## Problem

yb is built by two independent Nix recipes:

- **the repo's `default.nix`**, written with Crane: rustfmt, clippy, unit
  tests, the release binary, the tier-2 harness binaries and a NixOS VM
  test;
- **the nixpkgs package** (`pkgs/by-name/yb/yb/package.nix`, merged in
  NixOS/nixpkgs#514826 for 0.4.2), written with
  `rustPlatform.buildRustPackage`, plus its VM test
  (`nixos/tests/yb.nix`).  A copy is staged in the repo under
  `nixpkgs/`.

Consequences:

- **CI never builds the nixpkgs recipe.**  Mistakes in it (completion
  patches, the harness `buildPhase`, fixtures) only show up in the
  nixpkgs PR, under review.
- **The staged copy drifts.**  nixpkgs changed the package twice after the
  merge (`stdenv.hostPlatform.isLinux`, 2026-08-12; bindgen variables into
  `env`, 2026-08-19); the staged copy has neither.
- **Every packaging fix is written twice**, once per API (bindgen
  variables, fixtures, completion patches, harness binary extraction).
- **Reviewer comments are still open** in the nixpkgs recipe: "use the
  default buildPhase" and "this seems rather complicated" (the
  `find …-<hash>` lookup of the harness test binaries).  Both come from
  building the harness as `cargo test --no-run` output.
- **Test fixtures need plumbing:** the VM test ships `with_key.yaml` and
  `default.yaml` as a separate store path (`passthru.testFixtures`) and
  points the harness at it with `YB_FIXTURE_DIR`, because the build-time
  path baked into `CARGO_MANIFEST_DIR` no longer exists in the VM.
- **A version bump touches four places:** `rust/yb/Cargo.toml`,
  `rust/yb-core/Cargo.toml` (twice: its version and yb's dependency on
  it), and `default.nix`.

## Rationale: Crane and rustPlatform

Crane was chosen at the Rust port (spec 0001) without a recorded reason,
before nixpkgs packaging of the Rust version was considered.  It has real
benefits for development:

- `buildDepsOnly` compiles the ~330 dependencies once; fmt, clippy, tests
  and the binary reuse them, so a change to yb rebuilds only yb.  CI runs
  these jobs on four platforms.
- `cargoFmt`, `cargoClippy`, `cargoTest` are ready-made.
- No dependency hash to maintain: Crane reads `Cargo.lock` directly,
  including the five git dependencies of the harness (`piv-authenticator`
  and four trussed crates), fetched by their pinned revisions.

nixpkgs does not accept Crane; its recipe must use `rustPlatform`.
Keeping Crane for everything means the nixpkgs recipe stays untested.

**Decision:** keep Crane for the fast development checks, and make the
staged nixpkgs files the single recipe for the release build and the VM
test, built from the local source.

## Goals

- `nix-build -A yb` builds yb with the staged
  `nixpkgs/pkgs/by-name/yb/yb/package.nix`, from the local source.
- `nix-build -A integration-tests` runs the staged
  `nixpkgs/nixos/tests/yb.nix` against that build.
- CI builds and tests exactly what a nixpkgs PR will submit.
- Preparing a nixpkgs PR is: copy the staged files, run `nix-update`.
- The harness builds with the default `rustPlatform` phases (answers the
  open review comments).
- No `testFixtures` / `YB_FIXTURE_DIR` plumbing.
- One place for the version.
- yb and yb-core stay published on crates.io (both at 0.4.2, published by
  hand).  A script, run with a Nix-pinned toolchain, checks that they
  package, build and test as crates.io will see them; a tag-triggered
  workflow on a GitHub-hosted runner publishes them, after the
  maintainer's approval (§9).

## Non-goals

- Bash completion quirks (the `substituteInPlace` patches): spec 0020.
- The 0.5.0 release and its nixpkgs PR.  This spec prepares them.
- A flake.
- Generating man pages and completions without running the binary
  (cross-compiled builds keep skipping them, as nixpkgs accepts today).
- Moving the Cargo workspace from `rust/` to the repo root.
- Dropping Crane.

## Specification

### 1. Staged nixpkgs files are the source of truth

- `nixpkgs/pkgs/by-name/yb/yb/package.nix` and `nixpkgs/nixos/tests/yb.nix`
  are re-synced with nixpkgs `master` first (the two post-merge changes),
  then edited only as described here.
- They stay in nixpkgs style and are copied into nixpkgs verbatim: no SPDX
  header in the files; their licensing is declared in `REUSE.toml`.  The
  orphaned `nixpkgs/package.nix.license` is removed.
- `nixpkgs/README.md` (new, short) says what the directory is, and the
  PR procedure (§7).

### 2. Local build from the staged recipe

`default.nix` builds yb through an overlay, so that the VM test, which
installs `pkgs.yb`, sees the local build:

```nix
pkgsLocal = pkgs.extend (final: prev: {
  yb = (final.callPackage ./nixpkgs/pkgs/by-name/yb/yb/package.nix { })
    .overrideAttrs (finalAttrs: prev: {
      version = cargoVersion;            # §6
      src = localSource;                 # filtered ./. (Cargo sources, fixtures)
      cargoDeps = final.rustPlatform.importCargoLock {
        lockFile = ./rust/Cargo.lock;
        outputHashes = { /* one per git dependency, §3 */ };
      };
    });
});
```

- `src` comes from the working tree, not the GitHub tag.
- `cargoDeps` comes from `Cargo.lock` with `importCargoLock`: no hash to
  update when crates.io dependencies change.
- The package's `passthru.tests.integration` refers to `nixosTests.yb`;
  locally, `integration-tests` is built as nixpkgs's `all-tests.nix` does:
  `pkgsLocal.callPackage ./nixpkgs/nixos/tests/yb.nix { inherit
  (pkgsLocal.yb.passthru) ybPivHarnessTests; }`.

For the override to reach the harness derivation, `package.nix` makes it
reuse the package's dependencies: `inherit (finalAttrs) cargoDeps` instead
of `cargoHash` (a change to submit to nixpkgs; behavior is the same there).

Exposed attributes:

| Attribute | Recipe |
|---|---|
| `yb` (and `default`) | staged `package.nix`, local source |
| `integration-tests` | staged `nixos/tests/yb.nix`, against `yb` |
| `rust-fmt`, `rust-clippy`, `rust-tests` | Crane, unchanged |
| `release-shell` | toolchain for `scripts/check-crates` and the crates.io upload (§9) |
| `nixpkgs-staging-check` | `nixfmt` and version of the staged files (§8) |
| `dev-shell` | unchanged |
| `yb-rust` | alias of `yb`, kept for compatibility, then removed |

The Crane `ybRust`, `harnessTestBin`, `testFixtures` and its VM test are
removed.

### 3. Git dependency hashes

`importCargoLock` needs one `outputHashes` entry per git dependency (five
today, all from the harness's `piv-authenticator`).  They change only when
those pins change.  A comment next to them says how to refresh them (build
with a fake hash, copy the reported one).

### 4. Harness test binaries as named binaries

`hardware_piv_tests` and `yb_cli_tests` (46 tests) become `[[bin]]`
targets of `yb-piv-harness`, required feature `integration-tests`, using
`libtest-mimic`:

- each binary lists its tests as trials; test bodies are unchanged
  (libtest-mimic catches panics, so `assert!` still fails a test);
- the binaries keep libtest's output and options (`test result: ok`,
  filters, `--test-threads`).  libtest-mimic does not read
  `RUST_TEST_THREADS`, so the VM script passes `--test-threads=1`;
- binaries cannot use dev-dependencies: the test-only dependencies
  (`yb-core`, `p256`, `rand`, `tempfile`, `libtest-mimic`) become optional
  dependencies enabled by `integration-tests`;
- each bin has `test = false`; `cargo test` does not run them (it never
  could: they need pcscd with a virtual reader).  Locally, in the
  nix-shell: `cargo run -p yb-piv-harness --features integration-tests
  --bin <name>`.

The `ybPivHarnessTests` derivation in `package.nix` then uses the default
phases:

```nix
ybPivHarnessTests = rustPlatform.buildRustPackage {
  pname = "yb-piv-harness-tests";
  inherit (finalAttrs) version src cargoRoot cargoDeps;
  buildAndTestSubdir = "rust/yb-piv-harness";
  cargoBuildFlags = [ "--features" "integration-tests" ];
  nativeBuildInputs = [ pkg-config rustPlatform.bindgenHook ];
  buildInputs = lib.optionals stdenv.hostPlatform.isLinux [ pcsclite ];
  doCheck = false;
};
```

No custom `buildPhase`, no `installPhase`, no `find`.

### 5. Fixtures compiled in, bindgen hook

- The fixtures are compiled into `yb-core`, which owns them
  (`rust/yb-core/tests/fixtures/`, part of its package):
  `yb_core::piv::virtual_piv::fixtures::{DEFAULT, WITH_KEY, AES192}`, and
  `VirtualPiv::from_fixture_yaml` loads one.  Other crates use them from
  there, never through a path outside their own package.
  (`include_str!` in each crate, as first drafted, would not work: in the
  published `yb` crate, a path into `../yb-core/` does not exist.)
- The harness writes `WITH_KEY` to the per-test temp dir it already uses.
  `YB_FIXTURE_DIR`, `passthru.testFixtures` and the fixture lines of the
  VM test go away.  (`YB_BIN` stays: the binary under test is a runtime
  input.)
- The `yb` crate's tests use `from_fixture_yaml(fixtures::…)` instead of
  reading `CARGO_MANIFEST_DIR/../yb-core/tests/fixtures`, which does not
  exist in the published `yb` crate (so `cargo test` on the crate
  downloaded from crates.io failed; distribution packagers, e.g. Debian
  and Fedora, build from those tarballs and run the tests).
- Found while testing the packaged crates (§9): `yb-core`'s
  `virtual_piv_tests` needs the `test-utils` feature, which a self
  dev-dependency (`yb-core = { path = "." … }`) turned on.  cargo drops
  path dev-dependencies without a version from the published crate, so
  the test no longer compiled there.  The test target now declares
  `required-features = ["test-utils"]`; `cargo test --features
  test-utils` runs it from the crate alone.
- `rustPlatform.bindgenHook` replaces the hand-set `LIBCLANG_PATH` and
  `BINDGEN_EXTRA_CLANG_ARGS` (needed by `littlefs2-sys`, under
  `piv-authenticator`).  The dev shell keeps its own settings for local
  `cargo` runs.

The nixpkgs `all-tests.nix` line changes accordingly (no `testFixtures`);
the staged directory keeps that one line in `nixpkgs/README.md`.

### 6. One version

- `rust/Cargo.toml` gains `[workspace.package] version = "…"` and
  `[workspace.dependencies] yb-core = { path = "yb-core", version = "…" }`;
  `yb` and `yb-core` use `version.workspace = true` and
  `yb-core.workspace = true`.  `yb-piv-harness` keeps its own (unpublished).
  The two lines sit together in one file (crates.io needs a version on the
  path dependency, and cargo cannot derive it from `workspace.package`).
- `default.nix` reads it: `cargoVersion = (lib.importTOML
  ./rust/Cargo.toml).workspace.package.version`.
- `package.nix` keeps a literal `version`, which `nix-update` edits.  CI
  checks that it equals the Cargo version (§8), so a stale staged recipe
  is caught.

### 7. Release and nixpkgs PR procedure

Documented in `nixpkgs/README.md`:

1. bump `rust/Cargo.toml` (`workspace.package.version`), `cargo update -w`,
   rename `[Unreleased]` in `CHANGELOG.md`;
2. commit, tag `vX.Y.Z`, push the tag; `publish.yaml` verifies the
   crates, then waits for approval; inspect the `.crate` artifact,
   approve, and it publishes `yb-core` and `yb` to crates.io (§9);
3. in a nixpkgs checkout: copy the staged files; `nix-update yb` (sets
   `version`, `hash`, `cargoHash`); build; `nixpkgs-review`;
4. copy the updated `package.nix` back to the staged directory (keeping
   the version and hashes in sync), commit.

`meta.changelog` points to `CHANGELOG.md` at the tag
(`https://github.com/douzebis/yb/blob/v${finalAttrs.version}/CHANGELOG.md`).

### 8. CI

- `check` job: Crane fmt, clippy, unit tests (unchanged).
- `build` job: `nix-build -A yb` on the four platforms (the nixpkgs
  recipe; its check phase runs the `yb` crate tests).
- `integration` job: `nix-build -A integration-tests` (staged VM test).
- New `packaging` job (Linux): `nix-build -A nixpkgs-staging-check` (the
  staged files pass `nixfmt --check`, as nixpkgs CI requires, and the
  staged `version`, evaluated by Nix, equals `workspace.package.version`),
  then `scripts/check-crates` in the release shell (§9).
- New workflow `publish.yaml`, on tags only, upload gated by approval
  (§9).

### 9. crates.io

`yb-core` and `yb` are published to crates.io (`yb-piv-harness` is not:
`publish = false`).  Publishing needs the network and a credential, so it
cannot happen inside a Nix build; the work is split in two.

**Verification: `scripts/check-crates`**, run with network access in
the release shell (`nix-shell default.nix -A release-shell --run
scripts/check-crates`; the dev shell works too):

1. `cargo package --workspace --exclude yb-piv-harness --locked`.
   Online, cargo packages `yb` against the not-yet-published `yb-core`
   through its own temporary registry (Rust 1.90+), and verifies each
   `.crate` by building it on its own.
2. Each `.crate` is unpacked outside the workspace and its tests run
   there, as a distribution packager would: `yb-core` with `--features
   test-utils` (§5); `yb` with `yb-core` patched to the unpacked `yb-core`
   crate (`--config patch.crates-io.yb-core.path=…`), since that version is
   not on crates.io yet at release time.
3. The `.crate` files stay in `rust/target/package/`.

Extra arguments go to `cargo package` (e.g. `--allow-dirty` to check
uncommitted changes; publishing always runs on a clean tagged checkout).

`release-shell` is a `mkShell` with cargo, rustc, pkg-config and (Linux)
pcsclite: the toolchain is pinned by the nixpkgs pin, the dependencies by
`Cargo.lock` (`--locked`, checksums verified by cargo).  `mkShell` sets
`PKG_CONFIG_PATH`, which `pcsc-sys` needs to find pcsclite.

It catches what the other targets cannot: a file missing from the package
(e.g. `readme = "../../README.md"`), a path dependency without a version,
metadata crates.io rejects, tests that only pass inside the workspace.

**Why not inside a Nix build** (tried first, rejected): Nix builds run
offline on vendored dependencies.  Plain `cargo package` refuses when
crates.io is replaced by a vendored source; with `--registry crates-io`,
`yb` still cannot be packaged, as cargo's temporary registry for the
unpublished `yb-core` does not combine with a vendored source (and
`--no-verify` fails the same way).  Making it work meant re-implementing
that registry in shell (package `yb-core`, splice it into a copy of the
vendored sources): fragile, and an anti-pattern.  A fixed-output
derivation (Nix's way to grant network access) needs its output hash in
advance and is not meant to run tests.  Packaging is a networked cargo
task; Nix provides the toolchain.

**Workflow `.github/workflows/publish.yaml`** (upload), on a
GitHub-hosted runner, gated by the maintainer's approval.

A crates.io version can be yanked but never deleted or replaced, so the
upload never starts on its own:

- **Trigger:** a pushed tag `v*`.
- **Two jobs:**
  1. `verify` (no approval, no credential): checks that the tag equals
     `workspace.package.version`, then runs `scripts/check-crates` in the
     release shell and keeps the `.crate` files as a workflow artifact, for
     inspection before approving.
  2. `publish` (needs `verify`): runs in the GitHub **environment
     `crates-io`**, whose protection rule requires the maintainer's
     approval, and which only tags `v*` may use.  The job waits until the
     maintainer approves it in the GitHub UI (or rejects it: nothing is
     published).  It then runs `scripts/publish-crates`, which publishes
     `yb-core`, then `yb` (`cargo publish -p … --locked --no-verify`;
     `--no-verify`: `verify` already built and tested the packages from the
     same tagged source and lock file).
- **Resumable:** `scripts/publish-crates` skips a crate already on
  crates.io at this version (crates.io API: 200 skip, 404 publish,
  anything else stops).  If the upload fails halfway (`yb-core` published,
  `yb` not), re-running the `publish` job finishes the release; nothing
  needs doing by hand, which matters as both crates are set to "trusted
  publishing only".
- **Authentication:** crates.io **trusted publishing**.  At each run,
  the `publish` job exchanges a GitHub OIDC token, scoped to this
  repository, this workflow and the `crates-io` environment, for a
  short-lived crates.io token.  No long-lived secret is stored anywhere.
  Trusted publishing is configured once per crate on crates.io by the
  owner (repository `douzebis/yb`, workflow `publish.yaml`, environment
  `crates-io`).
- **Least privilege:** only the `publish` job gets `id-token: write`;
  `verify` has read-only permissions.  Third-party actions are pinned by
  commit hash.
- `cargo publish` packages again from the same tagged source and lock
  file, so what it uploads matches what `verify` checked.
- **No separate dry run.**  A dry run cannot test what is new at the
  first release, the trusted-publishing setup (it skips authentication),
  and the rest is already exercised: `scripts/check-crates` runs in CI on
  every push, and the tag check, approval gate and tag rule run before any
  upload.  Allowing dry runs before a tag exists would mean loosening the
  workflow (non-tag refs, bypassing the environment).  The first real run
  is the 0.5.0 release, stopped at the approval; a wrong trusted-publisher
  setting fails at the authentication step, before any upload.  (A
  pre-release such as `0.5.0-rc.1` is the way to rehearse the whole chain,
  if ever needed.)

A tag pushed by mistake is harmless: reject (or ignore) the pending
approval and delete the tag.

Manual publishing from the dev shell (`cargo publish` with a personal
token) stays possible as a fallback, e.g. if GitHub is unavailable.

## Tests

- `nix-build -A yb`, `-A integration-tests`, `-A rust-fmt`,
  `-A rust-clippy`, `-A rust-tests` succeed on Linux; `-A yb` on both
  macOS runners (CI).
- The VM test runs all 46 harness tests, against the local build (its
  `yb --version` matches the Cargo version).
- `cargo test -p yb-piv-harness --features integration-tests` still runs
  the harness tests locally (with a virtual card available).
- In a nixpkgs checkout at `master`, the staged files build with a
  `cargoHash` instead of the local override (dry run of §7, without
  opening a PR).
- `scripts/check-crates` produces `yb-core-X.Y.Z.crate` and
  `yb-X.Y.Z.crate`, and the tests of both pass from their unpacked
  `.crate` files alone; a broken `readme` path makes it fail.
- `scripts/publish-crates` skips crates already published at the current
  version (checked locally at 0.4.2: both skipped, nothing uploaded), and
  crates.io answers 404 for an unpublished version.
- `publish.yaml` refuses a tag that differs from the Cargo version, and
  publishes nothing until approved.  Its first real run is the 0.5.0
  release.

## Open questions

None.  Resolved:

- crates.io verification: a script run with network access and a
  Nix-pinned toolchain, not a Nix build (§9).
- `yb`'s test fixtures: compiled into `yb-core` and used from there (§5).
- Harness binaries: `libtest-mimic`; run locally with `cargo run --bin`
  (§4).
- `yb-rust` stays, as an alias of `yb`.

## References

- [spec 0001](0001-rust-port.md) — Rust port, Crane build
- [spec 0002](0002-crate-structure.md) §2.5 — crates.io and nixpkgs publication
- [spec 0003](0003-implementation-plan.md) §6.4 — crates.io publication checklist
- [spec 0005](0005-nix-integration-test-build.md) — NixOS VM integration test
- [spec 0020](0020-bash-completion-patches.md) — bash completion patches (separate)
- NixOS/nixpkgs#514826 — `yb: 0.1.0 -> 0.4.2, rewrite in Rust`, and its review
- `nixpkgs/review-response.md` — review comments and answers
- nixpkgs manual, Rust section: `buildRustPackage`, `importCargoLock`,
  `bindgenHook`
