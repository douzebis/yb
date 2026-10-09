<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0029 — Build and Test with the nixpkgs Recipe

**Status:** draft
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
  hand).  A Nix target checks that they package and build as crates.io
  will see them; a tag-triggered workflow on a GitHub-hosted runner
  publishes them, after the maintainer's approval (§9).

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
| `crates` | Crane: `cargo package` of `yb-core` and `yb`, `.crate` files in `$out` (§9) |
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

- each binary lists its tests as trials; test bodies are unchanged;
- the binaries keep libtest's output and options (`test result: ok`,
  filters, `--test-threads`), so the VM script keeps working; it passes
  `--test-threads=1` instead of relying on `RUST_TEST_THREADS=1`, unless
  `libtest-mimic` is confirmed to honor the variable;
- `cargo test -p yb-piv-harness --features integration-tests` still runs
  them locally (each bin also has `test = false`, and a thin `[[test]]`
  wrapper or `cargo run --bin` is documented; to settle in review).

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

- The harness embeds its fixtures with `include_str!` and writes them to
  the per-test temp dir it already uses.  `YB_FIXTURE_DIR`,
  `passthru.testFixtures` and the fixture lines of the VM test go away.
  (`YB_BIN` stays: the binary under test is a runtime input.)
- The `yb` crate's tests do the same.  `rust/yb/tests/cli_tests.rs`
  reads its fixtures from `CARGO_MANIFEST_DIR/../yb-core/tests/fixtures`,
  a path into the other crate: it exists in the repository, but not in
  the published `yb` crate, so `cargo test` on the crate downloaded from
  crates.io fails (distribution packagers, e.g. Debian and Fedora, build
  from those tarballs and run the tests).  The fixtures are embedded with
  `include_str!` and written to the temp dir the tests already use; the
  cross-crate path disappears.  (`yb-core`'s fixtures are inside its own
  crate, and are fine.)
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
- New step: the staged `package.nix` `version` equals
  `workspace.package.version`, and `nixfmt --check` passes on the staged
  files (nixpkgs CI requires nixfmt).
- New step in the `check` job: `nix-build -A crates` (§9), on Linux.
- New workflow `publish.yaml`, on tags only, upload gated by approval
  (§9).

### 9. crates.io

`yb-core` and `yb` are published to crates.io (`yb-piv-harness` is not:
`publish = false`).  Publishing needs the network and a credential, so it
cannot happen inside a Nix build; the work is split in two.

**Nix target `crates`** (verification, no upload):

- built with **Crane**, like the other checks (fmt, clippy, tests): it
  reuses Crane's vendored dependencies and its compiled-dependency cache;
- runs `cargo package --workspace --exclude yb-piv-harness --locked`
  offline, on the vendored dependencies.  Since Rust 1.90, packaging a
  workspace resolves `yb`'s dependency on the not-yet-published `yb-core`
  through a local overlay registry, in dependency order.  `cargo package`
  then unpacks each `.crate` and compiles it on its own;
- **to be tried first:** cargo treats packaging specially when crates.io
  is replaced by a vendored source (`cargo publish` refuses outright), so
  whether `cargo package` works offline that way is only known by trying.
  **Fallback** if it does not: `cargo package --no-verify` (still builds
  the `.crate` files and checks metadata and included files), then, in the
  same derivation, unpack the `.crate` files and compile them against the
  vendored dependencies: the same guarantee, a few more lines of Nix;
- with the `yb` fixtures embedded (§5), it also runs the packaged
  crates' tests, as a distribution packager would;
- this builds each `.crate` exactly as crates.io will unpack it: only the
  packaged files, path dependencies turned into versioned ones, the
  packaged `Cargo.lock` that `cargo install --locked yb` uses;
- outputs the `.crate` files in `$out`, so they can be inspected (size,
  file list, `Cargo.toml` as rewritten by cargo).

It catches what the other targets cannot: a file missing from the package
(e.g. `readme = "../../README.md"`), a path dependency without a version,
metadata crates.io rejects.

**Workflow `.github/workflows/publish.yaml`** (upload), on a
GitHub-hosted runner, gated by the maintainer's approval.

A crates.io version can be yanked but never deleted or replaced, so the
upload never starts on its own:

- **Trigger:** a pushed tag `v*`.
- **Two jobs:**
  1. `verify` (no approval, no credential): checks that the tag equals
     `workspace.package.version`, then runs `nix-build -A crates` and
     keeps the `.crate` files as a workflow artifact, for inspection
     before approving.
  2. `publish` (needs `verify`): runs in the GitHub **environment
     `crates-io`**, whose protection rule requires the maintainer's
     approval, and which only tags `v*` may use.  The job waits until the
     maintainer approves it in the GitHub UI (or rejects it: nothing is
     published).  It then runs `cargo publish --workspace --exclude
     yb-piv-harness --locked`, which publishes `yb-core`, then `yb`.
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
- `nix-build -A crates` produces `yb-core-X.Y.Z.crate` and
  `yb-X.Y.Z.crate`; breaking `readme` or removing `yb-core`'s version
  makes it fail.
- The tests of the packaged `yb` crate pass from its unpacked `.crate`
  alone (fixtures embedded, §5).
- `publish.yaml` refuses a tag that differs from the Cargo version, and
  publishes nothing until approved; a rejected approval publishes
  nothing.  Before the 0.5.0 release, it is exercised on a test tag with
  `cargo publish --dry-run` in place of the upload.

## Open questions

Resolved:

- `crates` target: built with Crane; plain `cargo package` tried first,
  with the `--no-verify` + unpack-and-build fallback (§9).
- `yb`'s test fixtures: embedded, fixed in this spec (§5).

Still open:

- Harness binaries: `libtest-mimic`, or plain `[[bin]]` targets with a
  hand-written runner?  (`libtest-mimic` keeps libtest's output and flags,
  which the VM script relies on.)
- How `cargo test` keeps running the harness tests locally once they are
  binaries (§4).
- Should `yb-rust` stay as an alias for a while (scripts, docs), or be
  removed at once?

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
