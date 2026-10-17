<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0043 — Windows, Phase 1: Legacy Stores, CI and Preview Releases

**Status:** draft
**App:** yb, yubiblob, CI (repo-wide)
**Implemented in:** <!-- YYYY-MM-DD, fill after implementation -->

## Problem

yb is not shipped for Windows (spec 0041, "Problem").  Today:

- yb-core and libyubiblob build there, for legacy stores only.
- The CI job `windows-libyubiblob` tests libyubiblob and builds the C
  library.
- The `yb` command is neither built nor tested on Windows.
- No release carries Windows files.

Full support needs post-quantum stores through Windows' WebAuthn API.
That needs a spike on a real YubiKey, and no Windows machine is
available yet (spec 0041, Q6).  Most of the remaining work needs neither:

- building and testing on GitHub's Windows runners;
- packaging;
- publishing with each release.

This spec is that first phase.  Spec 0041 keeps the rest:

- post-quantum stores;
- signing;
- winget and cargo-binstall.

The model is the release workflow of yb (`publish.yaml`, crates.io) and of
prototools (crates.io and PyPI):

1. a pushed `v*` tag starts it;
2. build jobs make the artifacts, which can be inspected;
3. each upload job waits for the maintainer's approval, in a GitHub
   environment that only accepts `v*` tags;
4. no secret is stored;
5. a failed upload is finished by re-running its job.

## Goals

- G1. **`yb.exe` on Windows, legacy stores:** every command that works
  on Linux on a legacy store works on Windows.
  - On a post-quantum store, yb fails clearly ("not supported on
    Windows").
  - The guided format offers legacy stores only.
- G2. **CI on `windows-latest`,** on every push and pull request:
  - the tests of the published crates;
  - the release build of `yb.exe`;
  - the C library.
- G3. **Release files for each `v*` tag,** built on `windows-latest` from
  the tagged commit after the tests pass:
  - `yb-<version>-windows-x86_64.zip`;
  - `libyubiblob-<version>-windows-x86_64.zip`;
  - `SHA256SUMS`;
  - a build provenance attestation for each zip.
- G4. **Publication behind an approval gate:** the files go to the tag's
  GitHub release only after the maintainer approves, in the
  `github-release` environment.
  - The environment accepts `v*` tags only.
  - The workflow's own token is used, with write access in that job
    only.
  - Re-running the job finishes a half-done upload.
- G5. **A dry run without a tag:** a manual run of the workflow builds
  and tests everything, keeps the files as artifacts, and publishes
  nothing.
- G6. **"Preview" until checked on a real YubiKey:**
  - the release notes and the README call the Windows files a preview;
  - one run of the legacy checklist on a real YubiKey lifts it (S8).
- G7. **The one-time GitHub setup** is documented step by step, with the
  equivalent `gh api` commands (S6).

## Non-goals

These belong to spec 0041 (later phases):

- post-quantum stores on Windows;
- libfido2 on Windows;
- the spike.
- Signing, winget, cargo-binstall.
- Windows on Arm.
- An MSI installer.
- Linux and macOS binary zips: nixpkgs and `cargo install` serve those
  platforms.  The workflow can grow them later.
- Hardware tests in CI.
- `yb_cli_tests` on Windows: it stays in the NixOS VM.
- PowerShell completion.

## Specification

### S1. What Windows gets

- **The same `yb`:** commands, options, exit statuses (0–4) and
  messages, on legacy stores.  Spec 0028's Windows exception stays:
  - yb-core is built without its `fido2` module;
  - post-quantum code is compiled out.
- **On a post-quantum store,** every command fails with "post-quantum
  stores are not supported on Windows" (already the case).
- **The guided format** goes straight to a legacy store, without the
  question "what kind of store?" (already the case, `guided.rs`).
- **libyubiblob:** unchanged.  A post-quantum store gives
  `YUBIBLOB_ERR_INTERNAL` with that message (already the case).

### S2. Code changes

Only what the first Windows runs need.  Each fix keeps Unix behavior
unchanged and comes with the test that showed it.  Known so far:

- **`yb/tests/cli_tests.rs`:** the guided-format helper answers "2"
  (legacy) to the store-kind question.  On Windows the question is not
  asked, so the helper must not answer it there (`cfg`).
- **`fetch` output:** bytes are written as stored, with no CRLF
  translation.  If no test checks this with a binary payload, one is
  added.
- **Console encoding:** if the Windows run shows non-ASCII blob names
  garbled, `yb` sets the console's output code page to UTF-8 at start.
  - It uses `SetConsoleOutputCP(65001)` through the `windows-sys`
    crate, a Windows-only dependency.

### S3. The CI job

In `.github/workflows/nix.yaml`, `windows-libyubiblob` becomes
`windows`:

```yaml
  # yb and libyubiblob on Windows (spec 0043): plain cargo, against the
  # simulated YubiKey; PC/SC comes from Windows (WinSCard).  Without FIDO2
  # (no libfido2): legacy stores only (spec 0028 D9).
  windows:
    runs-on: windows-latest
    env:
      RUSTFLAGS: -C target-feature=+crt-static
    steps:
      - uses: actions/checkout@<sha> # v7.0.1
      - uses: dtolnay/rust-toolchain@<sha>
        with:
          toolchain: <the release toolchain, S5>
      - name: Test the published crates
        run: >-
          cargo test --locked --manifest-path rust/Cargo.toml
          -p yb-core -p yb -p yubiblob -p clap-complete-rawline
      - name: Build yb
        run: cargo build --locked --release --manifest-path rust/Cargo.toml -p yb
      - name: Build the C library (cargo-c)
        run: |
          cargo install cargo-c --locked --version <pinned>
          cargo cbuild --locked --release --manifest-path rust/Cargo.toml -p yubiblob
```

Notes:

- **The crates tested** are those the Linux `msrv` job tests: the
  published ones.
- **The static C runtime** (`crt-static`) means `yb.exe` and
  `yubiblob.dll` need no Visual C++ Redistributable.  CI tests the same
  build that is shipped.
- **Actions are pinned by commit,** as in `publish.yaml`.

### S4. The release files

| File | Content |
|---|---|
| `yb-<V>-windows-x86_64.zip` | `yb.exe`, `LICENSE`, `README.md` |
| `libyubiblob-<L>-windows-x86_64.zip` | `bin/yubiblob.dll`, `lib/yubiblob.dll.lib`, `lib/yubiblob.lib`, `include/yubiblob.h`, `lib/pkgconfig/yubiblob.pc`, `LICENSE`, `README.md` |
| `SHA256SUMS` | SHA-256 of both zips, `sha256sum` format |

- `<V>` is the tag's version, which is also the workspace version
  (checked by `verify`).
- `<L>` is libyubiblob's own version (`rust/yubiblob/Cargo.toml`).
- The zips hold no top-level folder: unpacking gives the files.
- A provenance attestation is made for each zip
  (`actions/attest-build-provenance`).  Users check it with
  `gh attestation verify <zip> --repo douzebis/yb`.

### S5. The release workflow

`.github/workflows/publish.yaml` becomes "Publish", for crates.io and the
GitHub release.

**Triggers:**

```yaml
on:
  push:
    tags: ["v*"]
  workflow_dispatch: # dry run: build and test, publish nothing
```

**Jobs:**

| Job | Runner | Runs on | Needs | Environment | Token permissions |
|---|---|---|---|---|---|
| `verify` (existing) | ubuntu | tag; dispatch (skips the tag check) | — | — | read |
| `windows` | windows | tag; dispatch | — | — | read; `id-token`, `attestations` write (provenance) |
| `publish` (existing, crates.io) | ubuntu | tag only | `verify` | `crates-io` | read; `id-token` write |
| `publish-windows` | ubuntu | tag only | `verify`, `windows` | `github-release` | `contents` write |

**The `windows` job:**

1. the steps of the CI job (S3), with the same toolchain;
2. `cargo cinstall` into a staging folder;
3. the two zips (PowerShell `Compress-Archive`), and `SHA256SUMS`;
4. the attestations;
5. the upload of the artifact `windows`: the two zips and `SHA256SUMS`.

**The release toolchain** is the Rust version of the Nix build at the
time of the release.  It is written in the workflow and bumped
deliberately, so that a release does not change compilers silently.

**The `publish-windows` job** (`if: startsWith(github.ref,
'refs/tags/v')`):

1. downloads the artifact `windows`;
2. if the tag has no GitHub release, creates one:
   - `gh release create <tag> --verify-tag`, titled `yb <V>`;
   - its notes come from `scripts/release-notes <V>`;
3. uploads the three files (`gh release upload <tag> … --clobber`),
   which replaces those already there, so a re-run finishes the job.

**Existing releases:** a release made by hand before the job runs is
kept, with its title and notes; only the files are added.

**What a failure stops:**

- If `verify` or `windows` fails, no upload runs.
- `publish` (crates.io) and `publish-windows` are independent once both
  builds have passed.  Each waits for its own approval.

**`scripts/release-notes <V>`** prints:

- the section `## [<V>]` of `CHANGELOG.md`;
- then the Windows paragraph (S8).

It fails if the section is missing, so a release cannot go out without
its changelog entry.

### S6. One-time GitHub setup

This is done once, by the maintainer, before the first tagged release
with Windows files.

**1. The `github-release` environment** (Settings → Environments → New
environment):

- name: `github-release`;
- **Required reviewers:** `douzebis`;
- **Deployment branches and tags:** "Selected branches and tags", add
  the rule `v*` of type **tag**;
- no secrets and no variables.

These are the settings of `crates-io` today.  With `gh`:

```shell
id=$(gh api users/douzebis --jq .id)
gh api -X PUT repos/douzebis/yb/environments/github-release --input - <<EOF
{"reviewers": [{"type": "User", "id": $id}],
 "deployment_branch_policy": {"protected_branches": false,
                              "custom_branch_policies": true}}
EOF
gh api -X POST repos/douzebis/yb/environments/github-release/deployment-branch-policies \
  -f name='v*' -f type=tag
```

**2. Workflow permissions** (Settings → Actions → General):

- leave the default token permission at **read**;
- the jobs that need more ask for it themselves (S5).

**3. Release tags (recommended):** a tag ruleset (Settings → Rules →
Rulesets → New tag ruleset):

- target `v*`;
- restrict creations, updates and deletions;
- bypass for the repository admin.

Only the maintainer can then push or move a release tag.  The
environments already refuse anything but `v*` tags, and this stops a
`v*` tag from being made by anyone else.

**4. Dry run:**

1. Actions → Publish → Run workflow, on `main`;
2. check that `verify` and `windows` pass;
3. check that `publish` and `publish-windows` are skipped;
4. download the artifact `windows`, and check the zips' contents and
   `SHA256SUMS`.

### S7. Releasing

The procedure stays the one of spec 0029 §7, documented in
`nixpkgs/README.md`.  Its step 2 becomes:

2. commit, push `main`, and wait for CI.  Tag `vX.Y.Z` and push the tag.
   "Publish" then runs `verify` and `windows`, and waits.
   - Inspect the artifacts `crates` and `windows`.
   - Approve the two deployments, `crates-io` and `github-release`, on
     the run's page.
   - If an upload fails, re-run that job only.

`nixpkgs/README.md` is updated to match.

### S8. The preview

Windows files are a **preview** until one run of the legacy checklist on
a real YubiKey.

**The release notes paragraph** (`scripts/release-notes`):

> **Windows (preview).**  `yb-<V>-windows-x86_64.zip` and libyubiblob
> are built and tested by CI against a simulated YubiKey, not yet on a
> real one: please report problems.  Legacy stores only: post-quantum
> stores are not supported on Windows yet.  Check the download with
> `SHA256SUMS`, or `gh attestation verify <zip> --repo douzebis/yb`.

**The README** gains a section "Windows (preview)":

- download and unpack;
- put `yb.exe` on the PATH;
- check the download (`Get-FileHash`, or `gh attestation verify`);
- legacy stores only;
- the Smart Card service must be running (the default).

libyubiblob's README mentions the Windows zip.

**The checklist,** in `docs/testing-windows.md`, on a real YubiKey with
legacy stores:

- `yb list-readers`, and the device picker with two YubiKeys if
  available;
- `yb format` (guided and with flags);
- `store`, `fetch` (to a file and to standard output), `ls`, `fsck`,
  `rm`;
- a wrong PIN;
- the YubiKey removed during a `store`;
- a store made on Linux read on Windows, and the reverse;
- libyubiblob: the C smoke test (`rust/yubiblob/tests/c/smoke.c`),
  built with MSVC against the zip.

**Lifting the preview:**

- one full pass of the checklist, recorded in that file with its date,
  Windows version and YubiKey firmware;
- then the paragraph above and the README drop "preview";
- the hardware checks then repeat before releases that touch PC/SC or
  Windows code.

## Invariants

- New: **Release files are built from the tagged commit, after its
  tests pass, and published only with the maintainer's approval, with
  their checksums and provenance.**
  - It goes in `docs/invariants/0018-release-files.md`.
  - Its regression check is `scripts/check-release-workflow`.  It reads
    `publish.yaml` with `yq` (release shell) and fails unless:
    - every upload job has an environment, `needs` its build jobs, and
      runs on tags only;
    - only the upload jobs can publish: `contents: write`, or the
      `id-token` of trusted publishing.  The Windows build gets only
      what its attestations need (`id-token`, `attestations`);
    - the Windows build runs the tests before building.
  - It runs in CI (the `check` job) and is named in the invariant file
    for `scripts/check-invariants`.
- Existing invariants hold on Windows for legacy stores.  Invariant
  0012 (test fixtures out of shipped builds) applies to the Windows zips
  too: they are built without `test-fixture`, and
  `scripts/check-release-workflow` checks that no build step enables it.

## Open questions

None.

## References

- [spec 0041](0041-windows-support-and-release-channel.md): later phases
  (post-quantum, signing, package managers).
- [spec 0028](0028-post-quantum-protection.md): D9 (libfido2, the
  Windows exception).
- [spec 0029](0029-nixpkgs-aligned-build.md): the release procedure
  (§7), crates.io publishing (§9).
- [spec 0039](0039-c-api.md): libyubiblob.
- `.github/workflows/publish.yaml`, `nix.yaml`.
- prototools: `.github/workflows/publish.yaml` (crates.io and PyPI,
  approval per environment), the model for this one.
- GitHub: environments and deployment protection rules, tag rulesets,
  artifact attestations (`actions/attest-build-provenance`), `gh release`.
