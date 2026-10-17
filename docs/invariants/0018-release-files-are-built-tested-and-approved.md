<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0018 — Release Files Are Built, Tested and Approved

**Sources:** spec 0043 (S5, S6); spec 0029 §9

## Invariant

The files of a release are built by CI from the tagged commit, after its
tests pass, and published only after the maintainer approves:

- the crates on crates.io;
- the Windows zips and `SHA256SUMS` on the GitHub release.

Each zip has a build provenance attestation.  No release build enables
the simulated YubiKey (`test-fixture`, invariant 0012).

## Why

Users install what the release offers.  A file built from another
commit, from untested code, or published without the maintainer's
decision would carry yb's name without its checks.  The checksums and the
attestations let users check that what they downloaded is what CI built.

## Where the code keeps it

`.github/workflows/publish.yaml`:

- the build jobs, `verify` and `windows`, run the tests before building;
- the upload jobs, `publish` and `publish-windows`:
  - run on `v*` tags only, after the build jobs they publish;
  - each runs in an environment (`crates-io`, `github-release`) that
    requires the maintainer's approval and only accepts `v*` tags;
  - are the only jobs that can publish: `contents: write`, or the
    `id-token` of crates.io trusted publishing;
- the default token permission is read.

The environments' settings are in the repository settings (spec 0043
S6), outside the code.

## Limits

- The environments' settings (approval, tags only) are not visible to
  the regression check; spec 0043 S6 gives the commands that set them.
- The Windows files are not signed yet (spec 0041).
- Nothing here protects a maintainer's machine or account: a stolen
  account can approve.

## Regression tests

- `scripts/check-release-workflow`: run by CI in the packaging job of
  nix.yaml.  It fails if an upload job loses its environment, its tag condition or its
  dependencies, if another job can publish, if the Windows build stops
  testing first, or if a step enables `test-fixture`.
