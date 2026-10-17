# nixpkgs staging

The files under `pkgs/` and `nixos/` are yb's nixpkgs package and its NixOS
VM test, laid out as in the nixpkgs tree:

| Here | In nixpkgs |
|---|---|
| `pkgs/by-name/yb/yb/package.nix` | same path |
| `nixos/tests/yb.nix` | same path |

They are the single recipe for yb's release build and VM test (spec 0029):
the repository's `default.nix` builds them from the local source
(`nix-build -A yb`, `nix-build -A integration-tests`), so CI tests exactly
what a nixpkgs PR submits.  Keep them in nixpkgs style (nixfmt, no SPDX
header: their licensing is declared in `REUSE.toml`), and copy them into
nixpkgs verbatim.  `nix-build -A nixpkgs-staging-check` checks the
formatting and the version: between releases, `rust/Cargo.toml` has the
next version with a `-dev` suffix (e.g. `0.5.0-dev`) and the staged
`version` is the one nixpkgs ships, which must be older; for a release,
both are equal.

The test is registered in `nixos/tests/all-tests.nix` with:

```nix
yb = pkgs.callPackage ./yb.nix { inherit (pkgs.yb.passthru) ybPivHarnessTests; };
```

The other files (`pr-description.md`, `review-response.md`,
`discourse-post.md`) are notes from the PRs.

## Releasing

1. In `rust/Cargo.toml`, drop the `-dev` suffix from
   `workspace.package.version` and from the `yb-core` version under
   `workspace.dependencies`; run `cargo update -w`.  Rename `[Unreleased]`
   in `CHANGELOG.md`.  Set the same `version` in
   `pkgs/by-name/yb/yb/package.nix` (the check above requires it).
2. Commit, push `main`, and wait for CI.  Tag `vX.Y.Z` (`git tag -s`),
   push the tag.
3. `.github/workflows/publish.yaml` builds and tests, then waits for two
   approvals (spec 0043):
   - **crates.io:** `verify` packages and tests the crates
     (`scripts/check-crates`; artifact `crates`).  Approve the
     `crates-io` deployment; it publishes `yb-core`, then `yb`
     (`scripts/publish-crates`).
   - **GitHub release, Windows files:** `windows` tests and builds yb
     and libyubiblob on Windows (artifact `windows`: the two zips and
     `SHA256SUMS`, with provenance).  Approve the `github-release`
     deployment; it creates the release if missing (notes from
     `scripts/release-notes`, so the `CHANGELOG.md` section must exist)
     and adds the files.

   Inspect the artifacts before approving.  If an upload fails halfway,
   re-run its job: crates already published are skipped, and release
   files are replaced.  A manual run of the workflow is a dry run: it
   builds and tests, and publishes nothing.
4. nixpkgs, in a checkout of `master`:
   - copy the two staged files;
   - `nix-update yb` (sets `version`, `hash` and `cargoHash`);
   - if the all-tests.nix line above changed, update it;
   - build `yb` and `nixosTests.yb`, run `nixpkgs-review`, open the PR
     (`yb: A.B.C -> X.Y.Z`).
5. Copy the updated `package.nix` back here (with its new `hash` and
   `cargoHash`), and commit.
6. Start the next cycle: set `rust/Cargo.toml` to the next version with a
   `-dev` suffix (both lines), `cargo update -w`, add an `[Unreleased]`
   section to `CHANGELOG.md`, commit.

## One-time setup for publishing

- GitHub, repository settings: an environment `crates-io` with a
  required reviewer (the maintainer) and a deployment rule limited to
  tags `v*`.
- crates.io, for each of `yb` and `yb-core`: a trusted publisher with
  repository `douzebis/yb`, workflow `publish.yaml`, environment
  `crates-io`; "trusted publishing only" on.

Both are in place (2026-10-09).

- GitHub, repository settings: an environment `github-release`, set like
  `crates-io` (required reviewer, tags `v*` only), for the Windows files
  (spec 0043 S6, which also gives the `gh api` commands).  Not yet in
  place.
