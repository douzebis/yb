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
formatting and that `version` matches `rust/Cargo.toml`.

The test is registered in `nixos/tests/all-tests.nix` with:

```nix
yb = pkgs.callPackage ./yb.nix { inherit (pkgs.yb.passthru) ybPivHarnessTests; };
```

The other files (`pr-description.md`, `review-response.md`,
`discourse-post.md`) are notes from the PRs.

## Releasing

1. In `rust/Cargo.toml`, bump `workspace.package.version` and the
   `yb-core` version under `workspace.dependencies`; run `cargo update -w`.
   Rename `[Unreleased]` in `CHANGELOG.md`.  Set the same `version` in
   `pkgs/by-name/yb/yb/package.nix` (the check above requires it).
2. Commit, tag `vX.Y.Z`, push the tag.
3. crates.io: `.github/workflows/publish.yaml` packages and tests the
   crates (`scripts/check-crates`), then waits for approval in the
   `crates-io` environment.
   Inspect the `crates` artifact, approve; it publishes `yb-core`, then
   `yb`.
4. nixpkgs, in a checkout of `master`:
   - copy the two staged files;
   - `nix-update yb` (sets `version`, `hash` and `cargoHash`);
   - if the all-tests.nix line above changed, update it;
   - build `yb` and `nixosTests.yb`, run `nixpkgs-review`, open the PR
     (`yb: A.B.C -> X.Y.Z`).
5. Copy the updated `package.nix` back here (with its new `hash` and
   `cargoHash`), and commit.

## One-time setup for publishing

- GitHub, repository settings: an environment `crates-io` with a
  required reviewer (the maintainer) and a deployment rule limited to
  tags `v*`.
- crates.io, for each of `yb` and `yb-core`: a trusted publisher with
  repository `douzebis/yb`, workflow `publish.yaml`, environment
  `crates-io`.
