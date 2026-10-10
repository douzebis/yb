yb: 0.4.2 -> 0.5.2

Update `yb` (secure blob storage on a YubiKey) to 0.5.2.
Changelog: https://github.com/douzebis/yb/blob/v0.5.2/CHANGELOG.md

Highlights of 0.5.x: a guided `yb format` (asks before writing anything), a
YubiKey health report in `yb fsck`, `yb rotate-management-key`, support for
YubiKey firmware 5.7+ (AES-192 management key; 0.4.2 failed on those keys),
and interruption-safe management key changes.  One behavior change: bare
`yb format` run from a terminal is now interactive; scripts should use
`yb format --yes` (unchanged without a terminal).  See the changelog's
upgrade notes.

Packaging changes:

- `nixosTests.yb` now really exercises the PC/SC path.  Until now, its
  `hardware_piv_tests` skipped silently and were reported as passing: the
  VM listed `vsmartcard-vpcd` in `services.pcscd.plugins`, which does not
  load it (it is a serial-style driver, configured through `reader.conf`),
  and the upstream harness could not start its emulated card.  The VM now
  uses `services.vsmartcard-vpcd.enable`, upstream fixed the harness, and
  `YB_REQUIRE_VSC=1` makes a missing vpcd a failure instead of a skip.
- `ybPivHarnessTests`: the tier-2 tests are now binaries of the
  `yb-piv-harness` crate, so the derivation uses the default build and
  install phases: no custom `buildPhase`/`installPhase`, no `find`, as
  suggested in the review of the previous update (#514826).  It reuses the
  package's `cargoDeps` instead of fetching the dependencies again.
- `rustPlatform.bindgenHook` replaces the hand-set `LIBCLANG_PATH` and
  `BINDGEN_EXTRA_CLANG_ARGS`.
- The test fixtures are embedded at compile time (`include_str!` in
  `yb-core`) instead of read from the source tree at run time:
  `testFixtures` and `YB_FIXTURE_DIR` are gone (in `package.nix`,
  `nixos/tests/yb.nix` and `nixos/tests/all-tests.nix`).
- `nixosTests.yb` passes `--test-threads=1`: the test binaries use
  `libtest-mimic`, which does not read `RUST_TEST_THREADS`.
- `meta.changelog` points to `CHANGELOG.md`; `longDescription` updated.

Upstream builds and tests this exact recipe (staged in the repository's
`nixpkgs/` directory) in its CI, including the NixOS VM test.

## Things done

- Built on platform:
  - [x] x86_64-linux
  - [ ] aarch64-linux
  - [ ] aarch64-darwin
  - (aarch64-linux and aarch64-darwin: built and tested by upstream CI with
    this recipe, against nixos-unstable rather than master.)
- Tested, as applicable:
  - [x] [NixOS tests] in [nixos/tests].
  - [x] [Package tests] at `passthru.tests`.
  - [ ] Tests in [lib/tests] or [pkgs/test] for functions and "core" functionality.
- [ ] Ran `nixpkgs-review` on this PR. See [nixpkgs-review usage].
- [x] Tested basic functionality of all binary files, usually in `./result/bin/`.
- Nixpkgs Release Notes
  - [ ] Package update: when the change is major or breaking.
- NixOS Release Notes
  - [ ] Module addition: when adding a new NixOS module.
  - [ ] Module update: when the change is significant.
- [x] Fits [CONTRIBUTING.md], [pkgs/README.md], [maintainers/README.md] and other READMEs.
- [x] Follows the [automation/AI policy].

## AI disclosure

This update was prepared with Claude Code (Claude Opus 5.5): the packaging
changes, the commit message and this description were drafted with it and
reviewed by me, the maintainer, who is responsible for them.  The commit
carries an `Assisted-by:` trailer.

[NixOS tests]: https://nixos.org/manual/nixos/unstable/index.html#sec-nixos-tests
[Package tests]: https://github.com/NixOS/nixpkgs/blob/master/pkgs/README.md#package-tests
[nixpkgs-review usage]: https://github.com/Mic92/nixpkgs-review#usage

[CONTRIBUTING.md]: https://github.com/NixOS/nixpkgs/blob/master/CONTRIBUTING.md
[automation/AI policy]: https://github.com/NixOS/nixpkgs/blob/master/CONTRIBUTING.md#automationai-policy
[lib/tests]: https://github.com/NixOS/nixpkgs/blob/master/lib/tests
[maintainers/README.md]: https://github.com/NixOS/nixpkgs/blob/master/maintainers/README.md
[nixos/tests]: https://github.com/NixOS/nixpkgs/blob/master/nixos/tests
[pkgs/README.md]: https://github.com/NixOS/nixpkgs/blob/master/pkgs/README.md
[pkgs/test]: https://github.com/NixOS/nixpkgs/blob/master/pkgs/test

🤖 Generated with [Claude Code](https://claude.com/claude-code)
