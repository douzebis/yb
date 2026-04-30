# Review Response — PR #514826

Reviewer comments from GaetanLepage and SuperSandro2000.
GaetanLepage's suggestions are already applied in the current commit.
SuperSandro2000's suggestions are addressed below.

---

## 1. `rev =` → `tag =` (line 21)

**Comment:** Use `tag = "v${finalAttrs.version}"` instead of `rev =`.

**Proposal:** Apply directly. Using `tag` is more semantic and is the preferred
nixpkgs convention when the source is fetched from a tagged release.

**`tag` vs `rev`:** Semantically identical at fetch time — both resolve to a
Git SHA. The distinction is intent: `rev` accepts any ref (branch, tag, bare
SHA), while `tag` explicitly declares the ref is a tag. This makes the
derivation self-documenting and is what `nix-update-script` expects.

---

## 2. Remove `cargoHash` comment (line 27)

**Comment:** Remove the `# Single hash covering all vendored dependencies...` comment.

**Proposal:** Apply directly. The comment is redundant — `cargoHash` is self-explanatory
in the context of `rustPlatform.buildRustPackage`.

---

## 3. Fix bash completion quirks upstream (line 58)

**Comment:** "Would be cooler to fix this upstream."

**Discussion:** The two patches work around bugs in `clap_complete`:
- Missing `compopt -o filenames` for path arguments
- `$2` not reflecting the actual cursor position in `COMP_LINE`

These are known `clap_complete` issues. Fixing them upstream means either:
a) Filing issues / PRs against the `clap_complete` crate, or
b) Working around them in `yb`'s own bash completion wrapper code.

**Proposal:** Defer this to a follow-up. The patches are correct and necessary
right now. We can reply to the comment acknowledging it and noting it will be
addressed upstream in a separate PR. This is a blocker-free item.

---

## 4. Wrap `postInstall` for cross-compilation (line 53)

**Comment:** Suggested wrapping `postInstall` with:
```nix
postInstall = lib.optionalString (stdenv.buildPlatform.canExecute stdenv.hostPlatform) ''
```

**Proposal:** Apply directly. This is standard nixpkgs practice for any
`postInstall` that runs the built binary (shell completions, man pages).
Without this guard, cross-compilation builds fail because the host binary
cannot be executed on the build platform.

---

## 5. Move NixOS test to `nixos/tests/` (line 96) + keep package in `package.nix` (line 115)

**Comment (line 96):** "Those go under nixos/tests."
**Comment (line 115):** "We should keep the package in this file and not move it
to nixos/tests."

**Interpretation:** These are not contradictory. The intent is:
- Create `nixos/tests/yb.nix` containing the NixOS VM test definition.
- In `package.nix`, reference it via:
  ```nix
  passthru.tests.integration = pkgs.nixosTests.yb;
  ```
- Register the test in `nixos/tests/all-tests.nix`.

This is the standard nixpkgs pattern for packages with NixOS VM tests.

**Proposal:** Apply. This is a well-defined restructuring. The test logic moves
verbatim to `nixos/tests/yb.nix`; `package.nix` just gets a reference.

**On `default.nix` sharing the test:** No. `default.nix` builds with Crane;
`nixos/tests/yb.nix` uses `rustPlatform.buildRustPackage`. The two derivations
for the harness test binaries differ in build system, dependency wiring, and
environment variables. Sharing logic between them would require parameterizing
over two incompatible build APIs. The apparent duplication (both run the same
test binary) is unavoidable; the implementations must remain independent.

**Scope:** Requires changes to three files:
- `pkgs/by-name/yb/yb/package.nix` — replace inline test with reference
- `nixos/tests/yb.nix` — new file with the test
- `nixos/tests/all-tests.nix` — add `yb = handleTest ./yb.nix { };`

---

## 6. Remove `pkgs.` prefixes in nested derivation (line 130)

**Comment:** Strip `pkgs.` from `nativeBuildInputs` and `buildInputs` inside
the nested `yb-piv-harness-tests` derivation.

**Proposal:** Apply directly. Inside a `pkgs.rustPlatform.buildRustPackage { }`,
the `pkgs` argument is already in scope via the `{ config, pkgs, ... }` node
argument. The `pkgs.` prefix is redundant and not idiomatic.

---

## 7. Use default buildPhase (line 146)

**Comment:** "Would be cooler to use the default buildPhase."

**Discussion:** The current custom `buildPhase` does:
```bash
cd rust
cargo test --no-run -p yb-piv-harness --features integration-tests --offline --release
```

The reason for the custom phase is that we want `--no-run` (compile but don't
execute tests) and we need to scope to `-p yb-piv-harness`. The default
`buildPhase` from `rustPlatform` would run a full build of the workspace, which
is not what we want here.

However, `cargoTestFlags` + `doCheck = false` + `buildAndTestSubdir` might
achieve the same result more idiomatically. Needs investigation.

**Investigation result:** The idiomatic combination does not work here.
`rustPlatform.buildRustPackage` with `doCheck = false` still runs the default
`buildPhase`, which builds all default workspace members — not just
`yb-piv-harness`. `buildAndTestSubdir` only changes the working directory; it
does not scope the build to a single crate. `cargoTestFlags` with `--no-run`
only affects `checkPhase`, which is skipped when `doCheck = false`. There is no
standard attribute to express "run `cargo test --no-run -p <crate>`" as the
build step.

**Revised proposal:** Keep the custom `buildPhase`. Reply to the reviewer
acknowledging the suggestion, explain why the default phase cannot scope to a
single crate with `--no-run`, and note that the custom phase is the minimal
necessary deviation.

---

## 8. Simplify binary discovery with globs (line 162)

**Comment:** "This seems rather complicated. Can't we use a few globs instead?"

**Current code:**
```bash
bin=$(find target -name "$name-*" -executable -type f \
        ! -name '*.d' ! -name '*.rmeta' \
        -printf '%T@ %p\n' | sort -rn | head -1 | cut -d' ' -f2-)
```

**Discussion:** The complexity comes from the fact that Rust test binaries have
a hash suffix (e.g. `hardware_piv_tests-a3f2b1c4d5e6`). A simpler glob approach:
```bash
bin=$(echo target/release/deps/${name}-*([^.]))
```
or using `ls`:
```bash
bin=$(ls target/release/deps/${name}-* 2>/dev/null | grep -v '\.' | head -1)
```

The sort-by-mtime logic was defensive (pick the newest if multiple matches).
With `--release` and a clean build, there should only ever be one match.

**Proposal:** Simplify to a glob, drop the mtime sort. Something like:
```bash
bins=( target/release/deps/${name}-+([^.]) )
cp "${bins[0]}" $out/bin/$name
```
or even just:
```bash
cp target/release/deps/${name}-[^.]* $out/bin/$name
```
with a sanity check that exactly one file matched. Using `[^./]` (also
excluding `/`) is slightly more robust. **Apply.**

**Why `[^.]`:** Rust places several files in `target/release/deps/` that share
the same `${name}-<hash>` prefix: the test binary (no extension), a `.d`
depfile, and possibly a `.rmeta` artifact. The pattern `${name}-[^.]*` matches
only names where the character immediately after the hash contains no dot —
i.e. the extension-free binary — and excludes `hardware_piv_tests-abc123.d`
and similar. Without `[^.]`, the glob would match all three and `cp` would
fail or pick the wrong file.
