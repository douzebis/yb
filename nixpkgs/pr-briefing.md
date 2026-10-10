# Briefing: nixpkgs PR `yb: 0.4.2 -> 0.5.2`

Preparation notes for the maintainer before marking the PR ready, so that
reviewer questions can be answered first-hand (nixpkgs automation/AI policy:
the contributor must understand the change and answer without relaying to
an AI tool).

## What the two test binaries test

The VM test runs two programs, and they test different things:

- **`hardware_piv_tests`** (10 tests): yb's PC/SC path, end to end.  For
  each test, the program runs `piv-authenticator` (a software PIV card, from
  Nitrokey's trussed ecosystem) in a thread, plugs it into the VM's `pcscd`
  through the `vsmartcard-vpcd` virtual reader driver (TCP port 35963), and
  drives it with yb's real PC/SC code: key generation, ECDH, signing a
  certificate, PIN checks, object reads and writes.
- **`yb_cli_tests`** (36 tests): yb's command line.  It runs the packaged
  `yb` binary (`YB_BIN`) as a subprocess with `YB_FIXTURE=<file>`, so yb uses
  its in-memory simulated card instead of PC/SC, and checks arguments,
  prompts, exit codes and messages.  It needs the VM only because it runs
  the packaged binary.

## What the PR changes (3 files)

### `pkgs/by-name/yb/yb/package.nix`

1. **Version, `hash`, `cargoHash`**: set by `nix-update yb --version=skip`
   for the `v0.5.2` tag.
2. **`ybPivHarnessTests` rewritten** (the core of the PR).
   - *Before:* a custom `buildPhase` ran `cargo test --no-run`, and an
     `installPhase` located the test executables with `find` (cargo names
     them `<name>-<hash>`), then copied them to `$out/bin`.
   - *Now:* upstream turned the two test suites into ordinary binaries
     (`[[bin]]` targets of the `yb-piv-harness` crate, behind the
     `integration-tests` feature).  A plain `cargo build` produces them
     under their own names, so `buildRustPackage`'s default phases build
     and install them.  The derivation only says which crate
     (`buildAndTestSubdir = "rust/yb-piv-harness"`) and which feature
     (`cargoBuildFlags`; without it, cargo skips both binaries, which
     declare `required-features`).
   - `doCheck = false`: the harness has no tests to run at build time; the
     binaries *are* the tests, run in the VM.
   - It inherits `cargoDeps` (the main package's vendored dependencies)
     instead of `cargoHash`: one fixed-output derivation instead of two
     identical ones, and one hash for `nix-update` to maintain.
   - This answers points 7 and 8 of the 0.4.2 review (default
     `buildPhase`; simplify the binary lookup).  Back then the custom
     phases were kept because test executables have hashed names; making
     them binaries removed the reason.
3. **`rustPlatform.bindgenHook`** instead of `llvmPackages.libclang` plus
   hand-set `LIBCLANG_PATH` and `BINDGEN_EXTRA_CLANG_ARGS`.  Needed because
   `littlefs2-sys` (a C filesystem used by the emulated card's storage, under
   `piv-authenticator`) generates bindings with bindgen.  The hook is
   nixpkgs' standard way to set up bindgen.
4. **`testFixtures` removed.**  The fixtures (YAML descriptions of a
   simulated YubiKey, used by `yb_cli_tests`) are compiled into `yb-core`
   (`include_str!`), so no files need to be shipped into the VM.
5. **`meta`**: `changelog` points to `CHANGELOG.md` at the tag (GitHub
   releases have no notes); `longDescription` describes 0.5.

### `nixos/tests/yb.nix`

- **`services.vsmartcard-vpcd.enable = true;`** instead of listing
  `vsmartcard-vpcd` in `services.pcscd.plugins`.  The plugins option only
  picks up USB hot-plug drivers (from a package's `pcsc/drivers`); vpcd is a
  serial-style driver that `pcscd` loads from `reader.conf`, which the
  `services.vsmartcard-vpcd` module (in nixpkgs since 25.05) writes.  With
  the old setting, `pcscd` never had the virtual reader.
- **`YB_REQUIRE_VSC=1`** for `hardware_piv_tests`: a missing vpcd fails the
  tests instead of skipping them.
- No more `testFixtures` argument or `YB_FIXTURE_DIR` variable (see 4).
- `RUST_TEST_THREADS=1 <binary>` becomes `<binary> --test-threads=1`.  The
  PIV tests share one virtual reader, so they must run one at a time.  The
  binaries now use `libtest-mimic` (it gives a test binary libtest's output
  and flags), which honors `--test-threads` but not the environment
  variable.

### `nixos/tests/all-tests.nix`

- The `yb` entry no longer passes `testFixtures`.  This is why the PR is not
  limited to `pkgs/by-name/`: the merge bot cannot merge it, a committer
  must.  Future updates should touch `pkgs/by-name/yb/` only, so the
  r-ryantm bot can open them and you can merge them with the merge bot.

## The VM test fix: what happened (be ready to explain it)

While preparing this PR, the VM log showed every `hardware_piv_tests` test
printing "vpcd not available … skipping", then `ok`: a skip returned early
and counted as a pass.  With the old test runner (plain `cargo test`), the
output of passing tests was hidden, so the skips were invisible; the switch
to `libtest-mimic`, which shows it, revealed them.  The run times match (0.2
s for ten "tests" before and after), so the PIV tests most likely never ran
in the VM, including in the 0.4.2 package.  Causes, all fixed:

1. the VM did not load vpcd (the `plugins` setting above);
2. `piv-authenticator` is built against `trussed` without any `clients-N`
   feature, which leaves room for zero clients: the emulated card panicked
   on start-up.  The harness now enables `trussed/clients-1`;
3. the harness took an empty vpcd reader for a card, and a failing test left
   its card running, so failures cascaded.  It now waits for its card,
   removes it after each test (even a failing one) and waits for the reader
   to be empty;
4. two places where the emulator differs from a YubiKey: it rejects the PIV
   SELECT by 5-byte RID that yb, `ykman` and `yubico-piv-tool` send, and
   answers GET METADATA with an empty success (a stub).  A small adapter in
   the harness rewrites the SELECT and answers GET METADATA "not supported",
   as firmware < 5.3 does (yb then assumes a 3DES management key, the
   emulator's actual key);
5. one test signed a certificate without the PIN, which a real YubiKey also
   refuses; it now passes the PIN, as `yb format` does.

None of these were bugs in yb itself: on real YubiKeys, these code paths
were validated by hand.  Now the 10 tests run (about 12 s of real key
generation, ECDH and signing), and cannot pass silently again.

## Likely reviewer questions

**"Why do the PIV tests run in a VM instead of the check phase?"**
`hardware_piv_tests` talk to a smart card through pcscd.  pcscd's socket path
is fixed at build time (`/run/pcscd`), which the build sandbox cannot
provide.  The VM runs pcscd with the vpcd driver, and the test program plugs
an emulated card into it, so the full PC/SC stack is exercised without
hardware.  The check phase still runs the 94 tests of the `yb` crate against
the in-memory simulated card.

**"The old test passed; why change it?"**  It passed without testing
anything (see "The VM test fix" above).  Say so plainly: found while
preparing this update, fixed upstream in 0.5.2, and now guarded by
`YB_REQUIRE_VSC`.

**"You said you'd fix the bash completion quirks upstream."** (0.4.2 review,
point 3)  Not done yet: `postInstall` still patches the `clap_complete`
output (`compopt -o filenames`, and the cursor word for arguments with
spaces).  Be upfront: still planned, separate from this update.  Better: open
an issue (in yb, or in clap's repository for `clap_complete`) before
submitting, and link it.

**"`--features self-test` ships a destructive command?"**  `yb self-test`
writes to a real YubiKey, after asking you to type `yes` (the YubiKey's LED
flashes meanwhile); it is a deliberate end-user feature for checking a key,
unchanged since 0.4.2.

**"The binary honors `YB_FIXTURE`?"**  Yes: it is what `yb_cli_tests` relies
on to test the packaged binary without a card.  With `YB_FIXTURE=<file>`, yb
uses a simulated YubiKey described in that file instead of a real one.  It
needs control over yb's environment, i.e. the user's own session, which
already allows running anything as that user: no new attack surface.
Unchanged since 0.4.2.

**"Why is `yb-gen-man` installed in `bin/`?"**  It generates the man pages
in `postInstall`.  If asked, it can be removed after use
(`rm $out/bin/yb-gen-man`); harmless either way.

**"`buildAndTestSubdir = "rust/yb"` and `-p yb` are redundant."**  True,
either suffices; harmless.  Accept the suggestion if made.

**"x86_64-darwin?"**  nixpkgs dropped it in 26.11; nothing to do.  Intel Mac
users can still `cargo install yb` (upstream CI tests that separately).

**"Release notes?"**  The behavior change (bare `yb format` from a terminal
becomes interactive) is documented in the changelog's upgrade notes.  yb is
a niche tool; ask the reviewer whether a release-notes entry is wanted rather
than adding one unasked.

**"Which platforms did you build on?"**  x86_64-linux against nixpkgs
master, locally.  Upstream CI builds the same recipe on aarch64-linux and
aarch64-darwin, against nixos-unstable.  If you have an aarch64-darwin
machine, building `yb` there on the PR branch lets you tick that box too.

## Checks (x86_64-linux, nixpkgs master) — to redo at 0.5.2

- `nix-build ci -A fmt.check`, `nix-build ci -A parse`,
  `ci/nixpkgs-vet.sh master`.
- `nix-build -A yb`: 94 tests, `versionCheckHook`; binaries, completions
  (bash, zsh, fish) and 11 man pages present.
- `nix-build -A nixosTests.yb`: 10/10 `hardware_piv_tests` with no skip
  message in the log, 36/36 `yb_cli_tests`.
- No other package in nixpkgs depends on `yb` (checked at 0.5.1).
- Commit message format (`yb: 0.4.2 -> 0.5.2`, changelog link,
  `Assisted-by:` trailer).

## Still to do

- Run the binaries yourself before ticking "tested basic functionality":
  `./result/bin/yb --version`, `yb --help`, `yb fsck` with a YubiKey.
- After opening the draft PR: `nixpkgs-review pr <number> --eval github`
  (uses CI's evaluation; a local `nixpkgs-review rev` evaluates all of
  nixpkgs twice and needs more than 15 GB of RAM), then post its report and
  tick the box.
- Read the diff and this briefing once more; mark the PR ready.
