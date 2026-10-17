# SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

{
  pkgs ? import (fetchTarball {
    # Pinned to nixos-unstable @ e7439b6b14ad3cc35d05608ebca9bce01a25f5f8 (2026-10-08):
    # close to nixpkgs master, which builds the nixpkgs package (spec 0029).
    url = "https://github.com/NixOS/nixpkgs/archive/e7439b6b14ad3cc35d05608ebca9bce01a25f5f8.tar.gz";
    sha256 = "19y4py973w62z4qb7gzn0chjs67ihxy8rbjb7g71iyk8yz7z5k8z";
  }) { },
}:

let
  # ---------------------------------------------------------------------------
  # BASH 5.2.21 — pinned to match the GitHub Actions runner used by clap CI,
  # so that bash shell-integration tests behave identically locally.
  # nixpkgs @ 15ee47600479 is the last commit before the 5.2p21 -> 5.2p26 bump.
  # ---------------------------------------------------------------------------
  pkgs-bash521 = import (fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/15ee47600479b11a9674252a48c14db8fe0961be.tar.gz";
    sha256 = "0bd54880nvmhc6mc492b544kl45ganc2acqfd91dmi5yyvrkg5qb";
  }) { };
  bash521 = pkgs-bash521.bashInteractive;

  # ---------------------------------------------------------------------------
  # CRANE (Rust build framework)
  # ---------------------------------------------------------------------------
  crane = pkgs.callPackage (pkgs.fetchgit {
    url = "https://github.com/ipetkov/crane.git";
    rev = "80ceeec0dc94ef967c371dcdc56adb280328f591";
    sha256 = "sha256-e1idZdpnnHWuosI3KsBgAgrhMR05T2oqskXCmNzGPq0=";
  }) { inherit pkgs; };

  # Source filtered to only what Cargo needs (scoped to rust/ so other
  # top-level files do not affect the hash).
  rustSrc = pkgs.lib.cleanSourceWith {
    src = pkgs.lib.cleanSource ./rust;
    # Include Cargo sources plus YAML fixtures used by tests.
    filter = path: type: crane.filterCargoSources path type || pkgs.lib.hasSuffix ".yaml" path;
  };

  # The version, from the workspace manifest (spec 0029 §6).
  cargoVersion = (pkgs.lib.importTOML ./rust/Cargo.toml).workspace.package.version;

  rustCommon = {
    src = rustSrc;
    pname = "yb";
    version = cargoVersion;
    strictDeps = true;
    nativeBuildInputs = [
      pkgs.cargo
      pkgs.rustc
      pkgs.pkg-config
    ];
    # pcsclite is needed on Linux by all derivations that compile the crate.
    # On macOS, pcsc-sys links against PCSC.framework via the SDK sysroot
    # automatically — no explicit buildInputs entry required.  libfido2 on
    # every platform (spec 0028, D9).
    buildInputs = [
      pkgs.libfido2
    ]
    ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.pcsclite ];
  };

  # Shared dependency cache — rebuilt only when Cargo.lock or dep sources change.
  rustDeps = crane.buildDepsOnly (
    rustCommon
    // {
      pname = "yb-deps";
      doCheck = false;
    }
  );

  # ---------------------------------------------------------------------------
  # RUST LINT / TEST DERIVATIONS
  # ---------------------------------------------------------------------------
  rustFmt = crane.cargoFmt (
    rustCommon
    // {
      pname = "yb-fmt";
    }
  );

  rustClippy = crane.cargoClippy (
    rustCommon
    // {
      pname = "yb-clippy";
      cargoArtifacts = rustDeps;
      # With the self-test feature, so that `yb self-test` is linted too.
      cargoClippyExtraArgs = "--all-targets --features yb/self-test -- --deny warnings";
    }
  );

  rustTests = crane.cargoTest (
    rustCommon
    // {
      pname = "yb-tests";
      cargoArtifacts = rustDeps;
      # Includes the end-to-end `yb self-test` on a simulated YubiKey.
      cargoTestExtraArgs = "--features yb/self-test";
    }
  );

  # libyubiblob, the C API (spec 0039): the libraries, yubiblob.h and
  # yubiblob.pc, installed with cargo-c, for programs built against it
  # (e.g. KeePassXC, through pkg-config yubiblob).
  libyubiblob = crane.mkCargoDerivation (
    rustCommon
    // {
      pname = "libyubiblob";
      version = (pkgs.lib.importTOML ./rust/yubiblob/Cargo.toml).package.version;
      cargoArtifacts = rustDeps;
      nativeBuildInputs = rustCommon.nativeBuildInputs ++ [ pkgs.cargo-c ];
      buildPhaseCargoCommand = ''
        cargo cbuild --release --offline -p yubiblob --prefix $out --libdir $out/lib
      '';
      installPhaseCommand = ''
        cargo cinstall --release --offline -p yubiblob --prefix $out --libdir $out/lib
      '';
      doCheck = false;
      # The package is the library, not crane's build cache.
      doInstallCargoArtifacts = false;
    }
  );

  # ---------------------------------------------------------------------------
  # CRATES.IO RELEASE SHELL (spec 0029 §9)
  # ---------------------------------------------------------------------------
  # The pinned toolchain for scripts/check-crates and the crates.io upload.
  # These run cargo outside the Nix sandbox: packaging a workspace whose crates
  # depend on each other needs cargo's own temporary registry, which needs
  # the network.  mkShell's setup hooks set PKG_CONFIG_PATH, so pcsc-sys
  # finds pcsclite when the packaged crates are compiled.
  releaseShell = pkgs.mkShell {
    name = "yb-release";
    nativeBuildInputs = [
      pkgs.cargo
      pkgs.rustc
      pkgs.pkg-config
      pkgs.yq-go # scripts/check-release-workflow (invariant 0018)
    ];
    buildInputs = [
      pkgs.libfido2
    ]
    ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.pcsclite ];
  };

  # ---------------------------------------------------------------------------
  # RELEASE PACKAGE AND VM TEST — the staged nixpkgs recipe (spec 0029 §2)
  # ---------------------------------------------------------------------------
  # Same layout as the GitHub tarball that nixpkgs fetches (rust/ inside the
  # repository root), restricted to what the build reads.
  localSource = pkgs.lib.cleanSourceWith {
    src = pkgs.lib.cleanSource ./.;
    filter =
      path: type:
      let
        rel = pkgs.lib.removePrefix (toString ./. + "/") (toString path);
      in
      (rel == "rust" || pkgs.lib.hasPrefix "rust/" rel) && !(pkgs.lib.hasPrefix "rust/target" rel);
  };

  # nixpkgs with yb replaced by the staged recipe built from local source,
  # so that the VM test (which installs pkgs.yb) sees the local build.
  pkgsLocal = pkgs.extend (
    final: prev: {
      yb = (final.callPackage ./nixpkgs/pkgs/by-name/yb/yb/package.nix { }).overrideAttrs (
        finalAttrs: old: {
          version = cargoVersion;
          src = localSource;
          # From Cargo.lock: no hash to update when crates.io dependencies
          # change.  Git dependencies (under the harness's piv-authenticator,
          # and OpenSK) need one hash each; to refresh one, set it to
          # pkgs.lib.fakeHash and copy the hash the build reports.
          cargoDeps = final.rustPlatform.importCargoLock {
            lockFile = ./rust/Cargo.lock;
            outputHashes = {
              "piv-authenticator-0.5.3" = "sha256-QEQmm8ORw+o92l6qf8psUETi6zeWwyBR8dQwjPRYq5s=";
              "trussed-0.1.0" = "sha256-EML8BrRLICrh5OquItL226gk5PF9sAq6Nx+nngnHQww=";
              "trussed-auth-backend-0.1.0" = "sha256-80XwpB+zU87wMoK+wX22QOGXeO1iXFknmtyzvlOhmns=";
              "trussed-rsa-alloc-0.3.0" = "sha256-1AgAQb2Txfx+E7YI8XVBsgCmJaFZNXqGpXO/sjJB3pk=";
              "trussed-staging-0.3.2" = "sha256-kMvVJ/f7S33wl14iJHantfWmoOGTpkSgYm72FenJewY=";
              # The FIDO2 emulator of the tests (spec 0028).
              "opensk-1.0.0" = "sha256-qFDiF4IH+5FdLParw7TI854mdwZEI8Vzf2hwtUjyPps=";
            };
          };
        }
      );
    }
  );

  # The staged files must pass nixpkgs's formatter, and carry the right
  # version (spec 0029 §8).  Between releases, rust/Cargo.toml has the next
  # version with a `-dev` suffix and the staged package.nix the version
  # nixpkgs ships, which must be older; for a release, both are equal.
  stagedPackage = ./nixpkgs/pkgs/by-name/yb/yb/package.nix;
  stagedVersion = (pkgs.callPackage stagedPackage { }).version;
  nextRelease = pkgs.lib.removeSuffix "-dev" cargoVersion;
  stagedVersionOk =
    if nextRelease != cargoVersion then
      builtins.compareVersions stagedVersion nextRelease < 0
    else
      stagedVersion == cargoVersion;
  nixpkgsStagingCheck =
    pkgs.runCommand "yb-nixpkgs-staging-check"
      {
        nativeBuildInputs = [ pkgs.nixfmt ];
      }
      (
        ''
          nixfmt --check ${stagedPackage} ${./nixpkgs/nixos/tests/yb.nix}
        ''
        + pkgs.lib.optionalString (!stagedVersionOk) ''
          echo "staged package.nix has version ${stagedVersion}, which does not fit" \
            "rust/Cargo.toml's ${cargoVersion} (equal for a release, older during development)" >&2
          exit 1
        ''
        + ''
          touch $out
        ''
      );

  # Every invariant names regression tests that exist (docs/invariants/).
  invariantsCheck = pkgs.runCommand "yb-invariants-check" { } ''
    mkdir -p source/docs source/scripts
    cp -r ${rustSrc} source/rust
    cp -r ${./docs/invariants} source/docs/invariants
    cp ${./scripts/check-invariants} source/scripts/check-invariants
    chmod -R u+w source
    patchShebangs source/scripts
    source/scripts/check-invariants
    touch $out
  '';

  # Every .nix file tracked by Git is formatted with nixfmt (the nixpkgs
  # formatter, from the pinned nixpkgs), new files included.
  nixFiles = pkgs.lib.fileset.toSource {
    root = ./.;
    fileset = pkgs.lib.fileset.intersection (pkgs.lib.fileset.gitTracked ./.) (
      pkgs.lib.fileset.fileFilter (file: file.hasExt "nix") ./.
    );
  };
  nixFmt = pkgs.runCommand "yb-nix-fmt" { nativeBuildInputs = [ pkgs.nixfmt ]; } ''
    find ${nixFiles} -name '*.nix' -print0 | xargs -0 nixfmt --check
    touch $out
  '';

  # Built as nixpkgs's nixos/tests/all-tests.nix does.
  integrationTests = pkgsLocal.callPackage ./nixpkgs/nixos/tests/yb.nix {
    inherit (pkgsLocal.yb.passthru) ybPivHarnessTests;
  };

  # ---------------------------------------------------------------------------
  # DEVELOPMENT SHELL
  # ---------------------------------------------------------------------------
  dev-shell = pkgs.mkShell {
    name = "yb-dev";

    # Allow cargo to write build artifacts to rust/target/ outside /nix/store.
    NIX_ENFORCE_PURITY = 0;

    nativeBuildInputs =
      with pkgs;
      [
        # Rust toolchain
        cargo
        rustc
        rustfmt
        clippy
        pkg-config
        # libyubiblob, the C API (spec 0039): cargo cbuild / cinstall / ctest
        cargo-c
        # Project tooling
        reuse
        ruff
        gh
        mandoc
        poppler-utils
        bash-completion
        # Pinned bash to match clap CI (GitHub Actions runner = 5.2.21)
        bash521
        # FIDO2, for post-quantum stores (spec 0028)
        libfido2
      ]
      ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [
        pcsclite
        ccid
        # Tier-2 test harness (vsmartcard + piv-authenticator)
        vsmartcard-vpcd
        llvmPackages.libclang
        usbutils
      ];

    shellHook = ''
            old_opts=$(set +o)
            set -euo pipefail

            # Detected by ~/.claude/hooks/claude-hook-post-edit-lint to confirm
            # that the active nix-shell belongs to this repo.
            export NIXSHELL_REPO="${toString ./.}"

            # Ensure pinned bash 5.2.21 takes precedence over the system bash.
            export PATH="${bash521}/bin:$PATH"

            # Required by littlefs2-sys (pulled in by piv-authenticator)
            export LIBCLANG_PATH=${pkgs.llvmPackages.libclang.lib}/lib

            # Add Rust release binary to PATH once built
            export PATH="$PWD/rust/target/release:$PATH"

            # Build the Rust binary if not already built
            cargo build --release --manifest-path rust/Cargo.toml

            # Generate man pages into man/man1/ (gitignored) using the release binary.
            ./rust/target/release/yb-gen-man man/man1

            # Expose generated man pages.
            export MANPATH="$PWD/man:''${MANPATH:-}"
            makewhatis "$PWD/man" 2>/dev/null || true

            # Activate shell completions for the current session (bash only).
            # Re-runs on each nix-shell entry so completions stay in sync with
            # the freshly built binary.
            if command -v yb &>/dev/null; then
              # The script is used as printed (spec 0036: no patching).
              source <(YB_COMPLETE=bash yb)
            fi

            # Generate rust/rust-toolchain.toml so rust-analyzer uses the same
            # rustc version as the nix-shell build.  The file is gitignored and
            # regenerated on each nix-shell entry.  rustup installs the toolchain
            # on first entry; subsequent entries are instant (already installed).
            rustup toolchain install ${pkgs.rustc.unwrapped.version} \
              --component rust-src --no-self-update 2>/dev/null || true
            cat > rust/rust-toolchain.toml <<EOF
      [toolchain]
      channel = "${pkgs.rustc.unwrapped.version}"
      components = ["rust-src", "rustfmt", "clippy"]
      EOF

            # Generate pyrightconfig.json and ruff.toml so Pylance and ruff exclude
            # the attic/ directory.  Both files are gitignored — regenerated on each
            # nix-shell entry.
            cat > pyrightconfig.json <<'EOF'
      {
        "exclude": [
          "attic"
        ]
      }
      EOF
            cat > ruff.toml <<'EOF'
      exclude = ["attic/"]
      EOF

            echo "Development environment ready."
            echo "  Rust: $(cargo --version)"

            [[ "$old_opts" == *"set -o errexit"*  ]] && set -e || set +e
            [[ "$old_opts" == *"set -o nounset"*  ]] && set -u || set +u
            [[ "$old_opts" == *"set -o pipefail"* ]] && set -o pipefail || set +o pipefail
    '';
  };

in
{
  default = pkgsLocal.yb;
  yb = pkgsLocal.yb; # staged nixpkgs recipe, local source
  yb-rust = pkgsLocal.yb; # legacy alias of yb
  devShell = dev-shell; # legacy alias
  dev-shell = dev-shell;
  rust-fmt = rustFmt;
  rust-clippy = rustClippy;
  rust-tests = rustTests; # tier-1 only (fast)
  libyubiblob = libyubiblob; # the C API (spec 0039), for C/C++ builds
  nixpkgs = pkgs; # the pinned nixpkgs, for builds against libyubiblob
  nixpkgs-staging-check = nixpkgsStagingCheck; # nixfmt + version of nixpkgs/
  invariants-check = invariantsCheck; # docs/invariants/ name existing tests
  nix-fmt = nixFmt; # every tracked .nix file is nixfmt-formatted
  release-shell = releaseShell; # toolchain for scripts/check-crates
  integration-tests = integrationTests; # staged nixpkgs VM test (tier-2)
}
