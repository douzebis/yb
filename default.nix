# SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

{ pkgs ? import (fetchTarball {
    url    = "https://channels.nixos.org/nixos-25.11/nixexprs.tar.xz";
    sha256 = "1849z3492d6wi1y67hnh1b88abvi092clnv9awbfj4rilh70hc62";
  }) {}
}:

let
  # ---------------------------------------------------------------------------
  # CRANE (Rust build framework)
  # ---------------------------------------------------------------------------
  crane = pkgs.callPackage (pkgs.fetchgit {
    url    = "https://github.com/ipetkov/crane.git";
    rev    = "80ceeec0dc94ef967c371dcdc56adb280328f591";
    sha256 = "sha256-e1idZdpnnHWuosI3KsBgAgrhMR05T2oqskXCmNzGPq0=";
  }) { inherit pkgs; };

  # Source filtered to only what Cargo needs (scoped to rust/ so other
  # top-level files do not affect the hash).
  rustSrc = pkgs.lib.cleanSourceWith {
    src    = pkgs.lib.cleanSource ./rust;
    # Include Cargo sources plus YAML fixtures used by tests.
    filter = path: type:
      crane.filterCargoSources path type
      || pkgs.lib.hasSuffix ".yaml" path;
  };

  rustCommon = {
    src        = rustSrc;
    pname      = "yb";
    version    = "0.1.0";
    strictDeps = true;
    nativeBuildInputs = [ pkgs.cargo pkgs.rustc pkgs.pkg-config ];
    buildInputs = [ pkgs.pcsclite ];
  };

  # Shared dependency cache — rebuilt only when Cargo.lock or dep sources change.
  rustDeps = crane.buildDepsOnly (rustCommon // {
    pname = "yb-deps";
  });

  # ---------------------------------------------------------------------------
  # RUST LINT / TEST DERIVATIONS
  # ---------------------------------------------------------------------------
  rustFmt = crane.cargoFmt (rustCommon // {
    pname = "yb-fmt";
  });

  rustClippy = crane.cargoClippy (rustCommon // {
    pname              = "yb-clippy";
    cargoArtifacts     = rustDeps;
    cargoClippyExtraArgs = "-- --deny warnings";
  });

  rustTests = crane.cargoTest (rustCommon // {
    pname          = "yb-tests";
    cargoArtifacts = rustDeps;
  });

  # ---------------------------------------------------------------------------
  # TIER-2 HARNESS TESTS (compiled, not run — executed inside the NixOS VM)
  # ---------------------------------------------------------------------------
  harnessCommon = rustCommon // {
    nativeBuildInputs = rustCommon.nativeBuildInputs ++ [
      pkgs.llvmPackages.libclang
    ];
    LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
    # bindgen (used by littlefs2-sys) needs clang built-in headers.
    BINDGEN_EXTRA_CLANG_ARGS =
      let clangInclude = "${pkgs.llvmPackages.libclang.lib}/lib/clang";
          version      = pkgs.lib.versions.major pkgs.llvmPackages.release_version;
      in "-I${clangInclude}/${version}/include";
  };

  harnessDeps = crane.buildDepsOnly (harnessCommon // {
    pname          = "yb-harness-deps";
    cargoArtifacts = rustDeps;
    cargoExtraArgs = "-p yb-piv-harness --features integration-tests";
  });

  # Build the tier-2 test binary using crane's cargoTest with --no-run, then
  # extract the compiled binary from the cargo artifact output.
  harnessTestBin = crane.cargoTest (harnessCommon // {
    pname              = "yb-harness-test-bin";
    cargoArtifacts     = harnessDeps;
    cargoExtraArgs     = "-p yb-piv-harness --features integration-tests";
    cargoTestExtraArgs = "--no-run";
    # Instead of running tests, install the compiled binary.
    installPhase = ''
      mkdir -p $out/bin
      for name in hardware_piv_tests yb_cli_tests; do
        bin=$(find target -name "$name-*" -executable -type f \
                ! -name '*.d' ! -name '*.rmeta' \
                -printf '%T@ %p\n' | sort -rn | head -1 | cut -d' ' -f2-)
        if [ -z "$bin" ]; then
          echo "ERROR: $name binary not found under target/" >&2
          exit 1
        fi
        echo "Installing $bin -> $out/bin/$name"
        cp "$bin" $out/bin/$name
      done
    '';
  });

  # ---------------------------------------------------------------------------
  # RUST PACKAGE
  # ---------------------------------------------------------------------------
  ybRust = crane.buildPackage (rustCommon // {
    pname          = "yb-rust";
    cargoArtifacts = rustDeps;
    cargoExtraArgs = "-p yb --features self-test";

    nativeBuildInputs = rustCommon.nativeBuildInputs ++ [ pkgs.installShellFiles ];

    postInstall = ''
      installShellCompletion --cmd yb \
        --bash <(YB_COMPLETE=bash $out/bin/yb | sed \
          -e '/^\s*) )$/a\    compopt -o filenames 2>/dev/null' \
          -e 's|words\[COMP_CWORD\]="$2"|local _cur="''${COMP_LINE:0:''${COMP_POINT}}"; _cur="''${_cur##* }"; words[COMP_CWORD]="''${_cur}"|') \
        --zsh  <(YB_COMPLETE=zsh  $out/bin/yb) \
        --fish <(YB_COMPLETE=fish $out/bin/yb)

      # Generate and install man pages.
      $out/bin/yb-gen-man $out/share/man/man1
    '';

    meta = with pkgs.lib; {
      description  = "Secure blob storage on a YubiKey (Rust port)";
      homepage     = "https://github.com/douzebis/yb";
      license      = licenses.mit;
      maintainers  = with maintainers; [ ];
      mainProgram  = "yb";
      platforms    = platforms.unix;
    };
  });

  # ---------------------------------------------------------------------------
  # DEVELOPMENT SHELL
  # ---------------------------------------------------------------------------
  dev-shell = pkgs.mkShell {
    name = "yb-dev";

    # Allow cargo to write build artifacts to rust/target/ outside /nix/store.
    NIX_ENFORCE_PURITY = 0;

    nativeBuildInputs = with pkgs; [
      # Rust toolchain
      cargo
      rustc
      rustfmt
      clippy
      pkg-config
      pcsclite
      ccid
      # Tier-2 test harness (vsmartcard + piv-authenticator)
      vsmartcard-vpcd
      llvmPackages.libclang
      # Project tooling
      reuse
      ruff
      gh
      usbutils
      mandoc
      poppler-utils
    ];

    shellHook = ''
      old_opts=$(set +o)
      set -euo pipefail

      # Detected by ~/.claude/hooks/claude-hook-post-edit-lint to confirm
      # that the active nix-shell belongs to this repo.
      export NIXSHELL_REPO="${toString ./.}"

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
        source <(YB_COMPLETE=bash yb | sed \
          -e '/^\s*) )$/a\    compopt -o filenames 2>/dev/null' \
          -e 's|words\[COMP_CWORD\]="$2"|local _cur="''${COMP_LINE:0:''${COMP_POINT}}"; _cur="''${_cur##* }"; words[COMP_CWORD]="''${_cur}"|')
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

  # Fixture files needed by yb_cli_tests at runtime in the NixOS VM.
  # crane.filterCargoSources strips .yaml from the build sandbox, so the
  # compile-time CARGO_MANIFEST_DIR path is gone by VM time; we ship the
  # fixtures as a separate store path and inject YB_FIXTURE_DIR instead.
  testFixtures = pkgs.runCommand "yb-test-fixtures" {} ''
    mkdir -p $out
    cp ${./rust/yb-core/tests/fixtures/with_key.yaml} $out/with_key.yaml
    cp ${./rust/yb-core/tests/fixtures/default.yaml}  $out/default.yaml
  '';

  # ---------------------------------------------------------------------------
  # NIXOS VM INTEGRATION TEST (tier-1 + tier-2)
  # ---------------------------------------------------------------------------
  integrationTests = pkgs.testers.nixosTest {
    name = "yb-integration-tests";

    nodes.machine = { config, pkgs, ... }: {
      services.pcscd = {
        enable  = true;
        plugins = [ pkgs.ccid pkgs.vsmartcard-vpcd ];
      };
      environment.systemPackages = [ harnessTestBin ybRust ];
    };

    testScript = ''
      machine.start()
      machine.wait_for_unit("pcscd.socket")

      # Tier-2: hardware PIV tests. with_vsc connects to vpcd in-process (each
      # test gets a fresh RAM-backed virtual card). RUST_TEST_THREADS=1
      # serialises tests to avoid concurrent vpcd connections.
      out = machine.succeed("RUST_TEST_THREADS=1 hardware_piv_tests 2>&1")
      print(out)
      if "test result: ok" not in out:
        raise Exception("Tier-2 hardware_piv_tests failed:\n" + out)

      # Tier-2: CLI subprocess tests. YB_BIN points to the Nix-built binary so
      # the pre-built yb_cli_tests binary can find it (CARGO_BIN_EXE_yb is
      # baked at compile time and would point to the wrong store path).
      # YB_FIXTURE_DIR points to fixtures in the nix store (the build-sandbox
      # path baked into CARGO_MANIFEST_DIR is gone at VM runtime).
      out = machine.succeed(
        "RUST_TEST_THREADS=1 YB_BIN=${ybRust}/bin/yb"
        + " YB_FIXTURE_DIR=${testFixtures}"
        + " yb_cli_tests 2>&1"
      )
      print(out)
      if "test result: ok" not in out:
        raise Exception("Tier-2 yb_cli_tests failed:\n" + out)
    '';
  };

in
{
  default           = ybRust;
  yb-rust           = ybRust;
  devShell          = dev-shell;        # legacy alias
  dev-shell         = dev-shell;
  rust-fmt          = rustFmt;
  rust-clippy       = rustClippy;
  rust-tests        = rustTests;        # tier-1 only (fast)
  integration-tests = integrationTests; # tier-1 + tier-2 via NixOS VM
}
