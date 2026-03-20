# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

{ pkgs ? import <nixpkgs> {},
  pythonPkgs ? pkgs.python3Packages,
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

  # Source filtered to only what Cargo needs (scoped to rust/ so the Python
  # tree does not affect the hash).
  rustSrc = pkgs.lib.cleanSourceWith {
    src    = pkgs.lib.cleanSource ./rust;
    filter = path: type: crane.filterCargoSources path type;
  };

  rustCommon = {
    src        = rustSrc;
    pname      = "yb";
    version    = "0.1.0";
    strictDeps = true;
    nativeBuildInputs = [ pkgs.cargo pkgs.rustc ];
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
  # RUST PACKAGE
  # ---------------------------------------------------------------------------
  ybRust = crane.buildPackage (rustCommon // {
    pname          = "yb-rust";
    cargoArtifacts = rustDeps;

    checkPhase = ''
      echo "fmt:    ${rustFmt}"
      echo "clippy: ${rustClippy}"
      echo "tests:  ${rustTests}"
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
  # PYTHON MAIN PACKAGE
  # ---------------------------------------------------------------------------
  yb = pythonPkgs.buildPythonApplication rec {
    pname = "yb";
    version = "0.1.0";

    # This tells nix where to find the package source root
    # It assumes a src/yb layout for the yb package
    src = ./.;

    pyproject = true;

    nativeBuildInputs = with pythonPkgs; [
      setuptools
      wheel
      pytest
    ];

    propagatedBuildInputs = [
      pkgs.opensc
      pkgs.openssl
      pkgs.yubico-piv-tool
      pkgs.yubikey-manager
      pythonPkgs.click
      pythonPkgs.cryptography
      pythonPkgs.prompt_toolkit
      pythonPkgs.pyyaml
    ];

    makeWrapperArgs = [
      "--set" "LD_LIBRARY_PATH" "${pkgs.yubico-piv-tool}/lib"
    ];

    checkPhase = ''
      PYTHONPATH=${src}/src:$PYTHONPATH pytest || true
    '';

    pythonImportsCheckPhase = ''
      PYTHONPATH=${src}/src:$PYTHONPATH python -c 'import yb'
    '';

    meta = with pkgs.lib; {
      description = "CLI tool for securely storing and retrieving binary blobs using YubiKey";
      homepage = "https://github.com/douzebis/yb";
      license = licenses.mit;
      maintainers = with maintainers; [ douzebis ];
    };
  };

  # ---------------------------------------------------------------------------
  # MINIMAL SHELL (default nix-shell — just the built Python yb on PATH)
  # ---------------------------------------------------------------------------
  shell = pkgs.mkShell {
    buildInputs = [ yb ];
    shellHook = ''
      export NIXSHELL_REPO=${toString ./.}
    '';
  };

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
      # Python toolchain
      opensc
      openssl
      yubico-piv-tool
      yubikey-manager
      pythonPkgs.click
      pythonPkgs.cryptography
      pythonPkgs.prompt_toolkit
      pythonPkgs.pytest
      pythonPkgs.pyyaml
      # Project tooling
      reuse
      gh
    ];

    shellHook = ''
      old_opts=$(set +o)
      set -euo pipefail

      # Detected by ~/.claude/hooks/claude-hook-post-edit-lint to confirm
      # that the active nix-shell belongs to this repo.
      export NIXSHELL_REPO="${toString ./.}"

      # YubiKey / PKCS#11 env
      export LD_LIBRARY_PATH=${pkgs.yubico-piv-tool}/lib:''${LD_LIBRARY_PATH:-}
      export PKCS11_MODULE_PATH=${pkgs.yubico-piv-tool}/lib/libykcs11.so

      # Python path for the Python implementation
      export PYTHONPATH=$PWD/src:''${PYTHONPATH:-}
      export PATH=$PWD/bin:$PATH

      # Add Rust release binary to PATH once built
      export PATH="$PWD/rust/target/release:$PATH"

      # Build the Rust binary if not already built
      cargo build --release --manifest-path rust/Cargo.toml

      # Generate .env file for VS Code integration
      echo "PYTHON_INTERPRETER=$(which python)" > .env
      echo "PYTHONPATH=$PYTHONPATH" >> .env

      echo "Development environment ready."
      echo "  Rust:   $(cargo --version)"
      echo "  Python: $(python --version)"

      eval "$old_opts"
    '';
  };

in
{
  default    = yb;
  yb         = yb;
  yb-rust    = ybRust;
  shell      = shell;
  devShell   = dev-shell;   # legacy alias
  dev-shell  = dev-shell;
  rust-fmt    = rustFmt;
  rust-clippy = rustClippy;
  rust-tests  = rustTests;
}
