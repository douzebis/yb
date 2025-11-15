# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

{ pkgs ? import <nixpkgs> {},
  pythonPkgs ? pkgs.python3Packages,
}:

let
  # ---------------------------------------------------------------------------
  # MAIN PACKAGE
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
  # MINIMAL SHELL (default nix-shell)
  # ---------------------------------------------------------------------------
  shell = pkgs.mkShell {
    buildInputs = [ yb ];
  };

  # ---------------------------------------------------------------------------
  # DEVELOPMENT SHELL (nix-shell -A devShell)
  # ---------------------------------------------------------------------------
  devShell = pkgs.mkShell {
    buildInputs = [

      pkgs.opensc
      pkgs.reuse
      pkgs.yubico-piv-tool
      pkgs.yubikey-manager
      pythonPkgs.click
      pythonPkgs.cryptography
      pythonPkgs.prompt_toolkit
      pythonPkgs.pytest
      pythonPkgs.pyyaml
    ];

    shellHook = ''
      old_opts=$(set +o)
      set -euo pipefail

      # Set up environment variables
      export LD_LIBRARY_PATH=${pkgs.yubico-piv-tool}/lib:''${LD_LIBRARY_PATH:-}
      export PKCS11_MODULE_PATH=${pkgs.yubico-piv-tool}/lib/libykcs11.so
      export PYTHONPATH=$PWD/src:''${PYTHONPATH:-}

      # Generate .env file for VS Code integration
      echo "PYTHON_INTERPRETER=$(which python)" > .env
      echo "PYTHONPATH=$PYTHONPATH" >> .env

      # Add CLI to PATH and enable auto-completion
      export PATH=$PWD/bin:$PATH
      eval "$(_YB_COMPLETE=bash_source  yb)"

      # Display environment info
      echo "Development environment ready."
      echo "  PYTHONPATH: $PYTHONPATH"
      echo "  LD_LIBRARY_PATH: ${pkgs.yubico-piv-tool}/lib"
      echo "  PKCS11_MODULE_PATH: $PKCS11_MODULE_PATH"

      eval "$old_opts"
    '';
  };

in
{
  default = yb;
  yb = yb;
  shell = shell;
  devShell = devShell;
  dev-shell = devShell;  # alias for compatibility
}
