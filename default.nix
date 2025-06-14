# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

{ pkgs ? import <nixpkgs> {} }:

pkgs.python3Packages.buildPythonApplication rec {
  pname = "yb";
  version = "0.1.0";

  # This tells nix where to find the package source root
  # It assumes a src/yb layout for the yb package
  src = ./.;

  pyproject = true;

  nativeBuildInputs = with pkgs.python3Packages; [
    setuptools
    wheel
    pytest
  ];

  propagatedBuildInputs = with pkgs.python3Packages; [
    pkgs.opensc
    pkgs.yubico-piv-tool
    pkgs.yubikey-manager
    pkgs.python3Packages.click
    pkgs.python3Packages.pyyaml
    pkgs.python3Packages.cryptography
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
    homepage = "https://your.project.homepage/";
    license = licenses.mit;
    maintainers = with maintainers; [ yourGitHubHandle ];
  };
}

# Note: traditional python build still available, e.g. via:
# pip install --editable .
