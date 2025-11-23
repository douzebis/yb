# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT
#
# This is the nixpkgs-compatible package definition for yb.
# It should be placed at: pkgs/by-name/yb/yb/package.nix in nixpkgs

{
  lib,
  python3Packages,
  fetchFromGitHub,
  opensc,
  openssl,
  yubico-piv-tool,
  yubikey-manager,
}:

python3Packages.buildPythonApplication rec {
  pname = "yb";
  version = "0.1.0";
  pyproject = true;

  src = fetchFromGitHub {
    owner = "douzebis";
    repo = "yb";
    rev = "v${version}";
    hash = "";  # To be calculated with: nix-prefetch-url --unpack https://github.com/douzebis/yb/archive/v0.1.0.tar.gz
  };

  build-system = with python3Packages; [
    setuptools
    wheel
  ];

  dependencies = with python3Packages; [
    click
    cryptography
    prompt-toolkit
    pyyaml
  ];

  buildInputs = [
    opensc
    openssl
    yubico-piv-tool
    yubikey-manager
  ];

  makeWrapperArgs = [
    "--set"
    "LD_LIBRARY_PATH"
    "${yubico-piv-tool}/lib"
  ];

  pythonImportsCheck = [
    "yb"
  ];

  # Tests require physical YubiKey hardware
  doCheck = false;

  meta = {
    description = "CLI tool for securely storing and retrieving binary blobs using YubiKey";
    longDescription = ''
      yb is a command-line tool that provides secure blob storage using a YubiKey device.
      It leverages the YubiKey's PIV (Personal Identity Verification) application to store
      encrypted or unencrypted binary data in custom PIV data objects. The tool uses hybrid
      encryption (ECDH + AES-256-CBC) to protect sensitive data with hardware-backed
      cryptographic keys.

      Features:
      - Hardware-backed encryption using YubiKey PIV
      - ~36 KB storage capacity (expandable to ~48 KB)
      - PIN-protected management key mode
      - Multi-device support with interactive selection
      - Shell auto-completion for blob names
      - Glob pattern filtering
    '';
    homepage = "https://github.com/douzebis/yb";
    changelog = "https://github.com/douzebis/yb/releases/tag/v${version}";
    license = lib.licenses.mit;
    maintainers = with lib.maintainers; [ douzebis ];
    mainProgram = "yb";
    platforms = lib.platforms.linux;  # YubiKey support is best on Linux
  };
}
