# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = [
    pkgs.yubikey-manager
    pkgs.yubico-piv-tool
    (pkgs.python3.withPackages (ps: with ps; [
      asn1crypto
      click
      isort
      pip
      pycryptodome
      pykcs11
      pyopenssl
      pyscard
      pyudev
      pyusb
      pyyaml
      reuse
      setuptools
      virtualenv
      wheel
    ]))
  ];

  shellHook = ''
    export LD_LIBRARY_PATH=${pkgs.yubico-piv-tool}/lib:$LD_LIBRARY_PATH
    echo "LD_LIBRARY_PATH: ${pkgs.yubico-piv-tool}/lib"
    export PKCS11_MODULE_PATH=${pkgs.yubico-piv-tool}/lib/libykcs11.so
    echo "PKCS11_MODULE_PATH: $PKCS11_MODULE_PATH"
    export PYTHONPATH=$PWD/src:$PYTHONPATH
    echo "PYTHONPATH: $PYTHONPATH"

    # Set up the virtual env
    if [ -d .venv ]; then
      rm -rf .venv
    fi
    python -m venv .venv
    . .venv/bin/activate
    pip install reuse
    pip install --editable .
  '';
}
