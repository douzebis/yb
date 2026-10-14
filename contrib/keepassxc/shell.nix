# SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

# Build environment for KeePassXC with databases stored on a YubiKey
# (branch feature/yubikey-storage of https://github.com/douzebis/keepassxc),
# with libyubiblob from yb's v0.6.0 release.
#
# Everything comes from the nixpkgs that yb pins, so it works whatever the
# host's channel, and libyubiblob and KeePassXC share their libraries.
# To build against a local yb checkout instead: nix-shell --arg yb ../yb
{
  yb ? builtins.fetchTarball {
    url = "https://github.com/douzebis/yb/archive/refs/tags/v0.6.0.tar.gz";
    sha256 = "1maaibmgi35iizmv8gmp5qjps6hg98m747fds73fwzma05h9qnwi";
  },
  pkgs ? (import yb { }).nixpkgs,
}:
let
  libyubiblob = (import yb { inherit pkgs; }).libyubiblob;
  qt = pkgs.qt6;
in
pkgs.mkShell {
  nativeBuildInputs = with pkgs; [
    cmake
    ninja
    pkg-config
    asciidoctor
    qt.wrapQtAppsHook
  ];
  buildInputs = with pkgs; [
    qt.qtbase
    qt.qttools
    qt.qtsvg
    qt.qtwayland
    botan3
    zlib
    minizip
    pcsclite
    qrencode
    keyutils
    readline
    libusb1
    libyubiblob
    libx11
    libxi
    libxtst
    libxkbcommon
  ];

  # Let the unwrapped binary in build/ find Qt's platform plugins.
  shellHook = ''
    export QT_PLUGIN_PATH=${qt.qtbase}/${qt.qtbase.qtPluginPrefix}:${qt.qtwayland}/${qt.qtbase.qtPluginPrefix}:${qt.qtsvg}/${qt.qtbase.qtPluginPrefix}
  '';
}
