# SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

# Build environment for KeePassYB, a KeePassXC with databases stored on a
# YubiKey (https://github.com/douzebis/keepassyb, branch keepassyb), with
# libyubiblob and the yb command from yb's v0.7.0 release.
#
# Everything comes from the nixpkgs that yb pins, so it works whatever the
# host's channel, and libyubiblob and KeePassXC share their libraries.
# To build against a local yb checkout instead: nix-shell --arg yb ../yb
{
  yb ? builtins.fetchTarball {
    url = "https://github.com/douzebis/yb/archive/refs/tags/v0.7.0.tar.gz";
    sha256 = "0xpxnk9n6wzjh2ia4y3ca94a7zmp8rds08q2s2h92dgl4zlrhp9k";
  },
  pkgs ? (import yb { }).nixpkgs,
}:
let
  ybPackages = import yb { inherit pkgs; };
  inherit (ybPackages) libyubiblob;
  qt = pkgs.qt6;
in
pkgs.mkShell {
  nativeBuildInputs = with pkgs; [
    cmake
    ninja
    pkg-config
    asciidoctor
    qt.wrapQtAppsHook
    # The yb command, to set up the YubiKey and manage its store.
    ybPackages.yb
    # clang-format and git-clang-format, to format changed lines only
    # (KeePassXC's .clang-format).
    clang-tools
    # Backtraces of crashes.
    gdb
    # The tests on a headless machine (CI, a VM): a virtual X server, and a
    # clipboard tool for the CLI's clip test.
    xvfb-run
    xclip
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
