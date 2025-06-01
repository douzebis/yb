# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

{ pkgs ? import <nixpkgs> {} }:

let
  yb = import ./default.nix { inherit pkgs; };
in

pkgs.mkShell {
  buildInputs = [ yb ];
}
