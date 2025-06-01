{ pkgs ? import <nixpkgs> {} }:

let
  yb = import ./default.nix { inherit pkgs; };
in

pkgs.mkShell {
  buildInputs = [ yb ];
}
