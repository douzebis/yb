Switch `yb` from the Python 0.1.0 implementation to the Rust rewrite at v0.4.2.
Homepage: https://github.com/douzebis/yb

Changes:
- Switch from `buildPythonApplication` to `rustPlatform.buildRustPackage`
- Cargo workspace lives in `rust/` subdirectory (`cargoRoot = "rust"`)
- System dependency is now `pcsclite` only (replaces opensc, openssl, yubico-piv-tool, yubikey-manager)
- Shell completions installed for bash, zsh, and fish via `installShellFiles`
- Man pages generated and installed via `yb-gen-man` helper binary
- `passthru.tests.integration`: NixOS VM test using `vsmartcard-vpcd` + `piv-authenticator`, exercising the full PIV stack without physical hardware
- `badPlatforms = lib.platforms.darwin`: package depends on `pcsclite` (Linux PC/SC stack)
- `nix-update-script` added for automated version updates

## Things done

- Built on platform:
  - [x] x86_64-linux
  - [x] aarch64-linux
  - [ ] x86_64-darwin
  - [ ] aarch64-darwin
  - Note: builds successfully on GitHub Actions `macos-15` (aarch64-darwin) and `macos-15-intel` (x86_64-darwin), but `pcsclite` is a Linux-only runtime dependency, hence `badPlatforms = lib.platforms.darwin`
- Tested, as applicable:
  - [ ] [NixOS tests] in [nixos/tests].
  - [x] [Package tests] at `passthru.tests`.
  - [ ] Tests in [lib/tests] or [pkgs/test] for functions and "core" functionality.
- [x] Ran `nixpkgs-review` on this PR.
- [x] Tested basic functionality of all binary files, usually in `./result/bin/`.
- Nixpkgs Release Notes
  - [ ] Package update: when the change is major or breaking.
- NixOS Release Notes
  - [ ] Module addition: when adding a new NixOS module.
  - [ ] Module update: when the change is significant.
- [x] Fits [CONTRIBUTING.md], [pkgs/README.md], [maintainers/README.md] and other READMEs.
