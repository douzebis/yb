# 0005 — Nix Build for Integration Tests (Tier-2)

**Status:** ready
**App:** yb-core
**Implemented in:** <!-- YYYY-MM-DD, fill after implementation -->

## Problem

`nix-build` currently runs only the tier-1 `VirtualPiv` tests (via
`crane.cargoTest`).  The tier-2 `yb-piv-harness` tests require a running
`pcscd` with the `vpcd` driver loaded — neither of which exists inside a
standard Nix build sandbox.  As a result, `nix-build` gives no coverage of
`HardwarePiv` and the tier-2 tests are never executed in CI.

## Goals

- `nix-build` (and the crane `rustTests` derivation) runs all tier-2 tests
  against a real `piv-authenticator` virtual card.
- No real YubiKey required.
- Works in CI without special host configuration.
- The approach is reproducible and hermetic.

## Non-goals

- Testing the Python implementation via Nix.
- Hardware-tests (real YubiKey, `hardware-tests` feature).
- NixOS module or service configuration.

## Background

### Why a plain sandbox cannot work as-is

pcscd writes its IPC socket to a compile-time path (`/run/pcscd/pcscd.comm`
in nixpkgs).  The Nix sandbox does not provide a writable `/run`.  However:

- `libpcsclite` (the client library) honours `PCSCLITE_CSOCK_NAME` to redirect
  to an arbitrary path.
- pcsclite can be recompiled with `-Dipcdir=<path>` to change the daemon's
  socket path.
- vpcd communicates with `vpicc` over **TCP** (`localhost:35963` by default),
  not a Unix socket.  The port is configurable via `reader.conf`.
- `vpicc::connect_socket(addr)` accepts an arbitrary address.

### Chosen approach: NixOS VM test

The NixOS test framework (`pkgs.nixosTest` / `pkgs.testers.runNixOSTest`)
runs tests inside a QEMU VM that has a real systemd, writable `/run`, and
network.  This sidesteps all sandbox limitations cleanly and is the standard
pattern in nixpkgs for testing daemons.

The alternative (recompile pcsclite with a custom `ipcdir`, run pcscd as a
background process in a derivation with `__noChroot = true`) is fragile and
non-standard.  The VM approach is preferred.

## Specification

### New Nix output: `integration-tests`

Add an `integration-tests` attribute to `default.nix` that runs the
`nixosTest` framework:

```nix
integration-tests = pkgs.nixosTest {
  name = "yb-integration-tests";

  nodes.machine = { config, pkgs, ... }: {
    services.pcscd.enable = true;
    services.pcscd.plugins = [ pkgs.vsmartcard-vpcd ];
    environment.systemPackages = [ pivAuthenticatorBin ybRustTests ];
  };

  testScript = ''
    machine.wait_for_unit("pcscd.socket")
    machine.succeed(
      "piv-authenticator-vpicc &"
      + " sleep 1"
      + " && cargo test ... --features integration-tests"
    )
  '';
};
```

### New crane derivation: `pivAuthenticatorBin`

Build the `piv-authenticator` `examples/vpicc` binary with crane:

```nix
pivAuthenticatorBin = crane.buildPackage {
  src = pkgs.fetchgit {
    url = "https://github.com/trussed-dev/piv-authenticator";
    rev = "a4a4204e7089a6a5a99907877576cc40c75825ab";
    sha256 = "<hash>";
  };
  cargoExtraArgs = "--example vpicc --features vpicc";
  nativeBuildInputs = [ pkgs.llvmPackages.libclang pkgs.pkg-config ];
  LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
};
```

### New crane derivation: `ybHarnessTests`

Build and run the `yb-piv-harness` test binary:

```nix
ybHarnessTests = crane.cargoTest (rustCommon // {
  pname          = "yb-harness-tests";
  cargoArtifacts = rustDeps;
  cargoExtraArgs = "-p yb-piv-harness --features integration-tests";
});
```

This derivation is **not** run directly by `nix-build default.nix` (it would
fail in the sandbox).  Instead it is included as an input to the `nixosTest`
`testScript`, which runs it inside the VM where pcscd is available.

### Test flow inside the VM

1. systemd starts `pcscd.socket` with the vpcd plugin loaded.
2. `testScript` waits for `pcscd.socket` to be active.
3. `testScript` starts the `piv-authenticator` vpicc binary in the background.
4. A 1-second sleep lets the virtual card register with pcscd.
5. `testScript` runs the pre-built `ybHarnessTests` binary directly (no
   recompilation inside the VM).
6. Test results are reported back to the Nix build; non-zero exit fails the
   derivation.

### `with_vsc` adjustment

The `with_vsc` helper in `yb-piv-harness/src/lib.rs` currently checks for
`/var/run/vpcd` to detect whether vpcd is available.  This check is wrong for
the VM approach (vpcd is accessed via pcscd, not directly via a socket).
Replace the check with a PC/SC reader enumeration: if no virtual reader is
found within a timeout, skip gracefully.

### `default.nix` exports

```nix
{
  # existing
  yb-rust         = ybRust;
  rust-fmt        = rustFmt;
  rust-clippy     = rustClippy;
  rust-tests      = rustTests;         # tier-1 only (fast, no VM)
  # new
  integration-tests = integrationTests; # tier-1 + tier-2 via NixOS VM
}
```

`nix-build -A integration-tests` runs everything.
`nix-build -A rust-tests` remains fast (tier-1 only, no VM overhead).

### CI configuration

CI should run both:
- `nix-build -A rust-tests` (fast gate on every PR)
- `nix-build -A integration-tests` (full gate, scheduled or on main)

## Open questions

None.

## References

- `docs/specs/0004-tier2-hardware-piv-tests.md` — tier-2 harness spec
- `vendor/piv-authenticator/examples/vpicc.rs` — vpicc entry point
- `rust/yb-piv-harness/src/lib.rs` — `with_vsc` helper (needs adjustment)
- nixpkgs `nixos/tests/pcsclite.nix` — reference NixOS test for pcscd
- [vpicc docs.rs](https://docs.rs/vpicc/latest/vpicc/) — `connect_socket` API
