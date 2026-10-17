<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# Proof of concept: OpenSK as a FIDO2 test authenticator

Spec 0028 (post-quantum stores) needs FIDO2 tests without a YubiKey.  This
program runs Google's OpenSK in-process as a software authenticator and
drives it through the real libfido2, using libfido2's custom I/O functions
(`fido_dev_set_io_functions`): no USB device, no root.  It replays the
YubiKey hardware results of the spec (touch, PIN, `credProtect`,
`hmac-secret` with two salts, signatures, PIN attempts, power cycle).

Results (2026-10-16): see spec 0028, "Prerequisites", proof of concept.

Run, from this directory:

```shell
nix-shell -p libfido2 pkg-config cargo rustc --run 'cargo run --release'
```

OpenSK is not on crates.io; it is fetched from git, pinned to a commit.
This is a throwaway prototype, not part of the yb build.
