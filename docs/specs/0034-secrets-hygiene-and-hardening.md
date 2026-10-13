<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0034 — Secrets Hygiene and Hardening

**Status:** draft
**App:** yb
**Implemented in:** <!-- YYYY-MM-DD, fill after implementation -->

## Problem

The audit of 2026-10-13 (`docs/reviews/2026-10-python-design-audit.md`,
findings 1.2 and 1.3) found several smaller weaknesses, each unrecorded:

- **Management key lifetime.**  When the management key is kept on the
  YubiKey, yb must read it into memory to authenticate (the PIV protocol
  requires the host to know it; ykman does the same), so "the management
  key never leaves the YubiKey" was never true.  But yb also keeps it
  longer and in more copies than needed: `Context::management_key` is a
  plain `Option<String>`, and `management_key_for_write` returns `String`
  copies that are never zeroized.
- **Secrets on the command line.**  The hidden, deprecated `--pin` and
  `--key` options still accept the PIN and the management key as
  arguments, visible to other users in the process list.
- **`YB_FIXTURE` in release binaries.**  When set, it makes yb use a
  simulated YubiKey described in a file instead of the real one.  It is
  how the packaged binary is tested in the NixOS VM test (`yb_cli_tests`),
  but in a user's environment it silently redirects yb: a `yb store` would
  write secrets into that file, on disk.
- **Legacy unauthenticated ciphertext.**  Blobs written before spec 0006
  (AES-CBC, no authentication) are still decrypted silently.
- **`yb fetch` asks for the PIN** even when every matched blob is
  unencrypted.
- **No age overflow guard.**  Ages are 24-bit; a wrapped age of 0 would
  make an object look empty (the Python implementation asserted the
  bound).  Theoretical (about 16 million object writes).
- **No `object_count` cross-check.**  Each object records the store's
  object count; the Python implementation checked it against object 0,
  the Rust one does not, so a stray object is accepted silently.

## Goals

- **G1 — Management key: least time, least copies.**  The management key
  is held only in zeroizing memory (`Zeroizing`), obtained right before an
  operation that needs it and dropped right after; no plain `String`
  copies, including the bytes read from PRINTED.  The documentation states
  that the key is read into memory when kept on the YubiKey.
- **G3 — No simulated card outside tests.**  Support for `YB_FIXTURE` is a
  Cargo feature, `test-fixture`, off by default in every build (release
  and debug); only the test harnesses that need it turn it on.  A `yb`
  built without it refuses to run when `YB_FIXTURE` is set, saying that
  this build has no simulated-card support, so that a stray variable
  never goes unnoticed.
- **G4 — Legacy ciphertext flagged.**  Fetching a pre-0006 (AES-CBC) blob
  works, with a warning recommending to store it again; `yb fsck` and
  `yb ls -l` flag such blobs.
- **G5 — PIN only when needed.**  `yb fetch` asks for the PIN only if a
  matched blob is encrypted (or, after spec 0033, if verification needs
  it: it does not, the certificate suffices).
- **G6 — Age bound.**  A store that would push an age beyond 24 bits fails
  before writing, with a message (reformatting resets ages); `yb fsck`
  warns as the bound nears.
- **G7 — Foreign objects.**  An object whose `object_count` differs from
  object 0's is treated as corrupt: ignored by `sanitize`, reported by
  `yb fsck`.

## Non-goals

- Keeping the management key out of host memory (impossible with PIV's
  host-side authentication).
- Memory locking (`mlock`) or core-dump suppression; possible later.
- Removing `YB_PIN` and `YB_MANAGEMENT_KEY`: environment variables are
  visible only to the same user's processes, and are the documented
  non-interactive path.
- Removing the hidden, deprecated `--pin` and `--key` options, which put
  secrets on the command line: kept for a while longer (decision of
  2026-10-13); a later spec removes them.

## Specification

To be completed after the open questions.  Sketch:

- `Context`: the management key as `Option<Zeroizing<String>>`;
  `management_key_for_write` returns `Zeroizing<String>`; PRINTED parsing
  writes into a `Zeroizing<Vec<u8>>`.
- `test-fixture` feature (in `yb-core` and `yb`): gates `YB_FIXTURE` in
  `main.rs`, `context.rs`, `complete.rs`, `list_readers.rs`, `select.rs`.
  Enabled by `yb`'s and `yb-core`'s tests, and by `yb-piv-harness` for
  the `yb` binary that `yb_cli_tests` runs.  The NixOS VM test then runs
  `yb_cli_tests` against a `yb` built with the feature, from the same
  source, inside the harness derivation, instead of the packaged binary:
  a change to the staged nixpkgs files, shipped with the next release.
- Legacy CBC: decrypt as today; warning on stderr; `ls -l` flag.
- `fetch`: `require_pin` only for encrypted matches.
- `next_age`: refuse beyond `0xFF_FFFF`; `fsck` warns beyond 90%.
- `from_device_raw`: mismatching `object_count` → object treated as empty
  by `sanitize`, reported by `fsck`.

## Open questions

None.  Decided on 2026-10-13: `YB_FIXTURE` compiled out of every build
by default (G3); `--pin` and `--key` kept for now (Non-goals).

## References

- Spec 0006 — security hardening (AES-GCM).
- Spec 0024 — default-credential policy; deprecation of `--pin`, `--key`.
- Spec 0027 — management key rotation.
- Spec 0029 — NixOS VM test (`yb_cli_tests`, `YB_FIXTURE`).
- `docs/reviews/2026-10-python-design-audit.md`.
