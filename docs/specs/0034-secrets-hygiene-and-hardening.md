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
- **G2 — No secrets as arguments.**  `--pin` and `--key` are removed;
  using them fails with a message pointing to `YB_PIN`, `--pin-stdin`, the
  prompt, and `YB_MANAGEMENT_KEY`.
- **G3 — No silent redirection.**  A simulated YubiKey is never used
  without the user being told, and never by accident (see Open questions
  for the mechanism).
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

## Specification

To be completed after the open questions.  Sketch:

- `Context`: the management key as `Option<Zeroizing<String>>`;
  `management_key_for_write` returns `Zeroizing<String>`; PRINTED parsing
  writes into a `Zeroizing<Vec<u8>>`.
- `--pin`, `--key`: removed from the parser; a dedicated error if given.
- Legacy CBC: decrypt as today; warning on stderr; `ls -l` flag.
- `fetch`: `require_pin` only for encrypted matches.
- `next_age`: refuse beyond `0xFF_FFFF`; `fsck` warns beyond 90%.
- `from_device_raw`: mismatching `object_count` → object treated as empty
  by `sanitize`, reported by `fsck`.

## Open questions

- **G3 mechanism**, three options:
  1. keep `YB_FIXTURE` in release binaries, and print a warning on every
     run where it is active (simple; the VM test keeps testing the packaged
     binary);
  2. also require a second variable confirming the intent (e.g.
     `YB_FIXTURE_ALLOW=1`), set by the test harness only;
  3. compile fixture support out of release binaries, and have the VM test
     run a test build of `yb` (safest; the VM test then no longer tests
     the packaged binary's command line).
- G2 is a breaking change for scripts still using `--pin`/`--key` (hidden
  and deprecated since spec 0024): remove now, in 0.6.0, or keep with a
  warning one more release?

## References

- Spec 0006 — security hardening (AES-GCM).
- Spec 0024 — default-credential policy; deprecation of `--pin`, `--key`.
- Spec 0027 — management key rotation.
- Spec 0029 — NixOS VM test (`yb_cli_tests`, `YB_FIXTURE`).
- `docs/reviews/2026-10-python-design-audit.md`.
