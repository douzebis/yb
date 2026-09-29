<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0026 — APDU Trace (placeholder)

**Status:** draft
**App:** yb
**Implemented in:** <!-- YYYY-MM-DD, fill after implementation -->

> **Placeholder.**  This spec records an idea so it is not forgotten.
> It has not been designed yet.  Do not implement it until it has been
> fleshed out and marked `ready`.

## Problem

When a card operation fails, the user sees only the final error (spec
0025).  The exchange that led up to it is invisible: which algorithm yb
assumed, what the card had just replied, and whether a retry happened.
Diagnosing, for example, the firmware 5.7 `6A80` (spec 0021) took
several rounds of guesswork that a log of the exchange would have
avoided.

## Idea

An opt-in debug mode, e.g. `YB_DEBUG=1`, that logs every APDU sent to
the YubiKey and every response, in order, to stderr or a file, with a
short label per command:

```
→ 00 F7 00 9B 00                  GET METADATA (mgmt key)
← 01 01 03 02 02 00 01 05 01 01   9000
→ 00 87 03 9B 04 7C 02 80 00      MGMT AUTH step 1 (3DES)
←                                 6A80
```

## Constraints to respect

- **Redaction is mandatory.**  VERIFY PIN sends the PIN in plain text,
  and other commands carry management-key bytes, PRINTED contents, and
  decrypted material.  These bytes must be masked in the trace.
- **The serial and reader name** must be masked too (see spec 0025,
  "No identifying data in error output").
- Off by default; there is no cost when disabled.

## To be decided

- Activation (env var, flag, or both) and destination (stderr or a
  file).
- Whether GET DATA / PUT DATA payloads (blob contents) are elided
  entirely or truncated.
- Whether the trace runs in `transmit_raw` (all APDUs) or at the
  `CardOp` level (spec 0025).

## References

- [spec 0021](0021-firmware-5.7-management-key.md) — the case that motivated it
- [spec 0025](0025-actionable-errors.md) — actionable errors, no identifying data
