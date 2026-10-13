<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0037 — PIN and Payload on One Standard Input

**Status:** implemented
**App:** yb
**Implemented in:** 2026-10-13

## Problem

A program that drives `yb` (KeePassXC, spec 0030) must give it both the
PIN and a blob's content without a file on disk, without the PIN on the
command line or in the environment.  `yb --pin-stdin store -n <name>`
does it today: the first line of standard input is the PIN, the rest is
the payload.  But this works by accident (Rust's standard input has one
shared buffer, so the payload read starts where the PIN line ended), and
nothing documents or tests it: a change to how the PIN is read could
silently corrupt every blob stored this way.

## Goals

- **G1 — A documented contract.**  With `--pin-stdin`, yb reads the first
  line of standard input as the PIN, before anything else, whatever the
  command; a command that reads a payload from standard input (`yb store`
  without files) gets everything after that line, byte for byte: binary
  data, NUL bytes, newlines, no final newline, or nothing at all.
- **G2 — The PIN line.**  It ends at the first `\n`; a `\r` before it is
  dropped (Windows line endings).  Nothing else is trimmed.  End of input
  before any `\n` makes the whole input the PIN (as today).
- **G3 — Tested through the binary,** as callers use it.

## Non-goals

- A separate file descriptor for the PIN (`--pin-fd`): `QProcess` and
  similar APIs give a child one standard input; one stream suffices.
- Reading several payloads from standard input.

## Specification

- Help of `--pin-stdin`: "Read the PIN from the first line of standard
  input; a payload read from standard input (yb store) follows it."
- yb(1) and yb-store(1): the same, with an example:
  `{ printf '%s\n' "$PIN"; cat vault.kdbx; } | yb --pin-stdin store -n vault.kdbx`.
- Code: unchanged; a comment at the PIN read states the contract and
  points to this spec.
- Tests (`rust/yb/tests/exit_status_tests.rs`, through the binary on a
  simulated YubiKey): a payload with NUL bytes, `\r\n`, `\n` runs and no
  final newline round-trips byte for byte through `store` and `fetch -p`
  (`binary_payload_follows_the_pin_line`); an empty payload
  (`empty_payload_after_the_pin_line`); a PIN line ending in `\r\n`
  (`pin_line_with_crlf`); input without a newline
  (`pin_without_newline`).  Reading the PIN through a private buffer
  instead of the shared one makes them fail.

## Invariants

- None new: an interface contract, with its regression tests.

## Open questions

None.

## References

- Spec 0030 — KeePassXC integration.
- Spec 0024 — `--pin-stdin` and the PIN sources.
