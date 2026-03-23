<!--
SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0018 — Integrity Signals in `yb ls`

**Status:** implemented
**App:** yb
**Implemented in:** 2026-03-23

## Problem

`yb ls` shows blob names and metadata but gives no indication of
integrity.  A corrupted blob is indistinguishable from a healthy one
until the operator runs `yb fsck`.  Since `fsck` is a separate step
that requires deliberate invocation, corruption can go unnoticed.

## Goals

- `yb ls` performs a per-blob integrity check (same verdict logic as
  `fsck`, spec 0017 §4) and marks CORRUPTED blobs visibly in its output.
- Clean output (no CORRUPTED blobs) is byte-for-byte identical to the
  current output.
- Blob names that require quoting are displayed in single-quoted form,
  following the shell quoting convention of GNU coreutils `ls`, so the
  CORRUPTED marker is never ambiguous.
- `yb ls` exits with code 1 if any blob is CORRUPTED, 0 otherwise.

## Non-goals

- Adding new CLI flags (`--integrity`, `--no-quoting`, etc.).
- Showing UNVERIFIED/VERIFIED labels in `ls` output (that is `fsck`'s
  role; `ls` only signals the actionable case).
- Changing the output for UNVERIFIED blobs.

## Specification

### 1. Integrity check

After loading the store, `yb ls` performs the same signature check as
`fsck`:

1. Read the X.509 certificate from slot `0x82` and extract the P-256
   public key (no PIN required).  If the cert is unreadable, treat the
   verifying key as absent (same as `fsck`).
2. For each blob head, call `check_blob_signature` to obtain a
   `SigVerdict`.  This function is moved from `cli/fsck.rs` to
   `cli/util.rs` so that both `ls` and `fsck` can use it.
3. Only `SigVerdict::Corrupted` is acted upon in the output.

### 2. Name quoting

A blob name is displayed **quoted** if and only if it contains at least
one character that is not in the following safe set:

```
a–z  A–Z  0–9  .  -  _  +  ,  /  :
```

Any whitespace, shell metacharacter, non-ASCII byte, or control
character triggers quoting.

Quoting uses the POSIX shell single-quote convention:

- Wrap the name in single quotes: `'name'`
- Replace every embedded `'` with `'\''`

Examples:

| Raw name       | Displayed as      |
|----------------|-------------------|
| `mysecret`     | `mysecret`        |
| `my secret`    | `'my secret'`     |
| `it's here`    | `'it'\''s here'`  |
| `foo$bar`      | `'foo$bar'`       |
| `café`         | `'café'`          |

### 3. Output format

In the absence of any CORRUPTED blob the output is identical to today
(quoting is applied consistently — names that previously needed none
still need none, since typical blob names contain only safe characters).

For CORRUPTED blobs, the displayed name is followed by two spaces and
the marker `CORRUPTED`:

**Short mode (`yb ls`):**
```
mysecret
'my secret file'  CORRUPTED
other-blob
```

**Long mode (`yb ls -l`):**
```
-  1  Jan 15 14:30    512  mysecret
-  2  Jan 15 14:32   1234  'my secret file'  CORRUPTED
P  1  Mar 20 09:01    256  other-blob
```

The CORRUPTED marker is always the last token on the line.  Because all
name characters that could be confused with the marker (spaces, letters)
are inside single quotes when the name requires quoting, there is no
ambiguity.

### 4. Exit code

`yb ls` exits with code 1 if at least one blob is CORRUPTED, 0
otherwise.  This mirrors `fsck` behavior and allows scripting:

```sh
yb ls || alert "store corruption detected"
```

### 5. Performance

The integrity check requires one additional `GET DATA` APDU to read the
certificate from slot `0x82`.  For a 32-object store this adds one APDU
to an existing ~32 APDU scan — negligible.

## Open questions

None.

## References

- [spec 0017](0017-blob-integrity-signature.md) — blob integrity
  signature and verdict logic
- GNU coreutils `ls` quoting: `info '(coreutils) Formatting file names'`
