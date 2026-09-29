<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0025 — Actionable Error Messages

**Status:** implemented
**App:** yb
**Implemented in:** 2026-09-29

## Problem

When the YubiKey rejects a command, yb reports the APDU label and the
raw status word (SW), plus a generic description
(`piv/session/transport.rs`, `sw_description`):

```
Error: MGMT AUTH step1 failed: SW=6a80 (incorrect parameters in data field)
```

This tells a developer which APDU failed.  It tells a user nothing:

- **Protocol vocabulary.**  "MGMT AUTH step1" and "incorrect parameters
  in data field" describe the protocol, not the user's situation.  The
  real cause in this example was a firmware 5.7 YubiKey whose
  management key uses AES-192, not 3DES (spec 0021).
- **The same SW means different things for different operations.**
  `6A80` during management key authentication means an algorithm
  mismatch; during PUT DATA it means a malformed object.  `6A82` on the
  store slot's certificate means "no key set up yet"; on PRINTED it
  means "the management key is not PIN-protected".  One table cannot
  describe both.
- **No next step.**  No message says what to run or check next.
- **Errors below the card level are raw too.**  PC/SC failures show the
  raw library message, or a bare "No PC/SC readers found."  Yet each
  one has a common, fixable cause:
  - pcscd not running;
  - another program (gpg's scdaemon) holding the YubiKey;
  - a VM without working USB passthrough;
  - the YubiKey removed mid-operation.
- **Messages are built in many places.**  They are assembled with
  `bail!` wherever the error occurs, some without the SW at all (`VERIFY
  PIN failed: SW=…`).

The raw codes are still valuable for bug reports and must stay, but
they should come after an explanation.

## Goals

- Every error that reaches the user says, in this order:
  1. **what** yb could not do, in user terms;
  2. **why**, the most likely cause given the operation and the card
     state;
  3. **what to do**: a concrete command or check;
  4. **details**: operation label and SW, or the PC/SC error code, on
     one line, for bug reports.
- The explanation depends on the operation and the SW together, plus
  what the failing step knows (e.g. the management key algorithm yb
  used), never on the firmware version.
- Combinations yb doesn't recognize still produce the details line,
  plus an invitation to report the issue.
- The mapping is data-driven, lives in one place, and every entry is
  tested.

## Non-goals

- Distinct exit codes per error class.  Exit status stays 1.
- Localization.
- APDU tracing (a debug mode that logs every APDU).  This could be a
  separate spec.
- Rewording errors that do not come from the card or PC/SC (argument
  validation, file I/O), beyond making them follow the same layout
  where cheap.

## Specification

### 1. Error type

Two typed errors in `yb-core` replace the string-built messages.

**`CardError`**, for failures reported by the card or by PC/SC:

```rust
pub enum CardError {
    Status { op: CardOp, sw: u16, ctx: ErrCtx },
    Pcsc   { op: PcscOp, code: PcscCode },
    Protocol { op: CardOp, what: String },   // malformed response, too short, …
}
```

- **`CardOp`** names the operation in yb terms, one variant per call
  site:
  - `SelectPiv`, `VerifyPin`, `MgmtAuth`, `SetMgmtKey`;
  - `ReadObject(ObjId)`, `ReadCertificate(slot)`, `WriteObject(ObjId)`;
  - `GenerateKey(slot)`, `Sign(slot)`, `Ecdh(slot)`;
  - `GetMetadata(slot)`, `Command` (any other card command, e.g. a raw
    APDU);
  - `ChangePin` and `ChangePuk` arrive with spec 0023, which introduces
    those operations.
- **`ErrCtx`** carries only what the failing step itself knows, e.g. the
  management key algorithm yb used (from the spec 0021 detection) and
  which object or slot was involved.  It carries no firmware version.
- `transmit_check` takes a `CardOp` instead of a `&str` label.

**`YbError { what, why, fix }`**, for yb's own errors, the ones that do
not come from the card.  Examples: the spec 0022 key resolution ("the
management key is not in PRINTED…"), the key/certificate mismatch, the
spec 0024 policy refusals, and the spec 0022 Phase B messages.  These
messages move into this layout, with light rewording at most.

Both types implement `std::error::Error`.  They travel through `anyhow`
unchanged, and `main` downcasts them for rendering (§3).

**The catalog never depends on the firmware version.**  Where a status
word's meaning once depended on firmware, yb now asks the card instead
(spec 0021: the management key algorithm).

### 2. Mapping table

A single table, `yb-core/src/errors/catalog.rs`, maps `(CardOp pattern,
SW pattern)` to `{ what, why, fix }` text templates.  The first matching
entry wins; more specific entries come first.

Initial entries.  The "Fix" column is abridged here; implementations
give full commands.

| Operation | SW / code | What | Why | Fix |
|---|---|---|---|---|
| `VerifyPin` | `63Cx` | Wrong PIN | — | `x` attempts left; at 1: "one more failure blocks the PIN" |
| `VerifyPin` | `6983` | PIN is blocked | too many wrong attempts | unblock with the PUK (`ykman piv access unblock-pin`); if the PUK is also blocked, a PIV reset is needed (erases everything) |
| `ChangePin`/`ChangePuk` (added by spec 0023) | `6985` | New PIN/PUK rejected | does not meet this YubiKey's complexity policy (spec 0023 §6) | choose a less guessable value |
| `MgmtAuth` | `6A80` | Cannot authenticate with the management key | the card rejected the algorithm yb used (shown, from `ErrCtx`); only possible if detection had to guess (firmware without GET METADATA) | `ykman piv info` shows the card's algorithm; report a bug if they match |
| `MgmtAuth` | `6982` | Wrong management key | the key from `YB_MANAGEMENT_KEY` or PRINTED is not the card's key (on real hardware this surfaces at authentication step 2) | check `YB_MANAGEMENT_KEY`; `ykman piv info` shows whether the key is PIN-protected |
| `MgmtAuth` | response mismatch | Wrong management key | same as above, detected by yb instead of the card | same as above |
| `ReadObject(PRINTED)` | `6A82` | Management key is not stored on the YubiKey | card is not in PIN-protected mode, or it was set up by another tool | set `YB_MANAGEMENT_KEY`, or re-run setup with `yb format` |
| `ReadObject(cert of store slot)` | `6A82` | No key in slot 0x82 | the YubiKey has not been set up for yb | run `yb format` |
| `WriteObject(_)` | `6A84` | The YubiKey's storage is full | the PIV applet's ~51 KB are used up | `yb fsck --nvm`; remove blobs |
| `WriteObject(_)` | `6982` | Write not permitted | management key authentication did not happen or was lost | likely a yb bug: report it |
| `GenerateKey`, `Sign`, `Ecdh` | `6982` | The YubiKey requires the PIN (or touch) for this key | PIN not verified, or touch policy | re-run and touch the key if it blinks |
| `Sign`/`Ecdh` | `6A80` | The key in slot 0x82 cannot do this operation | not an EC P-256 key | `yb format --generate` (erases the store) |
| any | `6D00` | This YubiKey does not support the operation | its firmware is too old for it | — |
| `SelectPiv` | `6A82` | The PIV application is not available | PIV disabled on this key, or not a YubiKey | `ykman config usb --enable PIV` |

PC/SC errors:

| Code | What | Fix |
|---|---|---|
| `SCARD_E_NO_SERVICE` | The smart card service is not running | start pcscd (`systemctl start pcscd.socket`); on NixOS `services.pcscd.enable = true` |
| `SCARD_E_NO_READERS_AVAILABLE` / empty list | No YubiKey found | plugged in? CCID interface enabled (`ykman config usb`)? In a VM, check USB passthrough (`lsusb` shows `1050:…`) |
| `SCARD_E_SHARING_VIOLATION` | Another program is using the YubiKey | usually gpg's scdaemon: `gpgconf --kill scdaemon` |
| `SCARD_W_REMOVED_CARD`, `SCARD_W_RESET_CARD` | The YubiKey was removed or reset during the operation | reconnect; for write commands, run `yb fsck` to check the store |

**Interim wording.**  Fixes point to `ykman piv info` where spec 0023's
`yb fsck` YubiKey section will later give the same information; spec
0023 updates those entries.

Fallback, when no entry matches: an unexpected error.  This is the one
place that carries **all the context available**: the operation, the
status word, `ErrCtx`, the firmware version and the yb version.  It
still never carries the identifying data listed in §3.

```
Error: the YubiKey rejected <op description>.
  This is unexpected — please report it at https://github.com/douzebis/yb/issues
  with the details below.
  (details: <op> → SW <sw>; <ErrCtx>; firmware <version>; yb <version>)
```

`main` supplies the firmware version, which it knows from the device
list; the failing step does not need to.

### 3. Rendering

Rendering is a **pure function** from the error (and, for the fallback,
the firmware version) to text, so that tests check it directly.  `main`
prints its result on stderr:

```
Error: cannot authenticate with the management key.
  The YubiKey rejected the 3DES algorithm yb used.
  Try: `ykman piv info` shows the card's management key algorithm.
  (details: management key authentication → SW 6A80)
```

- The first line always starts with `Error: `, as today.
- The `why` and `fix` lines are omitted when empty.
- The details line is present for every `CardError`: the `CardOp`
  description and the 4-digit SW in uppercase hex.  It carries no
  firmware version, except in the fallback (§2).  `YbError` has no
  details line.
- **Errors with context.**  Errors often travel wrapped in context (e.g.
  spec 0022's "yb format stopped while erasing the store… Run `yb format`
  again", around a card error).  The outer context stays the headline.
  The inner `CardError` or `YbError` follows with its `why` as `Cause:`
  and its `fix` as `Try:`, then the details line:

  ```
  Error: yb format stopped while erasing the store (completed: …).  The store may be partly erased; …
    Cause: the YubiKey's storage is full (the PIV area's ~51 KB are used up).
    Try: `yb fsck --nvm`, then remove blobs.
    (details: write object 0x5F0003 → SW 6A84)
  ```

  Without an outer context, the error's own `what` is the headline, and
  `why` and `fix` follow as in the first example.
- **No identifying data in error output.**  Error messages, including
  the details line and the fallback text, must never contain:
  - the YubiKey serial number;
  - the PC/SC reader name, which can identify the device;
  - key material (PIN, PUK, management key).

  Users paste these messages into public bug reports.  A test asserts
  that the virtual backend's serial and reader name never appear in
  rendered errors.  Interactive output that is not an error, such as the
  `fsck` report or the guided-format confirmation, may still show the
  serial.
- Other errors (argument parsing, file I/O) render as today
  (`Error: {e:#}`).
- **Partial writes:** when a card error interrupts `Store::sync` after at
  least one object was written, `Store::sync` adds the context "the store
  may be partially updated; run `yb fsck`".  It is added in that one
  place, so it applies to `store` and `rm`.  `format` has its own spec
  0022 messages, which take precedence.

### 4. Migration

- Remove the free-standing `sw_description`; the catalog replaces it.
- Replace existing ad-hoc `bail!` sites that inspect SWs, such as
  `verify_pin`'s `VERIFY PIN failed: …`, with `CardError`.
- Map `pcsc::Error` values to `CardError::Pcsc`.  "No PC/SC readers
  found." (`list-readers`) and "no YubiKey found" (device selection)
  become the same catalog entry.
- Move the yb-level messages of specs 0021–0024 into `YbError`: key
  resolution, key/certificate mismatch, policy refusals, and the Phase B
  and key-switch messages.
- **Remove identifying data from existing messages:**
  - `transport.rs`: "connecting to reader '{reader}'";
  - `context.rs`: "no device on reader '{r}'";
  - `context.rs`: "no YubiKey with serial {s} found".  It echoes the
    serial the user typed, which still ends up in pasted reports.
- **Virtual backend:** for the failures it emulates, `VirtualPiv` returns
  the `CardError` a real YubiKey would produce, with the same status word:
  - wrong PIN `63Cx`, with the tries left;
  - blocked PIN `6983`;
  - wrong management key `6982`;
  - missing object `6A82`;
  - storage full `6A84` (new injectable fault).

  It does not emulate APDUs byte by byte; it fails the way the card
  does, so the CLI tests exercise the rendering users see.

### 5. Tests

- **Every catalog entry** has a unit test: a `CardError` with that
  operation and status word, rendered by the pure function, asserting the
  `what` line and the details line.
- **End to end:** the CLI tests trigger the failures the virtual backend
  emulates (wrong PIN, blocked PIN, wrong management key, storage full)
  and assert the rendered text.
- **Fallback**: an unmapped `(op, SW)` renders the report invitation and
  the full details, including the firmware version.
- **Composition**: a card error wrapped in context renders as `Cause:` /
  `Try:` under the context headline.
- **Coverage**: a compile-time match ensures no `CardOp` variant is left
  without a description.
- **No identifying data**: rendered errors never contain the virtual
  backend's serial or reader name, nor any PIN, PUK or management key.
- **Snapshot tests** on the full rendered text of the examples in this
  spec.

### 6. Backward compatibility

- Exit codes are unchanged (1 on error).
- stdout is unchanged.
- stderr error text changes.  Scripts that matched on `SW=…` strings
  will need updating: the SW is still there, but on the details line,
  in the form `SW 6A80`.
- No card data changes.  Spec 0021 §6 applies.

## Open questions

None.  APDU tracing is recorded as a placeholder in
[spec 0026](0026-apdu-trace.md).

## References

- [spec 0021](0021-firmware-5.7-management-key.md) — the `6A80` case that motivated this spec
- [spec 0022](0022-format-sequence.md) — format failure messages
- [spec 0023](0023-guided-format.md) — `fsck` YubiKey section, PIN complexity
- [spec 0024](0024-default-credential-policy.md) — default-credential refusals
- `rust/yb-core/src/piv/session/transport.rs` — `transmit_check`, `sw_description`
- PC/SC Lite error codes: `pcsclite.h`
