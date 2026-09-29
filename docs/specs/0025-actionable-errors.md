<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0025 — Actionable Error Messages

**Status:** draft
**App:** yb
**Implemented in:** <!-- YYYY-MM-DD, fill after implementation -->

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
- The explanation depends on the operation and the SW together, and on
  known card state (firmware, management key algorithm) where that is
  available.
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

Replace the string-built card errors with a typed error in `yb-core`:

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
  - `ReadObject(ObjId)`, `WriteObject(ObjId)`;
  - `GenerateKey(slot)`, `Sign(slot)`, `Ecdh(slot)`;
  - `ChangePin`, `ChangePuk`, `GetMetadata(slot)`.
- **`ErrCtx`** carries what is known at the time of the error:
  - firmware version and management key algorithm, if known;
  - whether the PIN was verified in this session;
  - which object id or slot was involved.
- `transmit_check` takes a `CardOp` instead of a `&str` label.
- `CardError` implements `std::error::Error`.  It travels through
  `anyhow` unchanged, and `main` downcasts it for rendering (§3).

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
| `ChangePin`/`ChangePuk` | `6985` | New PIN/PUK rejected | does not meet this YubiKey's complexity policy (spec 0023 §6) | choose a less guessable value |
| `MgmtAuth` | `6A80` | Cannot authenticate with the management key | the card uses a different algorithm than yb used (shows both, if known) | `yb fsck` shows the algorithm; report a bug if they match |
| `MgmtAuth` | response mismatch | Wrong management key | the key from `YB_MANAGEMENT_KEY` / PRINTED is not the card's key | check `YB_MANAGEMENT_KEY`; `yb fsck` shows the protection mode |
| `ReadObject(PRINTED)` | `6A82` | Management key is not stored on the YubiKey | card is not in PIN-protected mode, or it was set up by another tool | set `YB_MANAGEMENT_KEY`, or re-run setup with `yb format` |
| `ReadObject(cert of store slot)` | `6A82` | No key in slot 0x82 | the YubiKey has not been set up for yb | run `yb format` |
| `WriteObject(_)` | `6A84` | The YubiKey's storage is full | the PIV applet's ~51 KB are used up | `yb fsck --nvm`; remove blobs |
| `WriteObject(_)` | `6982` | Write not permitted | management key authentication did not happen or was lost | likely a yb bug: report it |
| `GenerateKey`, `Sign`, `Ecdh` | `6982` | The YubiKey requires the PIN (or touch) for this key | PIN not verified, or touch policy | re-run and touch the key if it blinks |
| `Sign`/`Ecdh` | `6A80` | The key in slot 0x82 cannot do this operation | not an EC P-256 key | `yb fsck`; `yb format` with a new key |
| any | `6D00` | This YubiKey does not support the operation | firmware too old (shows version) | — |
| `SelectPiv` | `6A82` | The PIV application is not available | PIV disabled on this key, or not a YubiKey | `ykman config usb --enable PIV` |

PC/SC errors:

| Code | What | Fix |
|---|---|---|
| `SCARD_E_NO_SERVICE` | The smart card service is not running | start pcscd (`systemctl start pcscd.socket`); on NixOS `services.pcscd.enable = true` |
| `SCARD_E_NO_READERS_AVAILABLE` / empty list | No YubiKey found | plugged in? CCID interface enabled (`ykman config usb`)? In a VM, check USB passthrough (`lsusb` shows `1050:…`) |
| `SCARD_E_SHARING_VIOLATION` | Another program is using the YubiKey | usually gpg's scdaemon: `gpgconf --kill scdaemon` |
| `SCARD_W_REMOVED_CARD`, `SCARD_W_RESET_CARD` | The YubiKey was removed or reset during the operation | reconnect; for write commands, run `yb fsck` to check the store |

Fallback, when no entry matches:

```
Error: the YubiKey rejected <op description>.
  This is unexpected — please report it at https://github.com/douzebis/yb/issues
  with the details line below.
```

### 3. Rendering

On stderr, in `main`:

```
Error: cannot authenticate with the management key.
  The YubiKey expects an AES-192 key, but yb used 3DES.
  Try: `yb fsck` to see the management key settings.
  (details: management key authentication → SW 6A80, firmware 5.7.1)
```

- The first line always starts with `Error: `, as today.
- The `why` and `fix` lines are omitted when empty.
- The details line is always present for `CardError`.  It uses the
  `CardOp` description, the 4-digit SW in uppercase hex, and the
  firmware version when known.
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
- Errors that are not `CardError` render as today (`Error: {e:#}`).
- For write commands (`store`, `rm`, `format`), a card error after the
  first write APDU adds: `The store may be partially updated; run `yb
  fsck`.`  Spec 0022 already covers `format`'s own messages; those take
  precedence.

### 4. Migration

- Remove the free-standing `sw_description`; the catalog replaces it.
- Replace existing ad-hoc `bail!` sites that inspect SWs, such as
  `verify_pin`'s `VERIFY PIN failed: …`, with `CardError`.
- Specs 0021–0024 introduce new errors (algorithm mismatch, B1c
  recovery, key/certificate mismatch, default-credential refusal).
  Their message texts become catalog entries or use the same
  what/why/fix layout.

### 5. Tests

- **Every catalog entry** has a test that injects its SW for its
  operation through the virtual PIV backend, and asserts the rendered
  `what` line and the details line.
- **Fallback**: an unmapped `(op, SW)` renders the report invitation and
  the details line.
- **Coverage**: every `CardOp` variant is used by at least one
  `transmit_check` call site; a compile-time match ensures no variant
  is left undescribed.
- **Snapshot tests** on the full rendered text of the four examples in
  this spec.

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
