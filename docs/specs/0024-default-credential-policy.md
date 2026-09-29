<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0024 — Default-Credential Policy

**Status:** draft
**App:** yb
**Implemented in:** <!-- YYYY-MM-DD, fill after implementation -->

## Problem

yb checks for factory-default credentials (PIN `123456`, PUK
`12345678`, management key `010203…`) when it creates its `Context`
(`rust/yb-core/src/context.rs`, `check_for_default_credentials`).  If
any are found, **every command refuses to run**, unless `--allow-defaults`
(which turns the refusal into a warning) or `YB_SKIP_DEFAULT_CHECK=1`
is given:

```
Error: YubiKey has default credentials: management key. This is insecure. Use --allow-defaults to override.
```

This is too blunt:

- **Read-only commands are blocked.**  `yb ls` and `yb fsck` reveal
  nothing that ykman could not read from the same YubiKey, yet they
  refuse.  `fsck` cannot even report the problem it is refusing over.
- **`fetch` is blocked.**  The owner cannot get their data out, for
  example to move it to a properly set-up key.  Refusing protects
  nothing: an attacker holding the key would simply use another tool.
- **Credentials are not told apart.**  A default management key allows
  tampering but reveals no secrets.  A default PIN or PUK reveals every
  secret.  Both get the same treatment.
- **First-time setup is a catch-22.**  `yb format --protect` needs the
  factory management key, which the check refuses.  Users must learn
  about `--allow-defaults` to get past it (see spec 0023).

## Goals

- yb **refuses only when it is about to put a secret behind a credential
  that does not protect it**.  Everywhere else it warns, or says
  nothing.
- A default PUK counts the same as a default PIN.
- Read-only commands never refuse because of default credentials.
- Existing overrides keep working: `--allow-defaults` and
  `YB_SKIP_DEFAULT_CHECK`.
- The policy only ever relaxes today's behavior: every invocation that
  works today still works.

## Non-goals

- Changing the PIN or PUK outside the guided format (spec 0023).
  `yb pin` is an open question.
- Detecting weak but non-default credentials.
- Firmware < 5.3, which has no GET METADATA: defaults cannot be
  detected, and yb stays silent as today.

## Specification

### 1. Threat model per credential

What an attacker who holds the YubiKey can do when a credential is
still at its factory value:

| Default credential | Attacker capability | Class |
|---|---|---|
| PIN | decrypt every blob | **disclosure** |
| PUK | set a new PIN with RESET RETRY COUNTER, then decrypt every blob | **disclosure** |
| Management key | overwrite or erase store objects; replace the store key and certificate, which also defeats the spec 0017 signatures | **tampering** |

### 2. Policy per command

| Command | Default PIN or PUK | Default management key |
|---|---|---|
| `list-readers`, `ls` | silent | silent |
| `fsck` | reported in the YubiKey section (spec 0023 §2) | reported |
| `fetch` | **warn** | silent |
| `store` | **refuse** | **warn** |
| `rm` | warn | warn |
| `format` (flag-driven), with `--protect` | **refuse**: `--protect` stores the new management key behind the PIN | allowed: `--protect` replaces it |
| `format` (flag-driven), without `--protect` | warn | warn |
| `format` (guided) | handled in the flow (spec 0023 §4) | handled in the flow |
| `self-test` | unchanged (today's behavior) | unchanged |

**Refuse** means: exit 1 before any card write.  The message names the
credential and the fix:

```
Error: this YubiKey still has the factory-default PIN.  Anything stored on
it could be read by whoever holds the key.
  Fix: change the PIN and PUK — run `yb format` in a terminal for guided
       setup (erases the store), or `ykman piv access change-pin` and
       `ykman piv access change-puk` (keeps the store).
  Override (testing only): --allow-defaults
```

**Warn** means: one line on stderr, printed once per invocation.
`--quiet` suppresses it.  It names the credential and points to `yb
fsck` for details, for example:

```
Warning: this YubiKey uses the factory-default PIN; run `yb fsck` for details.
```

**Silent** means no output at all.

### 3. Overrides

- `--allow-defaults` turns every refusal into the corresponding warning,
  exactly as today.
- `YB_SKIP_DEFAULT_CHECK=1` skips detection entirely: no refusals, no
  warnings, and `fsck` reports defaults as `not checked`.  That matches
  what it does today.

### 4. Implementation

- `Context` construction still **detects** defaults, but no longer
  **enforces** anything.  `check_for_default_credentials` returns a
  `DefaultCredentials` struct that now has a `puk` field, which today
  is detected but dropped, and never bails.
- A new function, `Context::enforce_default_policy(op: SecretOp)`, is
  called by each command at the point it is about to act.
  - `SecretOp` values: `Fetch`, `Store`, `Remove`, `Format { protect:
    bool }`.
  - It applies the §2 table and returns `Err` for a refusal.
  - Read-only commands do not call it.
- Detection costs three GET METADATA APDUs, as today.

### 5. Backward compatibility

- Every invocation that succeeds today still succeeds.  The only
  changes are refusals that become warnings or disappear.
- `store` on a card whose only default is the management key used to
  refuse and now warns.  This is intentional: nothing secret is exposed.
- Output: stderr wording changes; stdout is unchanged.
- No card data changes.  Spec 0021 §6 applies.

### 6. Tests

For each row of the §2 table, run the virtual PIV backend with a
default PIN, a default PUK, and a default management key, each on its
own.  Assert:

- exit status;
- whether a warning is printed;
- that a refusal leaves zero write APDUs;
- `--allow-defaults` → warning only;
- `YB_SKIP_DEFAULT_CHECK` → nothing;
- `--quiet` → no warning, but a refusal is still printed.

## Open questions

- Should yb get a `yb pin` command (change PIN/PUK, keeping the store),
  so the refusal message doesn't have to send users to ykman?  It would
  reuse the spec 0023 PIN-change code.

## References

- [spec 0017](0017-blob-integrity-signature.md) — integrity signatures (defeated by a default management key)
- [spec 0023](0023-guided-format.md) — guided format, `fsck` YubiKey section
- `rust/yb-core/src/auxiliaries.rs` — `check_for_default_credentials`
