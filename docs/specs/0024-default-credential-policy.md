<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0024 — Default-Credential Policy

**Status:** implemented
**App:** yb
**Implemented in:** 2026-09-29

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
| `ls` | silent | silent |
| `list-readers`, `select` | not applicable: they bypass `Context` and never detect defaults | — |
| `fsck` | **warn** (spec 0023 §2 later reports it in its YubiKey section) | warn |
| `fetch` | **warn** | silent |
| `store` | **refuse** | **warn** |
| `rm` | warn | warn |
| `format` (flag-driven), with `--protect` | **refuse**: `--protect` stores the new management key behind the PIN | allowed: `--protect` replaces it |
| `format` (flag-driven), without `--protect` | warn | warn |
| `format` (guided, spec 0023) | handled in the flow (spec 0023 §4) | handled in the flow |
| `self-test` | **refuse** unless `--allow-defaults`: today's behavior, unchanged | same |

`format` applies the policy in spec 0022 Phase A step 2, next to the
protection-mode check.  A refusal therefore reports "nothing was changed on
the YubiKey", and nothing is written.

**Refuse** means: exit 1 before any card write.  The message names the
credential and the fix:

```
Error: this YubiKey still has the factory-default PIN.  Anything stored on
it could be read by whoever holds the key.
  Fix: change the PIN and PUK with `ykman piv access change-pin` and
       `ykman piv access change-puk` (the store is kept).
  Override (testing only): --allow-defaults
```

**Warn** means: one line on stderr, printed once per invocation.
`--quiet` suppresses it.  It names the credential(s), for example:

```
Warning: this YubiKey uses the factory-default PIN.
```

**Silent** means no output at all.

**Interim wording.**  Spec 0023 comes after this spec.  Until it lands,
the messages above do not mention the guided `yb format` or the `yb fsck`
YubiKey section, which do not exist yet.  Spec 0023 adds those pointers:
"run `yb format` in a terminal for guided setup" in the refusal, and "run
`yb fsck` for details" in warnings.

### 2a. Factory credentials are filled in, not prompted for

- When detection reports the factory PIN, yb uses `123456` without
  prompting, whether or not `--allow-defaults` is given.  Knowing that the
  PIN is the factory PIN means knowing the PIN; a prompt would only add
  friction.  A refusal still applies.  An explicit PIN (`YB_PIN`,
  `--pin-stdin`) always wins.
- The factory **management key** is no longer injected by
  `--allow-defaults`.  Since spec 0022, `Context::management_key_for_write`
  tries the factory key as its last candidate, so the injection is
  redundant.

### 3. Overrides

- `--allow-defaults` turns every refusal into the corresponding warning,
  exactly as today.
- `YB_SKIP_DEFAULT_CHECK=1` skips detection entirely, in both `Context`
  constructors: no refusals and no warnings.  That matches what it does
  today.  (Spec 0023's `fsck` YubiKey section will show defaults as
  `not checked` in that case.)

### 4. Implementation

- Both `Context` constructors (`Context::new` and
  `Context::with_backend`) **detect** defaults in the same way, and
  neither **enforces** anything.  `check_for_default_credentials` returns
  a `DefaultCredentials` struct that now has a `puk` field (today the PUK
  is detected but dropped), and never bails.  `with_backend` used to skip
  detection; running it there too gives one code path that tests
  exercise.
- `allow_defaults` becomes a public `Context` field, like
  `management_key`, so that tests can set it on a `with_backend`
  context.
- A new function, `Context::enforce_default_policy(op: SecretOp)`, is
  called by each command at the point it is about to act.
  - `SecretOp` values: `Fetch`, `Store`, `Remove`, `Fsck`,
    `Format { protect: bool }`, `SelfTest`.
  - It applies the §2 table.  A refusal returns `Err`.  Otherwise it
    returns the warnings that apply (`Vec<String>`), and prints them
    unless `--quiet`.  Returning them lets the in-process tests check
    warnings without capturing stderr.
  - `ls` does not call it.
- Detection costs three GET METADATA APDUs, as today.

### 4a. Virtual backend

- `VirtualPiv` reports the "is default" flag (GET METADATA tag `0x05`)
  **truthfully**, by comparing its current PIN, PUK and management key
  with the factory values.  Today it never reports the flag.
- The test fixtures that represent a set-up card (`with_key.yaml`,
  `aes192.yaml`) get a non-default PIN and PUK; the CLI tests' `PIN`
  constant follows.  Their management key stays at the factory value
  where tests rely on it, which under §2 only causes a warning.
  `default.yaml` keeps every factory credential and serves the policy
  tests.  `VirtualPiv::new()` keeps factory credentials (it is used by
  low-level backend tests that do not go through the policy).
- `VirtualPiv` gains a **write counter**: the number of card-changing
  operations (object writes, `SET MANAGEMENT KEY`, key generation), so
  that tests can assert "zero writes".
- Tests that run against the real binary set `YB_SKIP_DEFAULT_CHECK=1`
  (the Nix VM tier-2 tests), so they are unaffected.

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

- success or refusal;
- the warnings returned by `enforce_default_policy`;
- that a refusal leaves the write counter unchanged;
- `--allow-defaults` → warnings instead of a refusal;
- `YB_SKIP_DEFAULT_CHECK` → no warnings, no refusal;
- `--quiet` → warnings still returned but not printed; a refusal is
  still an error.

Also:

- **Factory PIN filled in** (§2a): with the factory PIN, `fetch` succeeds
  without any PIN source, with and without `--allow-defaults`; an
  explicit wrong PIN is used as given (and fails).
- **No management key injection** (§2a): with the factory management key
  and no `YB_MANAGEMENT_KEY`, `store` and `rm` work, through the spec 0022
  resolver.
- **`self-test`**: refused on any default without `--allow-defaults`.
- **`format` refusal writes nothing**: `format --protect` with a default
  PIN fails with "nothing was changed on the YubiKey" and zero writes.
- **Truthful reporting**: after the virtual card's PIN, PUK or management
  key is changed, the corresponding "is default" flag clears.

## Open questions

None blocking.  Deferred to a later spec:

- Should yb get a `yb pin` command (change PIN/PUK, keeping the store),
  so the refusal message doesn't have to send users to ykman?  It would
  reuse the spec 0023 PIN-change code.

## References

- [spec 0017](0017-blob-integrity-signature.md) — integrity signatures (defeated by a default management key)
- [spec 0023](0023-guided-format.md) — guided format, `fsck` YubiKey section
- `rust/yb-core/src/auxiliaries.rs` — `check_for_default_credentials`
