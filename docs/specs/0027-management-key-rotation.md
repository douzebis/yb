<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0027 — Management Key Rotation

**Status:** implemented
**App:** yb
**Implemented in:** 2026-09-29

## Problem

Since spec 0023 §3a, `--protect` means "make sure the management key is
PIN-protected".  On a YubiKey that is already protected it keeps the
key.  That leaves no way, in yb, to **replace** a protected management
key on purpose, for example:

- the key may have been exposed (read out with `yubico-piv-tool`, as
  documented in spec 0023's summary, or copied during an incident);
- an organization's policy requires periodic rotation;
- the key was set by another tool, and the owner wants a fresh random
  one.

A second gap: the only way to *protect* a key in yb is `yb format
--protect`, which **erases the store**.  A user with blobs on an
unprotected YubiKey cannot move to PIN-protected mode without losing
them, or without ykman.

Today the workaround is ykman (`ykman piv access change-management-key
--generate --protect`), which changes the key *before* storing it, with
no rollback (spec 0022, Assumptions / Context).

## Goals

- A yb command that sets a **new random management key**, stored behind
  the PIN, **without touching the store**.  On an already-protected
  YubiKey it rotates the key; on an unprotected one it protects it.
- The switch is the spec 0022 B1 sequence: the same recovery, the same
  guarantees, the same assumptions (with the fixes of §3a and §3b).
- The new key keeps the card's algorithm (spec 0021 §3).
- No key material is ever shown (spec 0025).

## Non-goals

- Changing the management key algorithm, e.g. 3DES to AES-192 (spec 0021
  non-goal).  A later `--algorithm` option could build on this command.
- Setting a user-chosen management key.  yb only sets random keys.
- Turning PIN protection **off** (returning to an unprotected key).
- Rotating the store's ECDH key in slot 0x82.  That changes what blobs
  are encrypted to, and is `yb format --generate`.

## Specification

### 1. Command

```
yb rotate-management-key
```

It is a separate subcommand, not a `format` flag, because it must not
erase the store.  Global options apply as usual (`--serial`, `--reader`,
`--quiet`, `--allow-defaults`, `YB_PIN`, `YB_MANAGEMENT_KEY`).

### 2. Preflight (no card writes)

The same checks as spec 0022 Phase A steps 2–4:

1. Card state: refuse PIN-derived or unparseable ADMIN DATA (spec 0021
   §4).
2. Default-credential policy (spec 0024): a new operation
   `SecretOp::RotateManagementKey`, with the same rule as `format
   --protect`.  It **refuses** on a factory PIN or PUK, because it
   stores a key behind the PIN.  A factory management key is allowed,
   since it gets replaced.  `--allow-defaults` turns the refusal into a
   warning.
3. PIN: obtain and verify it.
4. Current management key: the spec 0022 resolver (`YB_MANAGEMENT_KEY`,
   PRINTED `89`, `8A`, factory key), accepted by the card.

Any failure reports "nothing was changed on the YubiKey".

### 3. The switch

- Generate a random key of the card's algorithm (spec 0021 §3).
- Run spec 0022 B1a–B1d, with the resolved key as the old key.  This
  includes the B1b recovery, the self-healing resolution, the ADMIN DATA
  write (standard flag) and the PRINTED cleanup, with two changes (§3a,
  §3b).
- The resolver's pending repairs (legacy flag, leftover `8A`) are covered
  by B1c/B1d, as in `format --protect`.

The store is not read or written.  Blobs are unaffected: the management
key only authorizes writes, and blobs are encrypted to and signed with
the slot 0x82 key.

### 3a. Whether the old key is in PRINTED

When B1a or B1b fails and the key is unchanged, B1 puts PRINTED back:
`88 { 89 <old> }` if PRINTED held the old key, no object otherwise.
"Held" is decided by what PRINTED contains, not by where yb got the key:
tag `89` **or** tag `8A` holds the old key.

- Tag `8A` counts: after an earlier interrupted switch that did not take
  effect, `8A` may be the only copy of the card's key.  Deleting PRINTED
  then would leave a management key that exists nowhere.
- The key's source is not enough: when the key comes from
  `YB_MANAGEMENT_KEY` on a card that also stores it, a rejected switch
  would delete PRINTED, and the card would no longer keep its key.
  `yb format --protect` cannot reach that case since spec 0023 (it keeps
  a stored key); rotation can.

This is not the spec 0023 §3a "already protected" test, which asks
whether the key is stored in `89` and accepted, to decide whether to
switch at all.

### 3b. Messages after a failed switch

Spec 0022 B1 tells the user to run `yb format --protect` after some
failures.  That command erases the store and, since spec 0023, does not
replace a stored key.  In the spirit of the store (spec 0022 `write_dirty`),
yb says nothing about state that the next write repairs by itself:

- **The command failed** (B1a, B1b, B1c): the failure is reported, with
  what happened, but no instruction to run another command when the next
  yb write repairs the state anyway (leftover tag `8A`, ADMIN DATA flag
  not yet written, PRINTED not restored).  An interrupted switch still
  says to reconnect the YubiKey.
- **The command succeeded** (B1d, dropping tag `8A`, failed): no warning.
  The next write drops it.

This applies to `yb format --protect` and the guided format as well,
which share B1.

### 4. Output

- Unless `--quiet`, one line:
  - `Management key rotated (3DES).` on a card that was protected;
  - `Management key replaced, and now kept on the YubiKey, unlocked by
    your PIN (AES-192).` on a card that was not.
- It never prints the key.  The spec 0023 summary hint on reading it back
  (`yubico-piv-tool … read-object 0x5fc109`) is repeated.
- Failures are rendered through spec 0025, with the spec 0022 B1
  messages as context.

### 5. Tests

On the virtual backend:

- **Protected card:** the key changes; PRINTED holds only the new key
  (`89`, no `8A`); ADMIN DATA has the standard flag; existing blobs still
  decrypt; `store` works with the PIN only.
- **Unprotected card** (factory key, or a key from `YB_MANAGEMENT_KEY`):
  ends up protected, the store is untouched.
- **Legacy card** (flag `0x01`): rotated, and the flag repaired.
- **Policy:** a factory PIN or PUK refuses with zero writes;
  `--allow-defaults` warns instead.
- **Faults:** each spec 0022 fault point (B1a–B1d, SET MANAGEMENT KEY
  rejected / lost reply / card lost) keeps invariants I2 and I4 of spec
  0022 §5; I1 holds trivially (store untouched).
- **§3a:** a rejected switch leaves PRINTED holding the card's key, on a
  card that stores it with `YB_MANAGEMENT_KEY` also set, and on a card
  whose only copy is in tag `8A`.
- **§3b:** no failure message mentions `yb format --protect`; a failed
  B1d prints nothing, and the next write drops tag `8A`.
- **§8:** the hint appears in `yb fsck`, not in the guided format.

### 6. Hardware validation

On each test YubiKey (firmware < 5.7 and ≥ 5.7):

1. `yb rotate-management-key` on a protected card.  PRINTED changes;
   `ykman piv info` still reports "protected by PIN"; `yb fetch` of an
   existing blob works; `yb store` works.
2. On a card made unprotected with ykman, the command protects it and
   keeps the store.
3. Old yb (spec 0021 worktree) still reads the card.

### 7. Backward compatibility

- New subcommand only.  Card content is the same as after `yb format
  --protect` (spec 0021 metadata, spec 0022 PRINTED layout).
- Messages after a failed key switch change (§3b); they are not meant for
  parsing.
- Spec 0021 §6 applies.

### 7a. Documentation

The README and the man pages name `yb rotate-management-key` where they
now tell users of an already formatted YubiKey to run `ykman piv access
change-management-key --generate --protect`.  `yb-rotate-management-key(1)`
is added.

The error catalog entry for PRINTED not found (`6A82`, spec 0025) points
to `yb rotate-management-key` instead of `yb format --protect`, which
erases the store.

### 8. `yb fsck` hint

Storing the management key behind the PIN is a **convenience, not a
security measure**: the key no longer has to be kept and supplied by the
user, since yb reads it from the YubiKey once the PIN is given.  Without
it, every `yb store` and `yb remove` needs `YB_MANAGEMENT_KEY`.

When the management key is neither stored on the YubiKey nor the factory
default (the factory key is covered by spec 0024), the spec 0023 YubiKey
section adds a hint under the management key line, in plain words:

```
  Management key   3DES, not stored on the YubiKey
                   yb store and yb remove need it each time (YB_MANAGEMENT_KEY).
                   To have yb keep it on the YubiKey, unlocked by your PIN:
                   yb rotate-management-key
```

- The hint does not say "protect" or "PIN-protected mode": that is
  jargon.
- The hint is shown by `yb fsck` only.  The guided format prints the same
  section without it, since it stores the key anyway.  The report gains
  optional hint lines under an item for this.
- It is not a warning: keeping the key elsewhere (e.g. in a password
  manager) is a valid choice.  The line's severity stays **ok**, and the
  exit status is unchanged.

## Open questions

None.  Resolved:

- **Name:** `yb rotate-management-key`, in the spirit of `ykman piv
  access change-management-key`.
- **fsck:** a plain-language hint, not a warning, in `yb fsck` only (§8).
- **Failure messages:** silent about state the next write repairs (§3b).

## References

- [spec 0021](0021-firmware-5.7-management-key.md) — management key algorithm, metadata
- [spec 0022](0022-format-sequence.md) — the B1 key switch, its recovery and assumptions
- [spec 0023](0023-guided-format.md) — `--protect` alignment (§3a)
- [spec 0024](0024-default-credential-policy.md) — default-credential policy
- [spec 0025](0025-actionable-errors.md) — error rendering, no key material
