<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0022 — Safe Ordering of `yb format`

**Status:** implemented
**App:** yb
**Implemented in:** 2026-09-29

## Problem

`yb format` (`rust/yb/src/cli/format.rs`) currently runs:

1. `--generate`: new key pair in the store slot, then a new self-signed
   certificate.  **Committed to the card immediately.**
2. `--protect`: `SET MANAGEMENT KEY`, then writes PRINTED, then writes
   ADMIN DATA.
3. `Store::format`: wipes and rewrites the store objects.

Nothing is checked up front.  A failure in any step leaves whatever the
earlier steps did in place.

### Observed incident

On a YubiKey with firmware 5.4.3, `yb ls` showed:

```
bar  CORRUPTED
```

We examined the card:

- **The blob was structurally valid.**  It had a correct header, a v2
  AES-GCM payload, and a 65-byte `0x01` signature trailer.  It was
  written 2026-04-15, at store age 2.
- **The signature failed against slot 0x82's certificate**, with yb and
  with openssl alike.
- **`yb fetch bar` failed**: `AES-GCM authentication failed`.  The
  private key in slot 0x82 was no longer the one `bar` was encrypted to.
- **The certificate was made by yb**: yb's default subject `CN=YBLOB
  ECCP256` and yb's fixed validity dates (2000–9999).  It matched the
  current private key.
- **The store had not been re-formatted since `bar` was written.**

The mechanism was later confirmed on hardware (spec 0021 §3).  The card
was already PIN-protected, and `yb format --generate --protect` ran in
this order:
1. `--generate` replaced the key and certificate;
2. `--protect` then assumed the factory management key and failed with
   `SW=6982`;
3. so the store was never rewritten.

The blob was permanently lost, and the store still looked intact.  Spec
0021 fixed that particular trigger.  This spec removes the whole class:
no failure at any step may leave blobs behind a replaced key.

### Other ways it can go wrong

- **`--protect` changes the management key before saving it.**  It
  calls `SET MANAGEMENT KEY` first and writes the new random key to
  PRINTED afterwards.  If that write fails, the card's management key
  exists nowhere: it is unknown and unrecoverable.  Only a full PIV
  reset gets the card back.
- **`generate_certificate` commits the key before the certificate.**  If
  writing the certificate fails, slot 0x82 holds a new key alongside the
  old certificate.  `yb store` encrypts to the public key in the
  certificate (`Context::get_public_key`), so from then on **every newly
  stored blob is undecryptable**, and nothing reports it.
- **Without `--generate`, format only checks that a certificate
  exists.**  It never checks that the certificate matches the key in the
  slot.

## Goals

- If `yb format` fails at any point, the card is left in one of these
  states:
  1. **unchanged**, or
  2. **consistent**: every blob in the store can be decrypted with the
     key in the store slot (an empty store counts), and the
     certificate's public key matches that key, or
  3. **a documented intermediate state** that yb names explicitly and
     can repair by running `yb format` again.

  No failure leaves blobs that look intact but cannot be decrypted.
- The management key is never at risk of being lost.
- Everything that can fail without changing the card (PIN, management
  key, slot contents, ADMIN DATA state) is checked **before** the first
  write.
- `yb format` never exits 0 while the store slot's key and certificate
  do not match.
- `yb store` refuses to write when the store slot's key does not match
  its certificate, so a card damaged by another tool cannot silently
  receive undecryptable or unverifiable blobs.
- On failure, the message says what was done, what was not, and what to
  run next.

## Non-goals

- True atomicity.  PIV has no transactions.
- Asking for confirmation, or any interactive behavior (spec 0023).
- Generating the key in a spare slot and moving it (firmware 5.7 MOVE
  KEY).  That could make `--generate` atomic, but it is left for later.
- Changing `yb self-test`, which keeps calling `format --generate`.

## Specification

### 1. Phase A — preflight (no card writes)

In order; any failure aborts with `nothing was changed on the YubiKey`:

1. **Arguments**: validate them, as today.
2. **Card state**:
   - management key algorithm (spec 0021 §1);
   - ADMIN DATA interpretation (spec 0021 §4);
   - default-credential status: today's check in `Context`, until spec
     0024 replaces it.

   Reject PIN-derived mode, unparseable ADMIN DATA and unknown
   algorithms here.
3. **PIN**: obtain it and VERIFY it.  A wrong PIN is caught here, not
   after a key has been replaced.
4. **Management key**: resolve it and authenticate, without writing
   anything.  `PivBackend` gains an authenticate-only operation for this.
   This proves write access with the key that the Phase B steps will use.
   Resolution order.  The first candidate the card accepts wins:
   1. `YB_MANAGEMENT_KEY`.  If the card rejects it, yb stops and does
      not fall through: an explicit key that is wrong is an error;
   2. the keys in PRINTED, when a PIN is available: tag `89` first, then
      tag `8A` (the previous key kept during a key switch, see B1a).
      PRINTED is tried whatever the flags say.  With flags "unprotected",
      a key there is the state an interrupted `--protect` leaves behind
      (B1c below);
   3. the factory default.

   If no candidate is accepted, yb fails: "the management key is not in
   PRINTED and is not the factory default; set YB_MANAGEMENT_KEY".

   A key from PRINTED can leave the card needing a **repair**, which
   Phase B carries out:
   - **flags**: the key came from PRINTED but the flags do not say
     "standard".  Either the legacy `0x01` flag of spec 0021, or no flag
     after an interrupted `--protect`.  The fix is to rewrite ADMIN DATA;
   - **PRINTED**: tag `8A` is present, or the key that won came from
     `8A`.  The fix is to rewrite PRINTED as `88 { 89 <winning key> }`.

   Repairs are done by B1c/B1d when `--protect` is given, otherwise
   after B2.  Unless `--quiet`, yb prints a one-line note.

   This resolution lives in `Context::management_key_for_write`, the
   **single place in yb that reads PRINTED for a key** (it generalizes
   the spec 0021 legacy migration).  It applies to every write command
   (`store`, `rm`, `format`), with the repairs done after the command's
   own writes.  The backends lose their own "PIN only → read PRINTED"
   fallback: `write_object` and the operations built on it take an
   explicit management key.
5. **Store slot** (only when `--generate` is **not** given):
   - read the certificate and check it holds an EC P-256 public key;
   - **check that the key matches it**: sign a random 32-byte digest in
     the slot (PIN already verified) and check the signature against
     the certificate's public key.

   On mismatch, fail with a message recommending `--generate`.
6. **Existing store** (read-only):
   - if a store is present, list its blobs on stderr as `will be
     destroyed: <name>…`.  This is printed **even with `--quiet`**: it is
     the last notice before data is erased;
   - if the store cannot be parsed, say so and continue.

Steps 3 and 4 may share one PC/SC session.  The whole phase must not
write any object.

### 2. Phase B — changes, in this order

> **Amended by spec 0023 §3a:** `--protect` on an already PIN-protected
> YubiKey keeps the key (only resolver repairs are made); B1 runs only
> when the key is not yet protected.  Replacing a protected key on
> purpose is spec 0027, which reuses B1 unchanged.

**B1 — `--protect`.**  Rearranged so that the new key is always saved
somewhere before it becomes the card's only key, and the old key stays
saved until the switch is confirmed.  yb keeps both keys in memory for
the whole of B1.

- **B1a** Write PRINTED as `88 { 89 <new>, 8A <old> }`, authenticating
  with the **old** key.  Tag `8A` keeps the old key on the card while
  the switch is in progress.
- **B1b** `SET MANAGEMENT KEY` to the new key, authenticating with the
  old key.
- **B1c** Write ADMIN DATA (spec 0021 §4), authenticating with the
  **new** key.
- **B1d** Rewrite PRINTED as `88 { 89 <new> }`, dropping the old key.
  A failure here is only a warning.  The leftover `8A` is harmless, and
  the next write command removes it (Phase A step 4, PRINTED repair).

**If B1b reports a failure**, yb finds out which key the card now
holds, and never guesses:

1. If the card accepts the **old** key, the change was rejected.  yb
   restores PRINTED as it was: `88 { 89 <old> }` if the old key came
   from PRINTED, otherwise it removes the object (an empty write).
   Format then fails with "nothing was changed".
2. Otherwise, if the card accepts the **new** key, the change was
   applied and only the reply was lost.  yb continues with B1c.
3. If the card accepts neither (in practice the YubiKey was removed
   during the switch), format stops.  The error says that the switch was
   interrupted, and that once the key is reconnected any write command
   or `yb format --protect` will recover: PRINTED holds both keys (tags
   `89` and `8A`), and Phase A step 4 tries both.  No key material is
   shown (spec 0025).

What each failure leaves behind:

| Fails at | Card state | Recovery |
|---|---|---|
| B1a | unchanged, or PRINTED holds both keys while the card still uses the old one | yb restores PRINTED (as in B1b case 1); re-run |
| B1b | handled as described above | per the case above |
| B1c | key changed and saved in PRINTED (with the old key under `8A`); flags not updated | re-run any write command or `yb format --protect`: Phase A step 4 finds the key and repairs flags and PRINTED |
| B1d | key switched and flags updated; the old key lingers under `8A` | nothing to do: the next write command removes it |
| B2 | store partly erased (it is written one object at a time); store key untouched | intact blobs still decrypt; blobs with erased chunks show as CORRUPTED; re-run `yb format` |

No failure prints key material.  The self-healing resolution in Phase A
step 4 replaces the need to show the key.

**B2 — wipe the store**: `Store::format` with the management key that is
current after B1.  When B1 ran, that is the new key yb holds in memory,
passed explicitly.  This avoids a PIN verification and a PRINTED read
for every object written.

Doing this before B3 means a `--generate` failure can never orphan
blobs, because there are no blobs left to orphan.

**B3 — `--generate`**:

- **B3a** Generate the key.
- **B3b** Create and write the certificate.
- **B3c** Re-read the certificate and verify the key/certificate match,
  as in Phase A step 5.

If B3b or B3c fails, format exits non-zero with this message, where
`<slot>` is the store slot actually used (`-k`):

```
the store is empty and the key in slot <slot> was replaced, but its
certificate could not be written/does not match.  Do not store data.
Run `yb format --generate` again.
```

**B4 — success**: print the existing `Store formatted: …` line.

### 3. Why this order

- **B1 first**: it doesn't touch the store or the store key, so a
  failure there costs nothing.
- **B2 before B3**: blobs are removed before their key can be replaced.
- **B3 last**: its failure modes only affect an empty store.
- **The only outcome that can lose data without notice** (blobs present,
  key replaced) is now impossible.

### 4. Progress and errors

- Unless `--quiet`, print a line when each Phase B step starts
  (`Setting up PIN-protected management key…`, `Erasing store…`,
  `Generating key in slot <slot>…`).
- A Phase B failure prints:
  - the failing step and the underlying error;
  - the steps already completed;
  - the resulting card state, taken from the tables above;
  - the command to run next.

### 5. Backend changes

- The key/certificate match check signs a digest in the slot with the
  existing `ecdsa_sign`.
- `PivBackend` gains an **authenticate-only** operation: authenticate
  the management key and write nothing.  Phase A step 4 and the B1b
  recovery use it.
- `write_object`, `Store::sync`, `Store::format` and the other
  operations built on them take a required management key.  Their PIN
  parameter existed only for the removed "read PRINTED" fallback, and
  is dropped.
- PRINTED is parsed and encoded by one pair of functions, used by both
  the resolution (Phase A step 4) and B1.
- `enable_pin_protected_management_key` is rewritten to follow B1a–B1d,
  including the B1b recovery.
- The virtual PIV backend gains **fault injection** at these points:
  - the Nth object write fails;
  - `SET MANAGEMENT KEY` is rejected;
  - `SET MANAGEMENT KEY` is applied but reported as failed (the lost
    reply of B1b case 2);
  - the card is lost during `SET MANAGEMENT KEY`, with or without the
    change applied: every later authentication fails until the fault is
    cleared, which simulates reconnecting (B1b case 3);
  - `generate_certificate` fails after the new key is generated and
    before the certificate is written.  The virtual backend's
    `generate_certificate` is split internally to allow this.

  Tests use it to fail each Phase B step in turn, on an unprotected and
  on an already-protected card, and assert:
  - **I1**: after any failure, the store is empty, or its blobs decrypt
    with the key in the store slot.
  - **I2**: the card's management key is available from PRINTED or from
    the caller's key.
  - **I3**: exit code 0 implies the key and certificate match.
  - **I4**: no output contains key material.  The tests check the full
    text (`{:#}`) of every returned error.  Progress lines and notes are
    fixed strings with no key interpolated, so they satisfy I4 by
    construction.  No stderr-capturing harness is added.

### 6. Key/certificate check in `yb store`

- Before writing, `yb store` runs the Phase A step 5 match check on the
  store slot.  This applies to **every** store, encrypted or not:
  plaintext blobs also carry a signature trailer that is verified
  against the certificate (spec 0017), so a mismatch would show them as
  CORRUPTED.  `store` already verifies the PIN, so this costs one extra
  sign operation per invocation, not per blob.
- The check runs only when the store slot **has a certificate**.  Without
  one, behavior is unchanged: an encrypted store fails as today (no
  public key to encrypt to), and a plaintext store proceeds unsigned as
  today.
- On mismatch, it refuses before writing anything:

  ```
  the key in slot <slot> does not match its certificate; new blobs would
  be undecryptable.  Nothing was stored.  Run `yb format --generate`
  (this erases the store).
  ```
- Blobs already on the card are not touched.  Any that were encrypted
  while the mismatch existed are already unrecoverable.

### 7. Backward compatibility

- CLI flags, their meanings and the success output are unchanged.
- Nothing new is stored on the card.  `--protect` produces the same
  PRINTED and ADMIN DATA content as specified in spec 0021, in a
  different order.
- Formats that used to succeed still succeed.  The exception is a store
  slot whose key does not match its certificate; format now rejects it
  in Phase A, where before it produced an unusable store.
- `yb store` now fails on such a card, where before it silently wrote
  undecryptable blobs.
- PRINTED may briefly hold an extra tag `8A`, only after an interrupted
  key switch.  ykman and older yb read only tag `89`, so they are
  unaffected, except in one state: the switch was interrupted *before*
  it took effect.  Then `89` holds a key the card does not use, and
  ykman and older yb fail to authenticate until the next yb write
  repairs PRINTED.
- Spec 0021 §6 applies.

## Assumptions

No host-side ordering can protect against a card that corrupts its own
state.  For example, power lost halfway through `SET MANAGEMENT KEY` could
leave the card's key unusable whatever yb does.  The guarantees of this
spec therefore rest on the following, stated explicitly.

### Assumed (not verified)

- **A1 — Each card command is all-or-nothing, including on power loss.**
  After an interruption, the card is in the state from before the command
  or the state after it, never a mix.  This covers `SET MANAGEMENT KEY` and
  `PUT DATA` alike.  Yubico does not document it.  YubiKey 5 runs native
  firmware, not Java Card, so the Java Card transaction guarantee does not
  apply.  It is the usual expectation for a secure element, and it is
  consistent with M1 below.  **If A1 does not hold, the outcome is outside
  what yb can guarantee; recovery may require a PIV reset.**
- **A2 — An interrupted write affects only the object being written.**

### Measured (firmware 5.4.3; M3 on 5.4.3 and 5.7.1)

Measured on 2026-09-29 with scratch objects (retired-slot certificate
objects `5FC10E`–`5FC120`), never with PRINTED itself.

- **M1 — An interrupted command may still have been applied.**  3000-byte
  `PUT DATA` writes (~80 ms, command chaining) were cut off by
  de-authorizing the USB device from the host during the write, 20 times.
  In all 20 trials the object held the complete new content: no torn or
  cleared object.  In 8 of them the host saw the command fail
  (`Transaction failed`) although the card had committed it.  yb handles
  this by never trusting an error from `SET MANAGEMENT KEY`: it checks
  which key the card accepts (§2, B1b).  Limitation: the de-authorization
  took about 60 ms to take effect, so the cuts landed late in the write,
  and the card stayed powered.  Power loss was not tested; a manual
  unplug test is impractical in the VM setup used.
- **M2 — A `PUT DATA` rejected for lack of space deletes the object.**
  With the PIV storage full, growing an object from 100 to 3000 bytes
  failed with `SW=6A84` (no space), and **the object was gone**: the firmware
  frees the old content before allocating the new.  Rewriting an object at
  the same or a smaller size succeeded on the full card, including
  rewriting the original content right after the failed grow.  B1a grows
  PRINTED (28 → 54 bytes), so on a nearly full card it can hit M2.  B1a's
  failure path then rewrites PRINTED from the old key held in memory, a
  same-size rewrite that M2 shows fits.
- **M3 — The PIN-protected objects.**  Reading PRINTED (`5FC109`), as well
  as fingerprints (`5FC103`), facial image (`5FC108`) and iris (`5FC121`),
  fails without the PIN (`SW=6982`).  Ordinary objects (e.g. `5FC120`) are
  readable by anyone.  An auxiliary copy of the key in one of those objects
  was considered and rejected: they may hold legitimate data, and under A1
  the design above needs no second copy.

### What the design guarantees under A1–A2 and M1–M2

At every step the card's management key is readable from PRINTED
(possibly under tag `8A`), is the caller's key, or is the factory key.
The one exception is below.  Once the YubiKey is reconnected, any write
command recovers (§1 step 4).

**Residual case, not covered:** yb is killed or crashes between an M2
failure in B1a and its immediate restore.  The old key then existed only
in yb's memory.  This needs two unlikely events back to back, and is
accepted.

### Context

Yubico's own tools (ykman `pivman_set_mgm_key`, yubico-piv-tool
`ykpiv_util_set_protected_mgm`, the .NET SDK `SetPinOnlyMode`) change the
management key *before* storing it, with no rollback.  yubico-piv-tool
reports success even when storing it fails.  No Yubico source found
documents what happens when a write is interrupted or fails.

## Open questions

None.  Resolved:

- `yb fsck` reports a key/certificate mismatch through the opt-in
  `--check-key` flag, as part of its YubiKey section (spec 0023 §2).

## References

- [spec 0017](0017-blob-integrity-signature.md) — signature trailer (how the incident was detected)
- [spec 0021](0021-firmware-5.7-management-key.md) — management key algorithm, ADMIN DATA
- [spec 0023](0023-guided-format.md) — guided format built on this sequence
