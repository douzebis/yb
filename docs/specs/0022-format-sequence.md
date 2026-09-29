<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0022 — Safe Ordering of `yb format`

**Status:** draft
**App:** yb
**Implemented in:** <!-- YYYY-MM-DD, fill after implementation -->

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

The only explanation that fits: `yb format --generate` (or `yb
self-test`, which runs it internally) replaced the key and certificate,
and then failed before the store was rewritten.  The blob was
permanently lost, and the store still looked intact.

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
- `yb store` refuses to encrypt when the store slot's key does not match
  its certificate, so a card damaged by another tool cannot silently
  receive undecryptable blobs.
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
   - firmware version;
   - management key algorithm (spec 0021 §1);
   - ADMIN DATA interpretation (spec 0021 §4);
   - default-credential status.

   Reject PIN-derived mode and unknown algorithms here.
3. **PIN**: obtain it and VERIFY it.  A wrong PIN is caught here, not
   after a key has been replaced.
4. **Management key**: resolve it and authenticate.  This proves write
   access with the key that the Phase B steps will use.
5. **Store slot** (only when `--generate` is **not** given):
   - read the certificate and check it holds an EC P-256 public key;
   - **check that the key matches it**: sign a random 32-byte digest in
     the slot (PIN already verified) and check the signature against
     the certificate's public key.

   On mismatch, fail with a message recommending `--generate`.
6. **Existing store** (read-only):
   - if a store is present, list its blobs on stderr as `will be
     destroyed: <name>…`;
   - if the store cannot be parsed, say so and continue.

Steps 3 and 4 may share one PC/SC session.  The whole phase must not
write any object.

### 2. Phase B — changes, in this order

**B1 — `--protect`.**  Rearranged so that the new key is always saved
somewhere before it becomes the card's only key:

- **B1a** Write the new key to PRINTED as `88 { 89 <key> }`,
  authenticating with the **old** key.
- **B1b** `SET MANAGEMENT KEY` to the new key, authenticating with the
  old key.
- **B1c** Write ADMIN DATA (spec 0021 §4), authenticating with the
  **new** key.

What each failure leaves behind:

| Fails at | Card state | Recovery |
|---|---|---|
| B1a | unchanged, or PRINTED holds an unused key while the flags still say unprotected | re-run; nothing is lost |
| B1b | as above | re-run |
| B1c | key changed and saved in PRINTED; flags not updated | yb prints the new key on stderr, prefixed `RECOVERY:`, and says to re-run `yb format --protect` with `YB_MANAGEMENT_KEY` set to it |

Printing the key in the B1c case is intentional: it is the only
situation in which the key would otherwise be reachable only through a
state yb does not recognize as protected.

**B2 — wipe the store**: `Store::format` with the management key that is
current after B1 (PIN-only resolution when B1 ran, as today).

Doing this before B3 means a `--generate` failure can never orphan
blobs, because there are no blobs left to orphan.

**B3 — `--generate`**:

- **B3a** Generate the key.
- **B3b** Create and write the certificate.
- **B3c** Re-read the certificate and verify the key/certificate match,
  as in Phase A step 5.

If B3b or B3c fails, format exits non-zero with:

```
the store is empty and the key in slot 0x82 was replaced, but its
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
  `Generating key in slot 0x82…`).
- A Phase B failure prints:
  - the failing step and the underlying error;
  - the steps already completed;
  - the resulting card state, taken from the tables above;
  - the command to run next.

### 5. Backend changes

- `PivBackend` gains an operation that signs a digest in a slot and
  returns a raw signature, for the match check.  The existing
  `ecdsa_sign` can be reused.
- `enable_pin_protected_management_key` is rewritten to follow B1a–B1c.
- The virtual PIV backend gains **fault injection**: fail the Nth
  write, or fail a named operation.  Tests use it to fail each Phase B
  step in turn and assert:
  - **I1**: after any failure, the store is empty, or its blobs decrypt
    with the key in the store slot.
  - **I2**: the card's management key is available from PRINTED, from
    the caller's key, or from the `RECOVERY:` output.
  - **I3**: exit code 0 implies the key and certificate match.

### 6. Key/certificate check in `yb store`

- Before encrypting, `yb store` runs the Phase A step 5 match check on
  the store slot.  It already verifies the PIN, so this costs one extra
  sign operation per invocation, not per blob.
- On mismatch, it refuses before writing anything:

  ```
  the key in slot 0x82 does not match its certificate; new blobs would
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
- Spec 0021 §6 applies.

## Open questions

None.  Resolved:

- `yb fsck` reports a key/certificate mismatch through the opt-in
  `--check-key` flag, as part of its YubiKey section (spec 0023 §2).

## References

- [spec 0017](0017-blob-integrity-signature.md) — signature trailer (how the incident was detected)
- [spec 0021](0021-firmware-5.7-management-key.md) — management key algorithm, ADMIN DATA
- [spec 0023](0023-guided-format.md) — guided format built on this sequence
