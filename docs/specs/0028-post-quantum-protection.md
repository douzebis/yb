<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0028 — Post-Quantum Protection of Blobs (placeholder)

**Status:** draft
**App:** yb
**Implemented in:** <!-- YYYY-MM-DD, fill after implementation -->

> **Placeholder.**  This spec records the analysis and the options so
> far.  It has not been designed yet.  Do not implement it until it has
> been fleshed out and marked `ready`.

## Problem

Blobs are encrypted with ECDH P-256 (ephemeral key × the YubiKey's key in
slot 0x82), HKDF-SHA256 and AES-256-GCM.  A large enough quantum computer
would recover the ECDH shared secret from public data alone:

- the store objects can be read **without the PIN** (that is how `yb ls`
  and `yb fsck` work), and each blob carries its ephemeral public key;
- the slot 0x82 public key is in its certificate, also readable by
  anyone.

So anyone who holds the YubiKey for a minute can copy every blob today and
decrypt the copies later ("harvest now, decrypt later").  For long-lived
secrets, this is the realistic quantum threat.

Not affected in practice: AES-256 and HKDF-SHA256 (Grover's algorithm
leaves ~128-bit strength).  The ECDSA blob signatures (spec 0017) could be
forged by a quantum attacker, but that affects integrity, not the
confidentiality of blobs already copied; lower priority.

## Guidance

- **ANSSI** recommends **hybrid** schemes during the transition: a
  classical algorithm and a post-quantum one used together, so that the
  result stays secure if either is broken.  This applies to the target
  design (option B, ML-KEM + ECDH).  The stopgaps (options A and C) also
  keep ECDH and add a second input, but that input is symmetric, not a
  post-quantum algorithm.
- **NIST** (reported 2026-06-12, to be checked): initial working drafts
  of SP 800-73 Parts 1–2 and SP 800-78 add ML-KEM and ML-DSA to PIV in a
  "dual-stack" model (new key references and containers next to the
  classical ones).  Parameter sets still open; no timeline.
  <https://pages.nist.gov/piv-standards/pqc-overview/>

## State of YubiKeys (research, 2026-09)

- No shipping Yubico product supports a post-quantum algorithm (PIV,
  OpenPGP, FIDO2, YubiHSM 2).  Firmware 5.7 added RSA 3072/4096,
  Ed25519 and X25519 to PIV; firmware 5.8 (reported GA 2026-07-21)
  makes no material PIV change.
- Yubico demonstrated a prototype key with post-quantum signatures in
  October 2025 ("prototype ≠ product"), and states that post-quantum
  algorithms need **new hardware**, not a firmware update.  No product
  date.
  <https://www.yubico.com/blog/future-proofing-authentication-a-look-at-the-future-of-post-quantum-cryptography/>
- So on-card post-quantum decryption for yb is years away at best, and
  will need a new YubiKey.

## Options

### A. Stopgap: a secret kept on the YubiKey, mixed into the key derivation

yb only encrypts to itself, and `yb store` already needs the PIN (to
sign), so it does not need a post-quantum public-key algorithm:

- a random **32-byte** secret, kept on the YubiKey behind the PIN (256
  bits: ~128-bit strength against a quantum attacker, like AES-256);
- the blob key is derived from **both** the ECDH result and the secret;
- a new encryption format version (v3); v2 and older blobs stay readable.

Copied blobs then need ECDH broken **and** the secret, which needs the
PIN (limited tries) and the YubiKey.  Classical security is unchanged.

**Limit: the secret can be stolen.**  It reaches host memory when used
(as the ECDH result does today).  Malware present during a yb command, or
someone with the YubiKey and the PIN, can keep it.  With a future quantum
computer, a stolen secret opens every copied blob, and every later blob
written with it, without the YubiKey.  Today, the same attacker loses
everything once they lose access to the card.  Rotating the secret
limits the damage but means re-encrypting every blob.

It can be implemented despite ykman (below): ykman still reads PRINTED
with an extra tag; only `ykman piv access change-management-key` destroys
the secret.  Mitigations: `yb rotate-management-key` carries the secret
along; the documentation warns against the ykman command; a check value
makes yb report a lost secret as such; optionally, a second copy in
another object that only the PIN unlocks lets yb restore it.

### C. Stopgap with no copyable secret: FIDO2 hmac-secret

The YubiKey's FIDO2 application can compute HMAC-SHA256 with a 32-byte
key that never leaves the card (the CTAP2 `hmac-secret` extension, used
by `systemd-cryptenroll --fido2-device` and age plugins).  The card
computes; yb derives and encrypts, as it does with ECDH today:

- **store:** yb picks a random per-blob seed ("salt"); the card returns
  `K2 = HMAC(card key, salt)`; the AES key is `HKDF(ECDH result, K2)`; the
  salt is stored in the clear with the blob.
- **fetch:** yb reads the salt, asks the card for the same `K2`, derives
  the same AES key.
- once per store, yb keeps the FIDO2 credential ID (which of the card's
  HMAC keys to use).  Neither the salt nor the credential ID is secret;
  losing the credential ID loses the blobs.

Why it is better than option A: HMAC-SHA256 is symmetric (~128-bit
strength against a quantum attacker), and there is no lasting secret to
steal.  Malware only gets the `K2` of the blobs it asks the card about,
while present, never the card key.  It is close to option B's security,
on today's YubiKeys.

Costs:

- a second application and transport: FIDO2 runs over USB HID (CTAP2),
  not PC/SC; yb needs a CTAP HID stack, and on Linux, access to hidraw;
- the FIDO2 PIN, separate from the PIV PIN;
- a touch on each store and fetch, required by the YubiKey (see "Touch
  and PIN" below);
- two applications to keep consistent: a FIDO2 reset (`ykman fido
  reset`) destroys the HMAC key, and every v3 blob with it.

#### Touch and PIN

- **Touch cannot be skipped.**  CTAP 2.1 requires the authenticator to
  refuse `hmac-secret` when the platform asks for no user presence
  (`up = false`): it returns `CTAP2_ERR_UNSUPPORTED_OPTION`.  YubiKeys do
  so: `systemd-cryptenroll --fido2-with-user-presence=no` fails on a
  YubiKey for this reason (systemd issue #23632), although the same key
  allows silent assertions without `hmac-secret`.  Creating the
  credential (`makeCredential`) always needs a touch too.  So the touch
  is enforced by the YubiKey, not by yb, and malware cannot suppress it:
  every `K2` it obtains costs a physical touch.

  **Tested on hardware** (YubiKey 5.7.1, FIDO2 PIN not set, 2026-09-29):

  | Request | Result |
  |---|---|
  | makeCredential, `up = false` | refused, `CTAP2_ERR_INVALID_OPTION` |
  | makeCredential with `hmac-secret` | needed a touch |
  | getAssertion, `up = false`, no extension | accepted without touch (UP flag clear) |
  | getAssertion, `up = false`, `hmac-secret` | refused, `CTAP2_ERR_UP_REQUIRED` |
  | getAssertion, `up = true`, `hmac-secret` (twice, same salt) | needed a touch each time; same 32-byte output |

  The refusal code is `UP_REQUIRED` rather than the `UNSUPPORTED_OPTION`
  named in the CTAP 2.1 text; either way, `hmac-secret` never runs
  without a touch.  The credential was not resident (nothing stored on
  the key).
- **The PIN is bound into the output.**  The authenticator keeps two
  HMAC keys per credential, `CredRandomWithUV` and `CredRandomWithoutUV`,
  and uses one or the other depending on whether user verification (the
  FIDO2 PIN) was performed.  If yb always verifies the PIN, a request
  without the PIN yields a different, useless `K2`.  `credProtect` level 3
  (user verification required) can additionally make the credential
  unusable without the PIN.
- Consequence for usability: one touch per `yb store` / `yb fetch` (a
  command handling several blobs could ask the card once per blob, or use
  one `K2` per command and derive per-blob keys from it; to decide).

#### Why FIDO2: the candidate second inputs

PIV itself has no usable symmetric key: every key in a PIV slot is
asymmetric (breakable by a quantum computer, and its public key can be
read without the PIN), and the only symmetric key, the management key,
is used by the card only to check that the host already knows it.  The
candidates therefore come from other YubiKey applications, or from a
stored secret (option A):

| Candidate | Key | Transport | Guarded by | Touch | Stealable? |
|---|---|---|---|---|---|
| **A. Secret in PRINTED** | 32-byte secret, read out by the host | PC/SC (PIV) | PIV PIN (limited tries) | no | **yes**: whoever reads it once keeps it |
| **OTP challenge-response** (slot 2) | HMAC-SHA1, 20-byte key (~80-bit against a quantum attacker), stays on the card | PC/SC or HID | **nothing**: holding the YubiKey is enough | optional, set when the slot is programmed | no |
| **OATH** (Authenticator application) | HMAC-SHA256, 32-byte key, stays on the card | PC/SC | optional OATH password, **no retry limit** | optional per credential | no |
| **C. FIDO2 hmac-secret** | HMAC-SHA256, 32-byte key, stays on the card | USB HID (CTAP2) | **FIDO2 PIN**, 8 tries, bound into the output | **always** (enforced by the YubiKey) | no |

The threat is someone who holds the YubiKey for a minute and copies the
blobs.  With OTP, or OATH without a password, they can also ask the card
for each blob's HMAC on the spot, so the second input adds nothing.  An
OATH password can be guessed without limit.  Only FIDO2 requires a PIN
with a retry limit, and binds it into the result, matching the
"PIN + YubiKey" protection PIV gives yb today, with no secret that
malware could keep.  FIDO2 is therefore the preferred stopgap; option A
is the fallback that stays within PIV.

(The OATH details, arbitrary challenges and full untruncated responses,
are to be confirmed on hardware if OATH is ever reconsidered.)

### B. Target: post-quantum decryption on the YubiKey

A hybrid ML-KEM + ECDH scheme with both private keys non-extractable on
the YubiKey (PIV "dual-stack", per the NIST drafts).  Malware would only
ever see per-blob secrets while present, never a lasting key.  This needs
a YubiKey that does not exist yet.

The v3 format of option A should be designed so that its second input can
later be an on-card ML-KEM result (v4) without another redesign: each blob
records which kind of second input it used.

## Findings for option A: where to keep the secret

**PRINTED (0x5FC109)**, next to the management key, as a new tag (e.g.
`88 { 89 <management key>, 8B <secret> }`).  Measured and checked:

- **Size:** on both test YubiKeys (firmware 5.4.3 and 5.7.1), PRINTED
  accepted and returned objects of up to **3034 bytes** (tag `8B` up to
  3000 bytes) alongside the management key, and ykman's parser still
  found the key.  A 3100-byte write was refused by ykman's own library
  before reaching the card ("APDU length exceeds YubiKey capability").
  32 bytes is far below any limit.
- **ykman drops unknown tags.**  ykman 5.9.1 `PivmanProtectedData` keeps
  only tag `89`, and rebuilds PRINTED from it whenever it changes the
  management key (`pivman_set_mgm_key`).  Confirmed on hardware (5.7.1):
  after `ykman piv access change-management-key --generate --protect`,
  PRINTED went from tags `89, 8B` to `89` only.  When the new key is not
  stored, ykman **deletes** PRINTED.  Either way, one ykman command would
  silently destroy the secret, and every v3 blob with it.
- ykman refuses `ykman piv objects import` into PRINTED while the
  management key is stored there; other writes to PRINTED come from yb
  (or a PIV reset, which erases everything anyway).
- yb's own `encode_printed` writes only `89` and `8A`: every yb write to
  PRINTED (key switch, repairs, `yb rotate-management-key`) would have to
  carry the secret along.

**Alternatives:** only four PIV data objects need the PIN to be read
(measured, spec 0022 Assumptions): PRINTED (`5FC109`), Cardholder
Fingerprints (`5FC103`), Cardholder Facial Image (`5FC108`) and
Cardholder Iris Images (`5FC121`).  Every other object, including the
store's `5F0000–5FFFFF` range, can be read without the PIN and cannot
hold the secret.  The three biometric objects are not touched by ykman's
key commands, but other software may fill them (in practice they are
empty on a YubiKey).

**Mitigation to consider in any case:** a short check value of the secret
stored with the store (header or each v3 blob), so that a lost or changed
secret is reported as such ("the post-quantum secret is missing"), not as
a decryption failure.

## Open questions

- Option C (preferred, see the table above) or option A as the stopgap?
- Option A: where to keep the secret: PRINTED (convenient, ykman
  destroys it), a biometric object (safe from ykman, may collide with
  other software), or both, one as a backup?
- Option C: which CTAP HID implementation (a Rust crate, or libfido2)?
  How does the guided format set up the FIDO2 PIN and the credential?
  Confirm the PIN behavior (outputs with and without the FIDO2 PIN
  differ; `credProtect` level 3) on hardware, with a FIDO2 PIN set.
- Option C on Linux: `/dev/hidraw*` must be accessible to the user
  (udev `uaccess` rules, e.g. from libfido2); on the test VM they are
  root-only (mode 0600).
- Cite the exact ANSSI documents on hybrid schemes (for option B).
- Should the secret be backed up outside the YubiKey?  Losing it loses
  every v3 blob; a backup weakens the protection it provides.
- Rotation: new secret for new blobs only (store several), or re-encrypt
  all blobs?
- Is the store opt-in (`yb format --post-quantum`) or the default for new
  stores?  How does an existing v2 store migrate?
- Does the ECDSA signature need a post-quantum counterpart (e.g. an HMAC
  keyed by the secret)?
- Verify the NIST and Yubico items above against their sources (they come
  from a web search in 2026-09).

## References

- [spec 0017](0017-blob-integrity-signature.md) — blob signatures
- [spec 0021](0021-firmware-5.7-management-key.md) — PRINTED and ADMIN DATA layout
- [spec 0022](0022-format-sequence.md) — PRINTED tags `89` / `8A`, key switch
- [spec 0027](0027-management-key-rotation.md) — rotation, which would carry the secret
- [docs/YBLOB_FORMAT.md](../YBLOB_FORMAT.md) — encryption format versions
- ykman 5.9.1 `ykman/piv.py`: `PivmanProtectedData`, `pivman_set_mgm_key`
- Yubico blog, 2025-10-21:
  <https://www.yubico.com/blog/future-proofing-authentication-a-look-at-the-future-of-post-quantum-cryptography/>
- CTAP 2.1, `hmac-secret` extension (§12.5):
  <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html>
- systemd issue #23632, `--fido2-with-user-presence=no` and hmac-secret:
  <https://github.com/systemd/systemd/issues/23632>
- NIST PIV post-quantum working drafts, 2026-06:
  <https://pages.nist.gov/piv-standards/pqc-overview/>
