<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0028 — Post-Quantum Stores (FIDO2 hmac-secret)

**Status:** ready
**App:** yb
**Implemented in:** <!-- YYYY-MM-DD, fill after implementation -->

> Goals, decisions with their rationale, the specification (formats,
> card operations, commands, libyubiblob), invariants, code structure,
> tests and the ANSSI assessment.  Implementation follows "Order of work"
> (Code structure).

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

AES-256 and HMAC/HKDF-SHA256 are not affected in practice (Grover's
algorithm leaves ~128-bit strength).  The ECDSA blob signatures could be
forged by a quantum attacker, which affects integrity at the time of the
attack, not the confidentiality of blobs already copied.

## Goals

- **G1. Post-quantum confidentiality of copied blobs.**  A copy of the
  store taken without the PIN cannot be decrypted, even with a quantum
  computer.
- **G2. No key leaves the YubiKey.**  The secret that protects the blobs
  stays on the card; the host only ever sees per-blob values.
- **G3. One PIN, one touch per blob.**  Storing or fetching a blob needs
  exactly one PIN and one touch, whatever the command does with it
  (encryption key or seal, management key).
- **G4. Post-quantum integrity.**  A blob not written by yb with this
  YubiKey and its PIN (forged, altered, renamed, or written back after a
  PIV reset) is detected when it is fetched, even by an attacker with a
  quantum computer.
- **G5. Legacy stores keep working**, unchanged, side by side with the new
  ones (same yb, same libyubiblob).
- **G6. Clear PIN wording.**  Every prompt and message names the PIN it
  wants: "FIDO2 PIN" or "PIV PIN".
- **G7. Testable without hardware**, as PIV is today with the virtual card
  (vpcd), plus hardware tests on real YubiKeys.
- **G8. Quick checks without PIN or touch.**  `yb ls` and `yb fsck` still
  detect corruption without the PIN (checksum, D5); they are not
  authoritative against the attacker of the threat model.

## Non-goals

- Post-quantum *public* checks.  The PIN-less check is a checksum (D5);
  post-quantum integrity comes from the seal, checked with the PIN (D6).
- Detecting deletions, or a blob replaced by an older genuine version of
  itself, with a sealed manifest; and detecting a whole-store rollback
  with state kept on the computer.  Not pursued: without the management
  key, nobody can write to the store, and obtaining write access through a
  PIV reset is detected (D11).
- Protecting against a compromised host or USB path while a yb command
  runs (see "Threat model").
- Converting a store between legacy and post-quantum in place: the choice
  is made at format time; changing it means reformatting.
- On-card post-quantum algorithms (ML-KEM, ML-DSA): no YubiKey supports
  them (see "State of YubiKeys"); a later spec may add them.
- Durability beyond the YubiKey: backups are the user's responsibility
  and are mandatory (see "Losing the store").

## Decisions

### D1. Two kinds of store, chosen at format time

`yb format` creates either a **legacy** store (today's design: PIV ECDH,
PIV ECDSA, PIV PIN) or a **post-quantum** store (this spec).  The kind
cannot be changed afterwards except by reformatting.  The guided format
recommends post-quantum strongly, and explains which PIN each kind uses.

Rationale: keeping both behaviors in one store (per-blob choice,
migration) multiplies the cases to test and explain; reformatting is
cheap with backups.

### D2. The secret: FIDO2 `hmac-secret` (option C)

Each blob's key comes from the YubiKey's FIDO2 application:
`K2 = HMAC-SHA256(card key, salt)`, computed on the card, with a random
32-byte salt per blob stored in the clear.  The card key never leaves the
YubiKey; the FIDO2 PIN is bound into the output, and the YubiKey enforces
a touch (both confirmed on hardware, below).

Rationale: this is the only YubiKey mechanism that keeps the key on the
card and requires a PIN with a retry limit (see "Options considered").

### D3. No ECDH in post-quantum stores

The blob key comes from K2 alone (through HKDF); PIV ECDH is not used.

Rationale: ANSSI's recommendation of **hybrid** schemes is about new
post-quantum *public-key* algorithms, which are young and may yet be
broken.  HMAC-SHA256 with a 256-bit key is a long-established symmetric
construction, considered post-quantum safe on its own.  Dropping ECDH
removes the PIV PIN from fetches, the PIV decryption key, and 33 bytes per
blob.  Checked against ANSSI's texts: see "ANSSI assessment".

### D4. A non-resident FIDO2 credential, one per store

`yb format` creates one FIDO2 credential, with `hmac-secret` and
`credProtect` level 3 (unusable without the PIN), **not resident**
(nothing stored in the YubiKey's credential slots).  Its credential ID is
kept in the store's readable PIV objects (D13); its public key is not
needed (D5).

Rationale:

- A non-resident credential ID is the credential's key material wrapped
  by a secret unique to the YubiKey: only that YubiKey can use it.  The
  ID is not secret.  (Yubico: AES-256-CCM under a device master key; see
  "YubiKey FIDO2 facts".)
- A resident credential is strictly worse: it is no more confidential
  (the USB exchange is the same, see "Threat model"), takes one of the
  limited slots (25; 100 since firmware 5.7), shows up in passkey managers
  (`ykman fido credentials`, browsers, OS settings), where a user cleaning
  up passkeys could delete it, and reveals that yb is in use.
- Cost: the ID must be stored in PIV.  A PIV reset loses the ID, a FIDO2
  reset loses the key; either loses the store.  Backups cover both.

### D5. No signature: a checksum for the PIN-less checks

Post-quantum blobs carry **no signature**.  `yb ls` and plain `yb fsck`
check a **SHA-256 checksum** of the blob (metadata and stored bytes),
kept in its trailer: it detects corruption without PIN or touch (G8).  It
is not authoritative against the attacker of the threat model; **the
seal is** (D6).  Commands say "checksum OK", never "authentic".

Rationale (revised 2026-10-16, confirmed 2026-10-17; the first version
signed each blob with the FIDO2 assertion, ES256 over `authData ‖
clientDataHash`):

- **The signed `authData` contains K2, encrypted.**  The `hmac-secret`
  output is an extension output inside `authData`, encrypted under the
  CTAP session key (ECDH P-256).  Checking the signature later would mean
  storing that ciphertext with every blob: the very secret we protect,
  kept in the store under classical cryptography.
- **It buys little.**  ECDSA is not post-quantum, so the signature was
  only a corruption check (G8).  Against classical tampering it only
  helps against someone with the management key, who is caught anyway at
  fetch (D6) and by D11.  It cost about 100 bytes per blob, plus envelope
  encryption (needed only to sign the ciphertext).

Without signatures, the credential's public key is not needed (D13).

### D6. The seal: post-quantum integrity

Every blob carries a **seal** that only the card's K2 can produce, so only
someone with the YubiKey, the FIDO2 PIN and a touch.  HMAC-SHA256 and
AES-256-GCM with a K2-derived key cannot be forged with a quantum
computer.  The metadata (name, sizes, flags, time) is bound to it.

- **Encrypted blobs:** the blob is encrypted with AES-256-GCM under a key
  derived from K2, with the metadata as associated data.  The GCM tag
  **is** the seal: no valid ciphertext can be made without K2, and it
  fails if the metadata or the bytes change, or if it is moved to another
  blob.  (Without a signature, K2 can be obtained first and used
  directly: no envelope, no random data key.)
- **Unencrypted blobs:** the seal is `HMAC-SHA256(key derived from K2,
  checksum)`, 32 bytes, in the trailer.

**Checking.**  Every fetch checks the seal (decryption does it for an
encrypted blob); a blob whose seal fails is refused, with a message that
suggests tampering.  `yb fsck` checks seals on request (one touch per
blob); by default it checks checksums (no PIN) and the credential and
management key (D11).

Consequences:

- **Fetching any blob of a post-quantum store needs the FIDO2 PIN and a
  touch**, unencrypted ones included (D8).
- Encryption does not become mandatory: integrity does not depend on it.
- Exact layout and overhead: see "Specification (draft)".

### D7. The user's management key, wrapped by FIDO2

The PIV management key authorizes every write to the store objects.  In a
post-quantum store, yb **uses the management key already on the card**,
as is: it does not generate a random one, and does not change the card's
key.  Other PIV uses of the YubiKey (ykman, SSH keys) keep working with
the key the user knows.

yb keeps a copy **wrapped by a second `hmac-secret` output** (a second,
per-store salt), with its algorithm, in the store descriptor (D13).
`hmac-secret` accepts **two salts per assertion**, so one PIN and one
touch give the blob's K2 and the management key's K2.

At format:

1. yb reads the key's algorithm from the card (GET METADATA, firmware
   5.3+): 3DES, AES-128, AES-192 or AES-256;
2. yb obtains the key: from `YB_MANAGEMENT_KEY`; else, if ykman's
   convention is in use (key in PRINTED behind the PIV PIN), from PRINTED
   with the user's agreement (the only time a post-quantum store asks for
   the PIV PIN); else typed by the user (hex, hidden);
3. yb **refuses the factory default** (`010203…0708`: 3DES before firmware
   5.7, AES-192 since);
4. yb checks the key against the card (mutual authentication), then wraps
   and stores it.

When the user changes the key (with ykman or another tool), they tell yb
with **`yb management-key set`**: it asks for the new key (any supported
algorithm), refuses the default, checks it against the card, warns that
a mismatch may also mean tampering (D11), then wraps and stores it.  FIDO2
PIN and a touch.

Consequences:

- yb never asks for the **PIV PIN** with a post-quantum store, except
  optionally once at format.
- `yb rotate-management-key` is refused on post-quantum stores (the user
  manages the key); legacy stores keep it.
- The "ykman drops unknown PRINTED tags" problem (see "Options
  considered") disappears: yb does not write PRINTED.
- If a ykman copy of the key remains in PRINTED, anyone with the PIV PIN
  can write to the store: delete or damage blobs, not read them, and
  not forge them (D6).  yb leaves that copy alone, and the wizard says so.
- Malware present during a yb command could keep the management key, as
  it can today with the PIV PIN.

### D8. One touch per blob

Each blob stored or fetched costs one assertion, so one touch, even when
a command handles several blobs.  Simpler to explain than batching two
blobs per touch.  In a post-quantum store this includes fetching an
unencrypted blob, to check its seal (D6).  `yb ls` needs neither PIN nor
touch.

### D9. libfido2 is a hard dependency

yb and libyubiblob always link libfido2 (through a small FFI layer).  The
guided format recommends post-quantum stores, so a yb unable to open them
would be confusing.

Exception, for now: **Windows**, where yb is not shipped and only
libyubiblob's portability is checked (CI): yb-core builds there without
its FIDO2 module, so legacy stores only.  To lift later: a planned
`keepassxc-yb` (KeePassXC with yb, legacy and post-quantum) will be built
for Windows too.  That needs libfido2 on Windows (Yubico's builds or
vcpkg) found at build time, and a Windows HID path for the serial
(vendor command).

### D10. PINs: one per store kind, named everywhere

| Store kind | PIN yb asks for | Retries | Unblocking |
|---|---|---|---|
| legacy | PIV PIN | 3 (then PUK, 3) | PUK |
| post-quantum | FIDO2 PIN | 8 (replug after 3 in a row) | **none**: only a FIDO2 reset, which destroys the store |

- yb never tries one PIN as the other (no wasted attempts), and never
  changes the FIDO2 PIN.  Users often already have one for passkeys.
- The guided format sets a FIDO2 PIN if none exists (FIDO2 has no default
  PIN, and `hmac-secret` with the PIN needs one).  Whether a PIN is set
  comes from the device info (`clientPin` option, as ykman shows it),
  without using an attempt.
- `--pin-stdin` provides the PIN of the store's kind.
- Before asking, yb reads the remaining attempts and refuses when **3 or
  fewer** remain, unless forced; the wizard explains that a blocked FIDO2
  PIN cannot be unblocked.  (The YubiKey also requires a replug after 3
  failures in a row.)

### D11. The management key is checked on every use

Every store **and every fetch** unwraps yb's copy of the management key
(the second salt of the same assertion, no extra touch) and authenticates
to the card with it (no PIN).  `yb fsck` does the same, along with
checking that the credential answers.  The YubiKey has no attempt counter
for the management key, so a failed check costs nothing.

On a mismatch, yb stops with a message that suggests tampering, for
example: "the PIV management key does not match: the PIV application may
have been reset, and the store may have been tampered with.  If you
changed the key yourself, run `yb management-key set`."

Rationale: this is what detects a PIV reset (see "Threat model").  After a
reset, the card's management key is the factory default, and an attacker
cannot restore the original one: it is wrapped by K2, which they cannot
compute.  So the mismatch persists whatever objects they write back.
(Resident and non-resident credentials make no difference here: both
survive a PIV reset, both are destroyed by a FIDO2 reset.)

### D12. A new magic for post-quantum stores

Every object of a post-quantum store starts with the magic **`0xF2EDF0B2`**
("Fred FOB 2", the second generation of `0xF2ED5F0B`, "Fred's Fob"),
stored little-endian (`B2 F0 ED F2`) like the first.

Rationale: older yb must never damage a post-quantum store; reading it is
not needed.  yb 0.6 refuses any object whose magic is not `0xF2ED5F0B`
(`Object::from_bytes`, `yb-core/src/store/mod.rs`), and every command
reads object 0 first, so with a new magic `yb ls`, `fetch`, `store`, `rm`
and `fsck` all stop with "bad magic" before writing anything, including
the cleanup writes `yb store` makes before signing, and even when a ykman
copy of the management key would let it write.  Only `yb format` can
overwrite the store, as it can any foreign data, after asking (since 0.5).

Consequences:

- The post-quantum layout is free: no constraint from yb 0.6's 65-byte
  signature trailer (see "Compatibility with older yb"), and
  `BLOB_KEY_SLOT` keeps no legacy meaning.
- The next release should say "this store was made by a newer yb
  (post-quantum); update yb" instead of "bad magic", and accept unknown
  signature trailers of any length as "newer version".  Neither is needed
  for safety.
- The `file` magic database must learn the new magic (see "Documentation,
  format and release tasks").

### D13. The store descriptor in object `0x5F_0000`

A post-quantum store keeps its description in **object `0x5F_0000`**, with
the new magic and a type byte saying "descriptor"; its chunks follow from
`0x5F_0001`.  All of yb's objects stay contiguous (neater for `fsck`,
backups and object dumps), and older yb stops at the very first object it
reads.

Contents (at most 356 bytes, no secrets, readable without the PIN;
exact layout in "Specification (draft)"):

| Field | Size |
|---|---|
| magic, chunk count, type, format version | 7 |
| management key algorithm | 1 |
| credential ID, with its length | up to 256 (241 with OpenSK; at most 128 on YubiKeys) |
| management key salt | 32 |
| management key: nonce, wrapped key, tag | 44–60 |

- It changes only at format and with `yb management-key set`.
- Losing it loses the store (like a FIDO2 reset): backups must include it.
  One copy (no redundant second object), backups cover it.
- Format creates the credential, wraps the management key, writes the
  empty chunks, deletes any yb object beyond the last chunk, and writes
  the descriptor **last**: a store exists once its descriptor is written.
  An interrupted format leaves object 0 and the chunks with different
  magics, which every yb version refuses to read (no writes), and which
  a new format overwrites.

Why not in the FIDO2 application: a credential cannot hold its own ID (yb
must know the ID to read anything kept with it; resident credentials,
found by RP ID, were rejected in D4); `largeBlob` (CTAP 2.1) needs a
resident credential, is shared with every FIDO2 user of the key
(browsers), needs the PIN to write, and is small; `credBlob` holds about 32
bytes, with the same chicken-and-egg problem.

## Threat model

**In scope:** an attacker who gets the YubiKey (stolen, or borrowed and
returned), for any time, with a quantum computer, but **without the FIDO2
PIN**.

- **They cannot read encrypted blobs** (G1): every blob key needs K2,
  so the card, the PIN and a touch; with `credProtect` 3 the credential
  does not even answer without the PIN.  Their only chance is guessing the
  PIN: 8 attempts, a replug after every 3.  FIDO2 allows PINs of 4
  characters, so the wizard insists on a non-trivial PIN.
- **They cannot forge or replace blobs undetected** (G4):
  - without the management key they cannot write to PIV at all (it is
    wrapped by K2, and the factory default is refused);
  - their only way to write is a PIV reset (block the PIV PIN and PUK,
    then reset), which sets the default management key; yb notices on
    the next store, fetch or fsck (D11);
  - any blob they write, alter or rename fails its seal at fetch (D6).
- **They can fake checksums** (D5), so the PIN-less checks are not
  authoritative against them (G8).
- **They can always destroy the store** (FIDO2 or PIV reset, or breaking
  the key): detectable, not preventable.  Backups.

| Attack (YubiKey in hand, quantum computer, no PIN) | Result |
|---|---|
| Read encrypted blobs | impossible |
| Forge, alter or rename a blob | detected at fetch (seal) |
| Write anything | needs a PIV reset: detected (management key) |
| Pass `yb ls` / plain `yb fsck` with forged blobs | possible: not authoritative |
| Destroy the store | always possible: backups |

**Out of scope:** the host and the USB path while a yb command runs.
Detailed analysis:

- **Compromised OS** (root, malware, `usbmon`): it reads the PIN as it is
  typed, and K2, the blob keys and the plaintext from memory.  No quantum
  computer needed; no design that types the PIN on the host can resist.
- **Passive hardware tap** (rogue cable or hub) with a clean OS: CTAP2
  protects the PIN and the `hmac-secret` salts and outputs with the PIN
  protocol (1 or 2), based on **ECDH P-256**.  A recording made today can
  be decrypted by a future quantum computer: it yields a truncated hash of
  the PIN (brute-forced easily), the K2 of the blobs used while recording,
  and the management key's K2, hence the management key.  This is the only
  place where classical cryptography remains in a post-quantum store.  It
  affects resident and non-resident credentials alike; CTAP has no
  post-quantum PIN protocol, up to CTAP 2.3 (2026-02).
- **Active hardware tap:** CTAP's key agreement is not authenticated, so
  a device in the middle reads the PIN and K2 today, without a quantum
  computer.
- For comparison, a **legacy** store is fully exposed to any tap: the PIV
  PIN crosses USB in clear (VERIFY), and so does the ECDH result.

## Losing the store

A post-quantum store depends on both applications of the YubiKey:

- a **FIDO2 reset** (including after a blocked FIDO2 PIN) destroys the
  card key: every blob is lost;
- a **PIV reset** destroys the store objects, including the credential ID;
- losing or breaking the YubiKey loses everything, as today.

Backups are therefore mandatory, and the wizard says so.  On a
post-quantum store, `yb fsck` checks that the credential still answers
and that the management key matches (D11), with the FIDO2 PIN and a
touch, and reports each failure as such.  Checksums need neither
(D5).

## Specification (draft)

All integers are little-endian unless stated.  "K2(salt)" is the
`hmac-secret` output of the store's credential for `salt`, obtained with
the FIDO2 PIN (UV) and a touch.  `HKDF(K2, label)` is HKDF-SHA256 with
`ikm = K2`, no salt, `info = label`, 32 bytes of output.

### Objects

| Object | Content |
|---|---|
| `0x5F_0000` | store descriptor (D13) |
| `0x5F_0001` … `0x5F_00NN` | chunks 1 … N (N = 1–32, default 32) |

Chunk `i` (0 … N−1) is object `0x5F_0001 + i`; `NEXT_CHUNK` holds chunk
indices.  (Revised 2026-10-17 from "indices 1 … N": with a per-store
first object ID, the legacy chunk code is reused unchanged.)

### Store descriptor (object `0x5F_0000`)

```
Offset   Size  Field
───────  ────  ───────────────────────────────────────────────────────
0x00      4    MAGIC = 0xF2EDF0B2
0x04      1    OBJECT_COUNT — number of chunks N (1–32)
0x05      1    TYPE = 0x01 (descriptor)
0x06      1    VERSION = 0x01
0x07      1    MGMT_ALGO — PIV algorithm of the management key:
               0x03 3DES, 0x08 AES-128, 0x0A AES-192, 0x0C AES-256
0x08      1    CRED_ID_LEN (1–255)
0x09      L    CRED_ID — FIDO2 credential ID (opaque)
0x09+L   32    MGMT_SALT — hmac-secret salt for the management key
0x29+L   12    MGMT_NONCE
0x35+L    K    MGMT_WRAPPED — the management key (K = 24, 16, 24 or 32
               bytes), AES-256-GCM encrypted
0x35+L+K 16    MGMT_TAG
```

`MGMT_WRAPPED ‖ MGMT_TAG = AES-256-GCM(HKDF(K2(MGMT_SALT), "yb-pq-v1
management key"), MGMT_NONCE, key, ad = bytes 0x00 … 0x29+L−1)`.  At most
356 bytes.  Rewritten (new nonce) by `yb management-key set` only.

The FIDO2 credential: RP ID `yb`, algorithm ES256, not resident
(`rk = false`), extensions `hmac-secret` and `credProtect` = 3, a random
16-byte user ID (not stored).  Its public key is not stored (D5).

### Chunks

Same layout as legacy chunks (`docs/YBLOB_FORMAT.md` §3), except:

- `MAGIC` (0x00) is `0xF2EDF0B2`;
- byte 0x05 (`STORE_KEY_SLOT` in legacy chunks) is `RESERVED = 0x00`;
- `OBJECT_COUNT` (0x04) repeats N;
- head byte 0x12 (`BLOB_KEY_SLOT` in legacy chunks) is `BLOB_FLAGS`:
  bit 0 = encrypted; other bits 0.

### Blob bytes and trailer

The chunk chain holds `STORED[0 .. BLOB_SIZE]`, then the trailer, as in
legacy blobs (the trailer may spill into one more chunk).

`STORED`:

- unencrypted: the payload (compressed or not, C-bit as today);
- encrypted: `0x03 ‖ NONCE (12, random) ‖ CIPHERTEXT ‖ TAG (16)`: 29
  bytes of overhead.

Trailer:

```
Offset  Size  Field
──────  ────  ─────────────────────────────────────────────────────────
0        1    TRAILER_VERSION = 0x03
1       32    SALT — this blob's hmac-secret salt (random, new per write)
33      32    CHECKSUM
65      32    SEAL — unencrypted blobs only
```

65 bytes for an encrypted blob, 97 for an unencrypted one.

With `META = u8 BLOB_NAME_LEN ‖ BLOB_NAME ‖ u8 BLOB_FLAGS ‖ u8 C-bit ‖
u32 BLOB_PLAIN_SIZE ‖ u32 BLOB_SIZE ‖ u32 BLOB_MTIME ‖ SALT`:

- `CHECKSUM = SHA-256("yb-pq-v1 checksum\0" ‖ META ‖ STORED)`;
- encrypted: `CIPHERTEXT ‖ TAG = AES-256-GCM(HKDF(K2(SALT), "yb-pq-v1
  blob encryption"), NONCE, payload, ad = "yb-pq-v1 blob\0" ‖ META)`;
- unencrypted: `SEAL = HMAC-SHA256(HKDF(K2(SALT), "yb-pq-v1 blob seal"),
  CHECKSUM)`.

Checks, in order:

1. checksum (no PIN): mismatch → corrupted;
2. seal (PIN, touch): GCM failure or `SEAL` mismatch → refused as
   possibly tampered with.

Overhead per blob: 94 bytes encrypted (29 + 65), 97 unencrypted; legacy
v2: 159 encrypted (94 + 65), 65 unencrypted.

### Writing

The chunk machinery is shared with legacy stores, so their write
guarantees apply unchanged: a new copy goes into free objects,
continuation chunks first and head last, and the old copy is freed only
afterwards (spec 0031, invariant 0001); a write the card refuses for lack
of memory is cleaned up by the next write (spec 0038); a store without
room writes nothing (invariant 0004).

Per blob, `yb store`:

1. compresses the payload if asked (before encryption, as today);
2. runs the blob's assertion (one touch), checks the management key
   (D11), and computes `STORED` and the trailer;
3. only then writes, with the same ordering as legacy stores.

A refused assertion (no touch, wrong PIN, missing credential) therefore
writes nothing for that blob.  With several blobs, each one is complete
or untouched; a refusal stops the command before the next blob.

### Card operations

Each FIDO2 operation costs one touch:

| Command | Operation | Salts |
|---|---|---|
| `yb format` | makeCredential, then an assertion | —, then `MGMT_SALT` |
| `yb store` (per blob) | assertion | new `SALT` ‖ `MGMT_SALT` |
| `yb fetch` (per blob) | assertion | blob's `SALT` ‖ `MGMT_SALT` |
| `yb rm` | assertion | `MGMT_SALT` |
| `yb fsck` | assertion; `--seals`: one more per blob | `MGMT_SALT`; blob's `SALT` ‖ `MGMT_SALT` |
| `yb management-key set` | assertion | `MGMT_SALT` |
| `yb ls` | none | — |

Every assertion: allowList = `[CRED_ID]`, `up = true`, the FIDO2 PIN
(PIN protocol 2 if offered, else 1), `clientDataHash` = 32 random bytes
(nothing is signed).  The management key from `K2(MGMT_SALT)` is checked
against the card before anything else (D11).

Card errors, as yb reports them:

| Error | Meaning for the user |
|---|---|
| `OPERATION_DENIED`, `USER_ACTION_TIMEOUT` | the YubiKey was not touched in time |
| `NO_CREDENTIALS` | the store's FIDO2 credential is gone (FIDO2 reset?); the store cannot be read; restore from backups |
| `PIN_INVALID` | wrong FIDO2 PIN, N attempts left |
| `PIN_AUTH_BLOCKED` | 3 wrong PINs in a row: unplug and replug the YubiKey |
| `PIN_BLOCKED` | FIDO2 PIN blocked: only a FIDO2 reset clears it, which destroys this store; restore from backups |

### Device

yb finds the FIDO2 device of the selected YubiKey by its serial (vendor
command, see "Finding the FIDO2 side"), else uses the only FIDO2 device
present, else refuses.  Without access to `/dev/hidraw*`, it says so and
points to the documentation (udev rules).

### Commands

**`yb format`.**  The guided format first asks for the kind of store,
post-quantum first and recommended:

```
What kind of store?
  1) post-quantum (recommended): protected by the YubiKey's FIDO2
     application; asks for the FIDO2 PIN and a touch for each blob
  2) legacy: protected by the PIV application; asks for the PIV PIN
```

For a post-quantum store it then:

1. finds the FIDO2 device of this YubiKey;
2. FIDO2 PIN: if none is set, asks for a new one, twice, at least 6
   characters (yb's minimum; the YubiKey allows 4); otherwise asks for it,
   after checking the attempts (D10).  It explains: "The FIDO2 PIN has no
   unblocking code: 8 wrong PINs block it for good, and only a FIDO2 reset
   clears it, which destroys this store.  Keep backups.";
3. management key: reads its algorithm from the card; refuses the factory
   default ("change it first, e.g. `ykman piv access
   change-management-key`"); takes it from `YB_MANAGEMENT_KEY`, else
   offers to read ykman's copy in PRINTED (PIV PIN), else asks for it
   (hex, hidden); checks it against the card;
4. shows the plan: objects erased and written, the FIDO2 credential
   created, two touches, backups mandatory, and that a ykman copy of the
   management key left in PRINTED lets anyone with the PIV PIN delete
   blobs; asks for confirmation;
5. creates the credential (touch), wraps the management key (touch),
   writes the empty chunks, deletes yb objects beyond them, and writes the
   descriptor last (D13).

Non-interactive: `yb format --post-quantum --yes`, with the management
key in `YB_MANAGEMENT_KEY` and the FIDO2 PIN on standard input
(`--pin-stdin`); it refuses if no FIDO2 PIN is set.  `--key-slot`,
`--generate`, `--subject` and `--protect` are legacy options and refused
with `--post-quantum`.

**PIN prompts** name the PIN: `FIDO2 PIN:` or `PIV PIN:`.  `--pin-stdin`
carries the PIN of the store's kind (spec 0037 unchanged otherwise).

**Touch:** before each assertion, `Touch your YubiKey…` on standard
error (not with `--quiet`).  No serial number (invariant 0011).

**FIDO2 PIN attempts:** with 3 or fewer left, yb refuses: "only N FIDO2
PIN attempts left; a blocked FIDO2 PIN cannot be unblocked, and would
destroy this store.  Make sure of your PIN, then retry with
`--allow-low-pin-attempts`."  The flag allows one command to go on.

**`yb management-key set`:** for post-quantum stores only; takes the new
key from `YB_MANAGEMENT_KEY` or asks for it (hidden), refuses the
default, checks it against the card, warns that a mismatch with the
stored key can also mean tampering (D11), then rewraps it (touch).

**`yb rotate-management-key`:** refused on post-quantum stores ("this
store uses your own management key; change it with ykman, then run `yb
management-key set`").

**`yb ls`:** says "post-quantum store"; per blob, the checksum verdict.

**`yb fsck`:** descriptor (parsed, credential ID, algorithm); the
credential and the management key (one touch); checksums; `--seals` adds
one touch per blob.

**`yb fetch`, `yb store`, `yb rm`:** as today, with one touch per blob
(store, fetch) or per command (rm), and the checks above.

### Exit statuses (`yb`)

Existing: 0 success, 1 error, 2 not found, 3 store full.  New:

| Status | Meaning |
|---|---|
| **4** | integrity check failed on a post-quantum store: checksum mismatch, seal failure, or management key mismatch (D11); nothing was returned or written |

Every other new failure (no touch, wrong or blocked FIDO2 PIN, too few
attempts, missing credential, no access to the FIDO2 device) is status 1,
with its message.  Legacy stores keep their statuses (G5).

### libyubiblob 0.2.0

The ABI is still 0 (spec 0039 G7: changes may break callers before
1.0); the library version becomes 0.2.0.

- **Store kind.**  `StoreInfo` gains `uint32_t kind`:
  `YUBIBLOB_KIND_LEGACY = 0`, `YUBIBLOB_KIND_POST_QUANTUM = 1`.  The
  application asks for the PIN of that kind ("FIDO2 PIN" or "PIV PIN");
  the `pin` arguments carry it; `yubiblob_last_pin_tries()` reports the
  attempts left for that PIN.
- **Touch.**  `yubiblob_set_touch_callback(Session *session, void
  (*callback)(void *user), void *user)`: called before each operation
  that waits for a touch (KeePassXC shows "Touch your YubiKey"); NULL
  removes it.
- **Open flag** `YUBIBLOB_OPEN_ALLOW_LOW_PIN_ATTEMPTS = 0x2`.
- **Verdict** `YUBIBLOB_SIGNATURE_CHECKSUM_OK = 4`: a post-quantum blob
  whose checksum matches (D5); a mismatch is `..._CORRUPTED` as today.
- **New statuses** (existing ones keep their values; `WRONG_PIN` and
  `PIN_BLOCKED` also cover the FIDO2 PIN):

  | Value | Name | Meaning |
  |---|---|---|
  | 14 | `YUBIBLOB_ERR_TAMPERED` | seal failure or management key mismatch (D6, D11); nothing returned or written |
  | 15 | `YUBIBLOB_ERR_NO_TOUCH` | the YubiKey was not touched in time |
  | 16 | `YUBIBLOB_ERR_FEW_PIN_ATTEMPTS` | 3 or fewer FIDO2 PIN attempts left, and the open flag not given |
  | 17 | `YUBIBLOB_ERR_REPLUG` | 3 wrong FIDO2 PINs in a row: unplug and replug |
  | 18 | `YUBIBLOB_ERR_NO_CREDENTIAL` | the store's FIDO2 credential is gone (FIDO2 reset) |
  | 19 | `YUBIBLOB_ERR_NO_FIDO2_ACCESS` | the FIDO2 device cannot be opened (permissions) |

### Documentation, format and release tasks

- `docs/YBLOB_FORMAT.md`: a section for post-quantum stores (this
  specification).
- **`file` magic database:** register the new magic, as the first one was
  (bug #666 at bugs.astron.com, merged June 2025, rule
  `0 lelong 0xF2ED5F0B yblob object store image data`), e.g.
  `0 lelong 0xF2EDF0B2 yblob post-quantum object store image data`; update
  `docs/YBLOB_FORMAT.md` §9 and the README.
- The next release's messages for older formats (D12): "made by a newer
  yb" for the new magic, and unknown trailers of any length as "newer
  version".
- Documentation: access to `/dev/hidraw*` (udev `uaccess` rules from
  systemd or libfido2; on NixOS `services.udev.packages = [ pkgs.libfido2
  ]`, plus group `plugdev` for users without a local seat, e.g. over SSH).
- **Install instructions** (READMEs, `contrib/keepassxc`): libfido2's
  development files become a build requirement (Debian/Ubuntu
  `libfido2-dev`, Fedora `libfido2-devel`, Homebrew `libfido2`), from the
  release that brings post-quantum stores.
- **READMEs** (GitHub, and crates.io for `yb`, `yb-core` and `yubiblob`):
  rework them with post-quantum stores; a poor README quickly shows in
  download counts.  Probably include a summary of the threat model (to be
  confirmed).

## Invariants

Each new or extended invariant gets its `docs/invariants/` file and its
regression tests during implementation (`scripts/check-invariants`
checks that the named tests exist).

**Existing invariants, extended to post-quantum stores:**

| # | Invariant | For post-quantum stores |
|---|---|---|
| 0001 | Interrupted writes lose nothing | unchanged (shared chunk machinery, "Writing") |
| 0002 | Reading never writes | `ls`, `fetch`, `fsck` (also `--seals`) never write |
| 0003 | Only complete chains are visible | unchanged |
| 0004 | A store refused for room writes nothing | also: a refused assertion writes nothing for its blob |
| 0005 | Existing stores stay readable | legacy stores, unchanged by this spec (G5) |
| 0006 | Tampering is detected before use | the seal replaces the signature: `yb fetch` checks every matched blob's checksum, seal and management key before returning or writing any, and returns nothing if one fails |
| 0007 | Commands act only on the selected YubiKey | also the FIDO2 device: matched by serial, else the only one present, else refused |
| 0008 | Format never strands blobs | the analogue of "slot key matches its certificate": a blob is only ever written under the credential the descriptor names, since the descriptor is written last, with the credential it was created with (0016) |
| 0009 | The management key is never lost | yb never changes the card's management key in a post-quantum store; `yb management-key set` checks the new key against the card before wrapping it |
| 0010 | No secrets behind factory credentials | format refuses the factory management key; FIDO2 has no factory PIN, and a post-quantum store cannot be used without one |
| 0011 | Errors reveal no identity or secret | also: no FIDO2 PIN, K2, derived key or credential ID in messages, nor the serial in the touch prompt |
| 0012 | A simulated YubiKey only in test builds | also the FIDO2 emulator (OpenSK), only with `test-fixture` |
| 0013 | The management key is held in zeroizing memory | also the FIDO2 PIN, every K2, every derived key and the unwrapped management key |

**New invariants:**

| # | Invariant | Regression tests (to write) |
|---|---|---|
| 0014 | **Older yb never writes to a post-quantum store** (D12): every object starts with the new magic, so the legacy parser stops before any write | parse every object of a post-quantum store with the legacy parser: refused; a legacy `store` and `rm` against it fail with no card write |
| 0015 | **The management key is checked before every write and every fetch** of a post-quantum store (D11) | after a simulated PIV reset (default key on the card), `store`, `fetch`, `rm` refuse with the tampering error, exit status 4, nothing written or returned |
| 0016 | **A post-quantum store exists only once its descriptor is written** (D13) | interrupt format at each step: every version refuses the half-written objects, and a new format succeeds |
| 0017 | **The FIDO2 PIN is never tried with 3 or fewer attempts left** without `--allow-low-pin-attempts`, and never tried as the PIV PIN or vice versa (D10) | emulator with 3 attempts left: refused, counter unchanged; with the flag: tried once |

**"Not guaranteed"** (`docs/invariants/README.md`) gains, for
post-quantum stores: confidentiality against a recording of the USB
traffic plus a future quantum computer (CTAP's ECDH PIN protocol, "Threat
model"); and, as for legacy stores, rollback of a blob to an older
genuine version, or of the whole store (non-goal).

## Code structure (proposal)

### Today

- `yb-core::orchestrator::store_blob` / `fetch_blob` / `remove_blob`
  take the PIV backend, the management key and the PIN as arguments, and
  call the legacy cryptography directly: `crypto::hybrid_encrypt` /
  `hybrid_decrypt` (PIV ECDH) and `signature::append_signature_trailer`
  (PIV ECDSA, a fixed 65-byte trailer, spec 0017/0033).
- `check_blob_signature` verifies against the slot certificate's key
  (`Context::get_public_key`).
- The callers (the `yb` commands, and `yubiblob` for the C API) each
  resolve the PIN (`Context::pin_fn`) and the management key
  (`Context::management_key_for_write`, from PRINTED), then call the
  orchestrator.  The order in `store_blob` is: encrypt, sync (writes),
  sign, write.

### Proposal

**1. One trait for what differs between store kinds.**  The orchestrator
keeps the chunk logic and becomes independent of the store kind; what it
asks of the protection goes through one trait, implemented twice:

```rust
/// What the store kind does to protect blobs (spec 0028).
pub trait Protection {
    /// Which PIN commands ask for, for prompts and `--pin-stdin`.
    fn pin_kind(&self) -> PinKind;            // Piv | Fido2
    /// Encrypt (optionally) and seal a blob, or sign it (legacy); also
    /// return the management key for the writes.  Post-quantum: one
    /// assertion, one touch.  Legacy: PIV ECDH + ECDSA, key from PRINTED.
    fn protect(&self, meta: &BlobMeta, payload: &[u8], encrypt: bool)
        -> Result<Protected>;                 // stored bytes, trailer, mgmt key
    /// Check the seal and decrypt; also check the management key (D11).
    /// Post-quantum: one assertion, one touch, for every blob.
    fn open(&self, meta: &BlobMeta, stored: &[u8], trailer: &[u8])
        -> Result<Vec<u8>>;
    /// The PIN-less check (`yb ls`, `yb fsck`): legacy signature, or
    /// post-quantum checksum (D5).
    fn quick_check(&self, meta: &BlobMeta, stored: &[u8], trailer: &[u8])
        -> SigVerdict;
    /// The management key alone (`yb rm`): post-quantum, one touch.
    fn management_key(&self) -> Result<MgmtKey>;
}
```

- `LegacyProtection` wraps today's code unchanged (ECDH, ECDSA, PRINTED).
- `PostQuantumProtection` holds the store descriptor and a `Fido2` device.
- `Store` gets a `kind` read from the header, and `Context` builds the
  matching `Protection`; callers (`yb`, `yubiblob`) stop resolving keys
  themselves.
- `store_blob` is reordered: `protect` first (no card writes), then the
  writes with the management key it returned.  The trailer after the
  blob's bytes holds what the kind needs (legacy: 65-byte signature;
  post-quantum: checksum, salt, seal).

**2. One FIDO2 module, one implementation.**  `yb-core::fido2`: the
hand-written libfido2 FFI (about 30 functions, as in the proof of
concept) and a small safe wrapper (`Fido2Device`: open, read the serial
with the vendor command, make credential, assertion with salts,
retries).  There is no
second backend: tests plug OpenSK **under** libfido2 through its I/O
functions, so the real FFI is exercised in every test.  (PIV, by
contrast, has `HardwarePiv` and `VirtualPiv`.)

**3. Touch and PIN prompts.**  `Context` gains a touch notifier, called
before each assertion ("Touch your YubiKey…" in `yb`; a C callback in
`yubiblob`), and `pin_fn` receives the `PinKind` for its wording (G6).
For `yubiblob` this is an API change (0.2.0).

**4. Tests.**
- Unit and orchestrator tests: OpenSK in-process (test-only crate, OpenSK
  from git, pinned), next to `VirtualPiv`.
- Command-line tests (`yb_cli_tests`, run the `yb` binary repeatedly with
  `YB_FIXTURE`): the test runner serves the emulator on a Unix socket
  (`yb_fido2_emulator::server`), named by `YB_FIDO2_SOCKET`; a `yb` built
  with `test-fixture` talks to it (`yb_core::fido2::socket`), so the
  emulator's state lasts for the whole run.  (Revised 2026-10-17 from a
  state file: `yb` is published and cannot depend on the emulator, which
  is not; the socket needs no dependency.)
- Hardware tests on YubiKeys, extended to post-quantum stores.

**5. Order of work.**
1. Introduce `Protection` with `LegacyProtection` only: a refactoring with
   no change of behavior, checked by the existing tests.
2. Add `yb-core::fido2` and the OpenSK test crate.
3. Add `PostQuantumProtection`, the store descriptor, the formats, and
   the commands (`yb format`, `yb management-key set`, `yb fsck`).
4. `yubiblob` 0.2.0 (touch callback, PIN kind), then KeePassXC.

## Tests

Three levels: unit and orchestrator tests against an in-process FIDO2
emulator; command-line tests with the emulator's state kept in a file;
hardware tests on YubiKeys (the reference).  The emulator was chosen on
2026-10-16 after reading the candidates' source code and running their
tests, then checked with a proof of concept.

**Hook.**  libfido2 can replace its device I/O
(`fido_dev_set_io_functions`: 64-byte HID reports, libfido2 still does
the CTAPHID framing) or its transport (`fido_dev_set_transport_functions`:
whole CTAPHID messages).  Either lets an emulator answer inside the test
process: no `/dev/uhid`, no root, works in the Nix build sandbox.
libfido2's own mocks only replay recorded traffic, which cannot answer
PIN protocol 2 or `hmac-secret` (fresh random key exchange each time).

**Candidates**, against what the spec needs (two salts, output depending
on the PIN, refused without touch, `credProtect` 3, non-resident
credentials, 8 PIN attempts with a power-cycle block after 3, ES256,
controllable touch):

| Candidate | Fits | Notes |
|---|---|---|
| **OpenSK** (Google, `libraries/opensk`, `TestEnv`) | **all** | Apache-2.0, active (2026-10-15); in-process `process_hid_packet`; pure Rust; not on crates.io (git/vendored), pins nightly but builds on stable; `TestEnv` is a test utility, not a stable API |
| fido-authenticator (Trussed: Nitrokey 3, Solo 2 firmware) | all | Apache-2.0 OR MIT, shipping firmware; harness must be copied (~800 lines, poller thread), large dependency tree (littlefs2-sys, bindgen), reset window behind a feature |
| fidolizer | most, with ~50 lines of patches | **no license**; never compiled on Linux; one CredRandom; wrong error for `credProtect` 3; advertises built-in UV |
| swpasskey | no | MIT, well tested, but refuses `credProtect` and non-resident credentials by design |
| soft-fido2 | no | AGPL-3.0 license file; no `hmac-secret` on non-resident credentials, one CredRandom, no UP requirement |
| softfido | no | dead since 2022, no clientPIN or extensions |

**Choice: OpenSK in-process**, behind `fido_dev_set_io_functions`, in a
test-only crate that depends on OpenSK from git, pinned to a commit
(OpenSK is not on crates.io; only its old `sk-cbor` 0.1.2 is).
Fallback: fido-authenticator.  Real YubiKeys stay the reference
(hardware tests).

**Proof of concept (2026-10-16):** ~300 lines of Rust: hand-written
libfido2 FFI, OpenSK's `TestEnv` answering libfido2's custom I/O
callbacks, a scriptable touch, and a "power cycle" that rebuilds the
authenticator on the same storage (`std::mem::take` of the `TestEnv`).
Built on stable Rust 1.98.1 with libfido2 1.17.0.  Results, compared
with the hardware results below:

| Check | OpenSK through libfido2 | YubiKey 5.7.1 |
|---|---|---|
| makeCredential, `hmac-secret`, non-resident | OK, 1 touch | OK, touch |
| getAssertion, `up = false`, no extension | OK, no touch, UP clear | same |
| getAssertion, `up = false`, `hmac-secret` | refused, `UNSUPPORTED_OPTION` | refused, `UP_REQUIRED` |
| `hmac-secret`, same salt twice | same output, 1 touch each | same |
| with PIN vs without PIN | different outputs, UV set / clear | same |
| `credProtect` 3 without PIN | refused, `NO_CREDENTIALS`, **no touch** | refused, `NO_CREDENTIALS`, after a touch |
| `credProtect` 3 with PIN | OK | OK |
| two salts | 64 bytes, first half = single-salt output | same (2026-10-17) |
| touch refused | `OPERATION_DENIED` | `OPERATION_DENIED` after ~30 s, no PIN attempt used (2026-10-17) |
| output after a power cycle | unchanged | unchanged (2026-10-17) |
| ES256 signature over yb's `clientDataHash` | verifies (`fido_assert_verify`) | not tested |
| PIN attempts | 8; 3rd wrong PIN in a row: `PIN_AUTH_BLOCKED` until power cycle; counter kept (5); correct PIN resets to 8 | 8, replug after 3 (documented) |
| credential ID size | 241 bytes | **64 bytes** (2026-10-17) |

Differences that matter for yb: none.  yb always asks for a touch
(`up = true`), so the different refusal codes for `up = false` do not
arise; yb must not assume a credential ID size (241 bytes here, 64 on
the YubiKey).  (The ES256 row is kept for the record: yb no longer uses
signatures, D5.)

**Hardware checks (2026-10-17)**, YubiKey 5 NFC, firmware 5.7.1, through
libfido2 with `attic/poc-fido-hw` (one non-resident credential, nothing
stored on the key): credential ID 64 bytes; one salt 32 bytes; two salts
64 bytes, the first half equal to the one-salt output; no touch for 30 s
gives `OPERATION_DENIED` without using a PIN attempt; the output is
unchanged after unplugging and replugging.

**State across processes.**  The command-line tests run the `yb` binary
repeatedly, so the emulator's state must survive between processes, like
the PIV fixture file.  **Checked** (2026-10-16, `attic/poc-opensk`):
OpenSK's public `Persist` API (`iter`, `find`, `insert`) saves and
restores it.  After a PIN, two credentials and some assertions the state is
3 entries, 149 bytes; a brand-new authenticator restored from them gives
the same `hmac-secret` output and the PIN attempts counter; a fresh
authenticator without them does not know the credentials
(`NO_CREDENTIALS`).  The fixture can store these entries in a file.

## Finding the FIDO2 side of the selected YubiKey

yb selects a YubiKey by serial over PC/SC; FIDO2 devices are HID devices,
and CTAP does not report a serial.  With several keys plugged in, yb must
not ask the wrong one for the PIN (wrong attempts are not refundable).

A YubiKey appears as two devices with nothing in common: a PIV reader
(PC/SC) and a FIDO2 device (USB HID).  yb must pair the right two.
Rules (revised 2026-10-17):

| Situation | FIDO2 device | Its PIV store |
|---|---|---|
| `--serial` given | by serial (vendor command, below) | by serial |
| one YubiKey connected | that one | that one |
| several, no `--serial` | **touch selection** (no PIN) | by serial; where the serial cannot be read (Windows), by credential (below) |

- **Touch selection:** CTAP 2.1 `authenticatorSelection` (libfido2
  `fido_dev_get_touch_begin` / `fido_dev_get_touch_status`): every key
  blinks, the one touched answers; no PIN, so no attempt is ever spent on
  the wrong key.  One extra touch, only when several keys are connected
  and no `--serial` is given (G3 holds otherwise).
- **By credential:** read the descriptors of every candidate store (no
  PIN), then one assertion on the chosen FIDO2 device, with the PIN,
  **without a touch** (`up = false`) and without extension, listing all
  their credential IDs: the key only recognizes the one it created, and
  names it, which designates its store (`fido2::Device::find_credential`).
  **Checked on hardware** (2026-10-17, YubiKey 5.7.1, `credProtect` 3):
  answered in 0.2 s without a touch with the right ID among two; "no
  credentials" for a stranger's ID only; no PIN attempt used.
- Matching USB devices on Linux was rejected: likely to need privileges.
- Never send the PIN to several FIDO2 devices in turn: a wrong PIN uses
  one of a key's 8 attempts for good.

- ykman (`yubikit/management.py`, `_ManagementCtapBackend`) sends Yubico's
  vendor CTAPHID command `READ_CONFIG` (`0x42`, `0xC2` on the wire) with
  the page number; the reply is the device info, a length byte then TLVs:
  tag `0x02` serial, `0x05` firmware version, `0x10` "more data".
- libfido2 has no public call for raw or vendor commands, so yb does this
  exchange itself (CTAPHID INIT, then `READ_CONFIG`) on the hidraw path
  libfido2 lists (`fido_dev_info_path`), with the same permissions as
  libfido2: no root.  The test emulator answers it with a configured
  serial.
- **Checked on hardware** (2026-10-16, YubiKey 5 NFC, firmware 5.7.1):
  `attic/poc-fido-serial/fido_serial.py` (standard-library Python, the
  same exchange) read serial 32283437 and firmware 5.7.1, as ykman reports
  over PC/SC.  On the test VM `/dev/hidraw*` is root-only, so it ran with
  sudo; desktops grant access through udev `uaccess` rules (systemd
  `60-fido-id.rules`, or libfido2's rules, which also use group
  `plugdev`).
- **macOS:** the same vendor command works there: python-fido2, which
  ykman uses, sends raw CTAPHID reports through IOKit
  (`IOHIDDeviceSetReport` and input-report callbacks;
  `fido2/hid/macos.py`), and ykman reads the serial this way on macOS
  too.  So yb needs a raw HID channel on both systems, not `/dev/hidraw`
  specifically: e.g. the `hidapi` crate (hidraw on Linux, IOHIDManager on
  macOS).  To verify on a Mac.
- yb's implementation is Rust, in `yb-core::fido2`.

## Compatibility with older yb

Checked in yb 0.6's code (2026-10-16).

**The problem.**  `check_blob_signature` treats a signature trailer whose
length is not 65 bytes as **CORRUPTED** (unless it is all zeros); the
"written by a newer yb" verdict (`NewerVersion`) only applies to 65-byte
trailers with an unknown version byte.  So if post-quantum blobs carry a
longer trailer (authData, signature, seal), yb 0.6 shows them as
CORRUPTED in `yb ls` and `yb fsck`, and `yb fetch` refuses them ("corrupted
or tampered with; nothing was fetched").  The 0.5 → 0.6 problem again.

Effects yb 0.6 would have had on a post-quantum store with the same magic
(`STORE_KEY_SLOT` holding a value with no key or certificate):

- signatures cannot be verified (no certificate);
- `yb store`: an encrypted store fails at once (no public key); an
  unencrypted one fails when signing, before writing the blob (only
  cleanup writes happen, and only with a management key it can find);
- `yb rm` works if yb 0.6 finds a management key: only through a ykman
  copy in PRINTED and the PIV PIN (D7);
- `yb fetch` of an encrypted blob would ask for the PIV PIN, then stop on
  the payload's unknown version (no PIN attempt is used: the version is
  checked first).

**Decision (2026-10-16):** neither keeping the trailer at 65 bytes so
that yb 0.6 reports "newer version" (it would only buy nicer messages: it
could still not fetch anything), nor a release that must reach every user
first.  Older yb does not need to read post-quantum stores, only to leave
them alone: a new magic (D12) makes it stop before any write.

## ANSSI assessment

Research 2026-10-17, from ANSSI's own documents (quotes verbatim; English
translations ours).  Question: does ANSSI's requirement of **hybridation**
(classical + post-quantum) apply to post-quantum stores, whose
confidentiality rests only on symmetric cryptography?

### What ANSSI says

- **Hybridation is about asymmetric algorithms.**  ANSSI defines it as
  combining post-quantum *asymmetric* algorithms with well-studied
  pre-quantum *asymmetric* ones: "L'hybridation consiste à combiner des
  algorithmes asymétriques post-quantiques avec une cryptographie
  asymétrique pré-quantique bien connue et bien étudiée" (follow-up
  position paper, December 2023, §1.1; same definition in the PQC FAQ).
  Its purpose is non-regression: a young post-quantum algorithm may yet
  be broken classically.
- **Only where post-quantum protection is relevant:** "hybridation is
  necessary only if a post-quantum protection is relevant" (2023,
  footnote 1).  The only post-quantum algorithms exempted are hash-based
  signatures (SLH-DSA, XMSS, LMS; FAQ).
- **Symmetric cryptography is quantum-safe with large enough
  parameters** (Grover's speed-up only).  The current reference, *Guide
  des mécanismes cryptographiques* ANSSI-PG-083 **v3.00 (20 March 2026)**,
  which now takes the quantum threat into account, states:
  - "AES-192 et AES-256 sont conformes à la règle et à la recommandation"
    (§2.1.1, RecoPQTailleCléSym: at least 192-bit symmetric keys when
    post-quantum security is sought);
  - "Le mécanisme de chiffrement authentifié AES-GCM est conforme …  Il
    est particulièrement important de garantir qu'un même IV n'est jamais
    réutilisé sous une même clé" (§2.1.2.1);
  - "Lorsqu'une résistance post-quantique est visée, il est donc suffisant
    que cette fonction de hachage produise des empreintes de 256 bits pour
    satisfaire à la fois la règle RèglePQMAC et la recommandation
    RecoPQMAC" and "Le mode d'intégrité HMAC utilisant SHA-256 … est
    conforme" (§2.1.3).
  - The guide names no KDF; HKDF-SHA256 is built on HMAC-SHA256, so the
    same reasoning applies (our inference).
- **Pre-shared symmetric keys** are discussed only *combined with*
  (EC)DH in network protocols (IPsec, TLS 1.3; technical sheets
  ANSSI-FT-115/117, February 2026), as a "temporary" measure, with two
  caveats: the key must be shared by two parties only, and it gives no
  forward secrecy against a quantum adversary.  Of IPsec's symmetric layer
  ESP, ANSSI notes it "n'est pas impacté par la menace quantique, puisqu'il
  n'utilise pas de mécanismes asymétriques… Toutefois, la sécurité des
  clés utilisées dans ce protocole repose sur le protocole IKEv2" (not
  affected, since it uses no asymmetric mechanism; but its keys' security
  rests on the key exchange).
- **Long-term data:** "En cas d'utilisation prévue au-delà du 1er janvier
  2030 … ou de l'existence d'un risque d'attaque rétroactive …, il est
  recommandé de viser une sécurité post-quantique" (PG-083 v3.00 §2,
  RecoSécuLongTerme): exactly yb's "harvest now, decrypt later" problem.
- **Legal status:** "Les préconisations de l'ANSSI sur la PQC (y compris
  sur l'hybridation) n'ont pas à ce jour de caractère d'obligation
  réglementaire" (FAQ), except in the regulated perimeter (classified and
  "Diffusion Restreinte" data, vital operators, ANSSI product
  certification and qualification, with PQC requirements for
  qualification "à partir de 2027").
- The EU roadmap (NIS Cooperation Group, June 2025, co-chaired by France)
  agrees: hybrid means post-quantum + quantum-vulnerable *public-key*
  algorithms, "quantum-safe" also covers symmetric algorithms, and "using
  symmetric methods instead of public-key cryptography are also worthwhile
  to consider".

### Assessment for post-quantum stores

1. **Confidentiality: the hybrid requirement does not apply.**  There is
   no post-quantum asymmetric algorithm to hybridize: blob keys come from
   HMAC-SHA256 with a 256-bit key on the card, then HKDF-SHA256 and
   AES-256-GCM, all listed as meeting PG-083's post-quantum rules and
   recommendations.  ANSSI's pre-shared-key caveats map poorly: the
   card's key is used by one party only (the YubiKey), never leaves it,
   and nothing is negotiated; forward secrecy is defined for sessions,
   not data at rest.  D3 stands.
2. **Integrity: no classical signature remains.**  With D5 revised,
   post-quantum stores carry no ECDSA signature, only a checksum (not a
   security mechanism) and the seal (HMAC-SHA256 or AES-GCM with a
   K2-derived key), both PG-083-compliant.  Had the signature stayed, it
   would have been acceptable only as long as no post-quantum claim
   rested on it (ECDSA meets the classical rule, not the post-quantum
   one).
3. **The real gap is CTAP's PIN protocol, and it is a missing protection,
   not a hybridation issue.**  The `hmac-secret` salts and outputs, and
   the PIN, cross USB protected by ECDH P-256: a quantum-vulnerable key
   exchange protecting the very key material, as IKEv2 protects ESP's
   keys in ANSSI's IPsec sheet.  ANSSI says nothing about local links,
   USB or CTAP, and leaves this to the risk analysis.  Ours is in "Threat
   model": exploiting it needs a recording of the USB traffic (or a
   position on the host, which reads the keys in clear anyway), and CTAP
   offers no post-quantum PIN protocol yet (up to CTAP 2.3).  So yb must
   not claim post-quantum confidentiality without this caveat.
4. **Parameters to respect:** 256-bit keys everywhere (above the 192-bit
   recommendation); AES-GCM nonces never reused under a key (each blob
   write uses a fresh salt, hence a fresh key; the management key is
   rewrapped with a fresh random nonce); HMAC-SHA256 (explicitly
   compliant).  PG-083's recommendation of hash outputs of at least 384
   bits (RecoPQHachage) concerns hashes used for security (collision
   resistance); the checksum (D5) is not a security mechanism, and HMAC
   is covered by RecoPQMAC.

**Wording for documentation:** "Post-quantum stores protect blobs with
symmetric cryptography only (HMAC-SHA256 on the YubiKey, HKDF,
AES-256-GCM), which ANSSI considers quantum-resistant; no hybrid scheme is
needed.
One classical element remains: the YubiKey protects the exchange with the
computer over USB with ECDH P-256 (the FIDO2 PIN protocol), which a
recording of that USB traffic and a future quantum computer could
break."

Sources:
- ANSSI, *ANSSI views on the Post-Quantum Cryptography transition*,
  2022-03-30:
  <https://messervices.cyber.gouv.fr/documents-guides/EN_Position.pdf>
- ANSSI, *Follow-up position paper on post-quantum cryptography*,
  2023-12-21:
  <https://messervices.cyber.gouv.fr/documents-guides/follow_up_position_paper_on_post_quantum_cryptography.pdf>
- ANSSI, PQC FAQ:
  <https://cyber.gouv.fr/enjeux-technologiques/cryptographie-post-quantique/faq-pqc/>
- ANSSI-PG-083 v3.00, *Guide des mécanismes cryptographiques*,
  2026-03-20:
  <https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-mecanismes-crypto-3.00.pdf>
- ANSSI-FT-117, *Transition post-quantique d'IPsec*, 2026-02-02:
  <https://messervices.cyber.gouv.fr/documents-guides/transition_post_quantique_ipsec.pdf>
- ANSSI-FT-115, *Transition post-quantique de TLS 1.3*, 2026-02-02:
  <https://messervices.cyber.gouv.fr/documents-guides/transition_post_quantique_tls_1_3.pdf>
- NIS Cooperation Group, *A Coordinated Implementation Roadmap for the
  Transition to Post-Quantum Cryptography*, v1.1, 2025-06-11.

## Open questions

None at this stage.

## Hardware results (YubiKey 5.7.1, 2026-09-29)

**Touch cannot be skipped.**  CTAP 2.1 requires the authenticator to
refuse `hmac-secret` without user presence; YubiKeys do
(`systemd-cryptenroll --fido2-with-user-presence=no` fails on a YubiKey
for this reason, systemd issue #23632).  FIDO2 PIN not set:

| Request | Result |
|---|---|
| makeCredential, `up = false` | refused, `CTAP2_ERR_INVALID_OPTION` |
| makeCredential with `hmac-secret` | needed a touch |
| getAssertion, `up = false`, no extension | accepted without touch (UP flag clear) |
| getAssertion, `up = false`, `hmac-secret` | refused, `CTAP2_ERR_UP_REQUIRED` |
| getAssertion, `up = true`, `hmac-secret` (twice, same salt) | needed a touch each time; same 32-byte output |

The credential was not resident.

**The PIN is bound into the output** (FIDO2 PIN set; one salt
throughout).  The authenticator keeps two HMAC keys per credential,
`CredRandomWithUV` and `CredRandomWithoutUV`:

| Request | Result |
|---|---|
| credential 1, `hmac-secret` with the PIN | touch; 32-byte output, UV flag set |
| credential 1, `hmac-secret` without the PIN | touch; 32-byte output, UV flag clear, **different** from the one with the PIN |
| credential 2 (`credProtect` 3), without the PIN | touch, then refused: `CTAP2_ERR_NO_CREDENTIALS` |
| credential 2 (`credProtect` 3), with the PIN | touch; 32-byte output |

So a request without the PIN yields a useless value, and with
`credProtect` 3 the credential behaves as if it did not exist.  The
refused request still asked for a touch first.

## YubiKey FIDO2 facts (research, 2026-10-16)

- **Credential ID:** Yubico wraps the credential's key and metadata with
  AES-256-CCM under a device master key (U2F key generation page: 64-byte
  key handles; FIPS 140-2 policy for firmware 5.4: "Wrapping Key — AES-256
  CCM", "Offline Key — HMAC SHA256 … HMAC-Secret").  No FIDO2 length is
  documented; metadata gives `maxCredentialIdLength` 128.  **Measured:
  64 bytes** (YubiKey 5.7.1, non-resident, `credProtect` 3, 2026-10-17).
  yb treats the ID as opaque, up to 255 bytes (OpenSK's are 241).
- **FIDO2 reset** regenerates the master key: earlier non-resident IDs and
  their `hmac-secret` outputs are gone (Yubico U2F page; FIPS policy
  §2.6.3).  Confirms D4 and "Losing the store".
- **PIN:** 8 attempts in total, replug after 3 in a row; minimum length 4
  (6 with PIN complexity, 8 on FIPS 5.7.4); `minPinLength` and
  `ykman fido config set-min-length` since firmware 5.7.4.  PIN protocol 2
  since firmware 5.4.
- **Resident slots:** 25; 100 since firmware 5.7.4.
- **Signature counter:** global for U2F (documented); assumed global for
  FIDO2 (not documented).  yb does not rely on it.
- **CTAP 2.3** (proposed standard, 2026-02-26) still defines only PIN
  protocols 1 and 2, both P-256 ECDH; FIDO's post-quantum work is
  exploratory, with no timeline.
- **libfido2** 1.17.0 in nixpkgs, BSD-2-Clause; ships udev rules
  (`70-u2f.rules`, `uaccess`).

## State of YubiKeys (research, 2026-09)

- No shipping Yubico product supports a post-quantum algorithm (PIV,
  OpenPGP, FIDO2, YubiHSM 2).  Firmware 5.7 added RSA 3072/4096, Ed25519
  and X25519 to PIV; firmware 5.8 (reported GA 2026-07-21) makes no
  material PIV change.
- Yubico demonstrated a prototype key with post-quantum signatures in
  October 2025 ("prototype ≠ product"), and states that post-quantum
  algorithms need **new hardware**.  No product date.
- NIST (reported 2026-06-12, to be checked): working drafts of SP 800-73
  Parts 1–2 and SP 800-78 add ML-KEM and ML-DSA to PIV in a "dual-stack"
  model.  No timeline.

## Options considered

PIV itself has no usable symmetric key: every PIV slot key is asymmetric
(breakable by a quantum computer, public key readable without the PIN),
and the management key is only checked by the card, never used to compute
for the host.  The candidates for a post-quantum secret:

| Candidate | Key | Transport | Guarded by | Touch | Stealable? |
|---|---|---|---|---|---|
| **A. Secret in PRINTED** | 32-byte secret, read by the host | PC/SC (PIV) | PIV PIN | no | **yes**: whoever reads it once keeps it |
| **OTP challenge-response** | HMAC-SHA1, 20-byte key | PC/SC or HID | **nothing** | optional | no |
| **OATH** | HMAC-SHA256, 32-byte key | PC/SC | optional password, **no retry limit** | optional | no |
| **C. FIDO2 hmac-secret** (chosen) | HMAC-SHA256, 32-byte key | USB HID (CTAP2) | **FIDO2 PIN**, 8 tries, bound into the output | **always** | no |

With OTP, or OATH without a password, someone holding the YubiKey can ask
for each blob's HMAC on the spot; an OATH password can be guessed without
limit.  Option A was the fallback within PIV; it was rejected because the
secret can be stolen once and kept, and because ykman silently destroys it
(measured on hardware: ykman 5.9.1 keeps only tag `89` of PRINTED and
rebuilds or deletes the object when it changes the management key; PRINTED
accepted up to 3034 bytes on firmware 5.4.3 and 5.7.1).

**B. On-card ML-KEM + ECDH** (hybrid, PIV dual-stack) remains the long-term
target, once YubiKeys support it; it would keep G2 without relying on
FIDO2.

## References

- [spec 0017](0017-blob-integrity-signature.md) — blob signatures
- [spec 0021](0021-firmware-5.7-management-key.md) — PRINTED and ADMIN DATA layout
- [spec 0022](0022-format-sequence.md) — PRINTED tags `89` / `8A`, guided format
- [spec 0027](0027-management-key-rotation.md) — management key rotation
- [spec 0033](0033-signed-blob-metadata.md) — signature version 2
- [spec 0039](0039-c-api.md) — libyubiblob
- [docs/YBLOB_FORMAT.md](../YBLOB_FORMAT.md) — object, encryption and signature formats
- CTAP 2.1, `hmac-secret` (§12.5), PIN/UV auth protocols:
  <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html>
- systemd issue #23632: <https://github.com/systemd/systemd/issues/23632>
- Yubico blog, 2025-10-21:
  <https://www.yubico.com/blog/future-proofing-authentication-a-look-at-the-future-of-post-quantum-cryptography/>
- NIST PIV post-quantum drafts: <https://pages.nist.gov/piv-standards/pqc-overview/>
- libfido2: <https://developers.yubico.com/libfido2/>
- Emulator candidates: <https://github.com/19h/fidolizer>,
  <https://github.com/madeye/swpasskey>,
  <https://lib.rs/crates/soft-fido2-ctap>
