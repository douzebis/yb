# YubiKey PIV APDU Reference

Sources studied: yubico-piv-tool `lib/ykpiv.c` (C), ykman `yubikit/piv.py` (Python),
and the current Rust implementation in `rust/yb-core/src/piv/hardware.rs`.

---

## Use cases required by yb

| # | Operation | INS |
|---|-----------|-----|
| 1 | List devices (serial + version) | `F8` / `FD` |
| 2 | Read object | `CB` |
| 3 | Write object (direct mgmt key) | `DB` |
| 4 | Write object (PIN-protected mgmt key) | `20` + `CB` + `87` + `DB` |
| 5 | Verify PIN | `20` |
| 6 | ECDH key agreement | `87` (tag `85`) |
| 7 | Read certificate | `CB` |
| 8 | Generate EC key pair | `47` |
| 9 | Generate + import self-signed certificate | `87` (sign) + `DB` |
| 10 | Default-credential check | `F7` |

---

## Instruction bytes

```
SELECT          A4   standard
VERIFY          20   standard
CHANGE_REF      24   standard
RESET_RETRY     2C   standard
GENERATE_KEY    47   standard
AUTHENTICATE    87   standard  (sign, ECDH, mgmt auth)
GET_DATA        CB   standard
PUT_DATA        DB   standard
GET_RESPONSE    C0   standard

GET_SERIAL      F8   Yubico vendor
GET_VERSION     FD   Yubico vendor
IMPORT_KEY      FE   Yubico vendor
SET_MGMKEY      FF   Yubico vendor
SET_PIN_RETRIES FA   Yubico vendor
RESET_PIV       FB   Yubico vendor
GET_METADATA    F7   Yubico vendor
ATTEST          F9   Yubico vendor
```

---

## Operation 1 — SELECT PIV applet

```
00 A4 04 00 05  A0 00 00 03 08
```

Always the first APDU in any session. Must precede all PIV operations.

---

## Operation 2 — GET_VERSION (INS=FD)

```
00 FD 00 00 00
```

Response: 3 bytes `MM mm pp` (major, minor, patch). SW=9000.

---

## Operation 3 — GET_SERIAL (INS=F8)

YK5+ (firmware major ≥ 5):
```
00 F8 00 00 00
```
Response: 4 bytes big-endian uint32. SW=9000.

---

## Operation 4 — GET DATA (INS=CB)

```
CLA=00  INS=CB  P1=3F  P2=FF  Lc=05
  5C 03 <3-byte-object-id>
Le=00
```

Response: `53 <BER-len> <value-bytes>` SW=9000
Caller strips the `53` wrapper to get the raw value.

For SW=61xx: issue `00 C0 00 00 NN` (GET RESPONSE) and append; loop until SW=9000.

### Common object IDs

```
CHUID           5F C1 02
AUTHENTICATION  5F C1 05   (slot 9A)
SIGNATURE       5F C1 0A   (slot 9C)
KEY_MANAGEMENT  5F C1 0B   (slot 9D)
CARD_AUTH       5F C1 01   (slot 9E)
PRINTED         5F C1 09   (PIN-protected mgmt key — ykman repurposes)
RETIRED 82      5F C1 0D
RETIRED 83..95  5F C1 0E .. 5F C1 20
PIVMAN_DATA     5F FF 00   (ykman flags)
DISCOVERY       7E         (single-byte ID)
```

---

## Operation 5 — PUT DATA (INS=DB)

```
CLA INS=DB  P1=3F  P2=FF
  5C 03 <3-byte-object-id>
  53 <BER-len> <value-bytes>
```

**Payload size.** A typical cert is 1–3 KB. Total PUT DATA payload is:
`5 (tag list) + 1–3 (53 + length) + cert_len ≈ 1000–3100 bytes`.

**Command chaining (mandatory).** Both yubico-piv-tool (C) and ykman (Python, over NFC
or when forced-short) split into 255-byte chunks with `CLA |= 0x10` on all but the last:

```
10 DB 3F FF FF <255 bytes>   ...repeated...
00 DB 3F FF <rem> <last chunk>
```

ykman over USB uses extended Lc (`00 NN NN`) in a single APDU instead; yubico-piv-tool
never uses extended Lc.

**Transaction requirement (pcsclite).** pcsclite requires `SCardBeginTransaction` before
`SCardTransmit` for multi-APDU commands. yubico-piv-tool wraps every public API call in
`SCardBeginTransaction` / `SCardEndTransaction(SCARD_LEAVE_CARD)`. Our Rust implementation
wraps `put_data` in `self.card.transaction()` for the same reason.

**BER-TLV length encoding for the `53` wrapper:**
```
0–127 bytes:      53 LL
128–255 bytes:    53 81 LL
256–65535 bytes:  53 82 HH LL
```

---

## Operation 6 — VERIFY PIN (INS=20)

```
00 20 00 80 08  <8-byte PIN padded with 0xFF>
```

- PIN is ASCII/UTF-8, 6–8 characters max.
- Always padded on the right to exactly 8 bytes with `0xFF`.
- P2=`80` = user PIN reference.

**Query retry count (no PIN):**
```
00 20 00 80
```
Response SW: `63 Cx` where `x` = retries remaining; `69 83` = PIN blocked.

**SW decoding:**
```
90 00              success
63 Cx              wrong PIN, x retries remaining (0x63C0 = 0 left, 0x63C3 = 3 left)
69 83              PIN blocked (SW_ERR_AUTH_BLOCKED)
69 82              security condition not satisfied
```

---

## Operation 7 — Management key mutual authentication (INS=87)

Two-APDU exchange. P1 = algorithm byte, P2 = `9B` (SLOT_CARD_MGMT).

**Algorithm bytes:**
```
3DES    03   block size 8 bytes   key length 24 bytes
AES-128 08   block size 16 bytes  key length 16 bytes
AES-192 0A   block size 16 bytes  key length 24 bytes
AES-256 0C   block size 16 bytes  key length 32 bytes
```

**Step 1 — request witness (card encrypts a random nonce):**
```
00 87 <algo> 9B 04  7C 02 80 00
```
Response: `7C <n> 80 <n> <encrypted_witness>`

**Step 2 — send decrypted witness + our challenge:**
```
00 87 <algo> 9B <Lc>
  7C <n>
    80 <clen> <ECB_decrypt(key, witness)>
    81 <clen> <random_challenge>
```
Response: `7C <n> 82 <clen> <ECB_encrypt(key, our_challenge)>`

**Local verification:** encrypt `our_challenge` with the mgmt key and compare to the card's
response. No third APDU.

**Algorithm auto-detection:** call GET_METADATA (INS=F7, P2=9B) first; if SW=6A88 or 6D00
(slot unknown or INS not supported), fall back to 3DES.

---

## Operation 8 — ECDH / EC key agreement (INS=87, tag 85)

```
00 87 <algo> <slot> <Lc>
  7C <n>
    82 00               (empty response placeholder)
    85 <peer_len> <uncompressed_peer_point>
Le=00
```

Algo `11` = P-256, peer point = 65 bytes (`04 || X || Y`).
Algo `14` = P-384, peer point = 97 bytes.

Response: `7C <n> 82 <n> <shared_secret_bytes>` (X-coordinate only, per NIST SP 800-73-4).

The distinguishing feature vs signing is tag `85` (exponentiation) vs `81` (challenge).

---

## Operation 9 — EC sign (INS=87, tag 81)

```
00 87 <algo> <slot> <Lc>
  7C <n>
    82 00               (empty response placeholder)
    81 <digest_len> <digest>
Le=00
```

For P-256: algo=`11`, digest = SHA-256 (32 bytes).

Response: `7C <n> 82 <n> <DER_encoded_signature>`

PIN must be verified first (unless pin_policy=NEVER).

---

## Operation 10 — GENERATE ASYMMETRIC KEY (INS=47)

```
00 47 00 <slot> <Lc>
  AC <n>
    80 01 <algo>          algorithm selector
    [AA 01 <pin_policy>]  optional
    [AB 01 <touch_policy>] optional
Le=00
```

Algo `11` = P-256 (minimum payload: `AC 03 80 01 11`, Lc=5).

Response:
```
7F 49 <n>
  86 <point_len> <uncompressed_EC_point>   (P-256: 65 bytes)
```

For RSA:
```
7F 49 <n>
  81 <mod_len>  <modulus N>
  82 <exp_len>  <public exponent e>
```

Management key must be authenticated before this command.

---

## Operation 11 — GET_METADATA (INS=F7)

```
00 F7 00 <target>
```

`target` = slot byte (e.g. `9B` for mgmt key, `9A`, `82`, `80` for PIN, etc.)

Response: flat BER-TLV sequence:
```
01 01 <algo>               algorithm / key type
02 02 <pin_pol> <touch_pol> policies
03 01 <origin>             01=generated, 02=imported
04 <n> <pubkey_data>       encoded public key (same sub-TLV as 7F49)
05 01 <is_default>         00=no, nonzero=yes (mgmt key only, fw≥5.3)
06 02 <total> <remaining>  PIN attempt counters
```

Requires firmware ≥ 5.3.0. SW=6A88 or 6D00 on older firmware — callers must handle.

---

## Operation 12 — Certificate TLV structure

Object value (inner bytes after stripping `53 <len>`):
```
70 <cert_len> <DER_certificate>   cert data
71 01 <info>                       00=plain, 01=gzip-compressed
FE 00                              LRC (always present, always empty)
```

To write: encode as above, then PUT DATA to the slot's object ID.
To read: GET DATA, strip `53`, parse TLV for tag `70`.

---

## Operation 13 — PIN-protected management key (ykman convention)

ykman stores the management key in the PRINTED object (`5F C1 09`), accessible only after
PIN verification.

PRINTED object value (inner bytes after `53 <len>`):
```
88 <n>
  89 <key_len> <raw_management_key_bytes>
```

Retrieval sequence (must be a single PC/SC session):
1. SELECT PIV
2. VERIFY PIN — `00 20 00 80 08 <padded_pin>`
3. GET DATA `5F C1 09` — parse `88 → 89 → key_bytes`
4. GENERAL AUTHENTICATE with recovered key bytes

The PIN verification state is lost if the session is closed between steps 2 and 3.

---

## Verification: Rust hardware.rs vs authoritative sources

### Confirmed correct

| Operation | Notes |
|-----------|-------|
| SELECT PIV | Bytes `00 A4 04 00 05 A0 00 00 03 08` — correct |
| GET DATA | CLA/INS/P1/P2 = `00 CB 3F FF`, tag-list `5C 03`, `53` wrapper stripped — correct |
| GET RESPONSE | `00 C0 00 00 NN` loop on SW=61xx — correct |
| VERIFY PIN | Padded to 8 bytes with `0xFF`, P2=`80` — correct |
| MGMT AUTH step 1 | `7C 02 80 00` witness request — correct |
| MGMT AUTH step 2 | `7C [80 witness][81 challenge]`, verify `82` response — correct |
| ECB decrypt/encrypt | 3DES (24-byte key, block 8) and AES-128/256 — correct |
| ECDH | tag `85` for peer point, tag `82` for response — correct |
| SIGN | tag `82 00` placeholder + tag `81` for digest — correct |
| SHA-256 before SIGN | rcgen passes TBS bytes; `sign()` calls `Sha256::digest` — correct |
| GENERATE KEY | `AC 03 80 01 11`, response tag `7F 49 → 86` — correct |
| PUT DATA chaining | `CLA |= 0x10` on non-final chunks, 255-byte max chunk — correct |
| PUT DATA transaction | `self.card.transaction()` wraps all PUT DATA chunks — correct |
| Cert TLV write | `70 <der> 71 01 00 FE 00` inside `53` wrapper — correct |
| Cert TLV read | parse tag `70` from `53`-stripped response — correct |
| PRINTED object | `88 → 89 → key_bytes` parse and retrieval in one session — correct |
| BER-TLV lengths | 1/2/3-byte encoding matching yubico-piv-tool — correct |
| slot_to_object_id | All 20 retired slots 0x82–0x95 mapped — correct |

### Discrepancies and gaps

**1. AES-192 not supported in authenticate_management_key (minor gap)**

`authenticate_management_key` maps key lengths:
```rust
24 => (0x03, 8)   // 3DES
16 => (0x08, 16)  // AES-128
32 => (0x0E, 16)  // AES-256  ← wrong P1: should be 0x0C
```

- AES-192 (24-byte key) is ambiguous with 3DES (also 24 bytes) — correct to prefer 3DES.
- AES-256 P1: used `0x0E` but correct value is `0x0C` per yubico-piv-tool constants.

**2. Algorithm auto-detection not implemented**

yubico-piv-tool calls GET_METADATA (INS=F7) before every management key auth to determine
whether the slot holds 3DES or AES. Our code skips this and decodes purely from key byte
length. This works for the default 3DES key and for keys of unambiguous length (16 or 32
bytes), but would fail to distinguish AES-192 from 3DES.

**3. Le byte after GET DATA APDU**

Our GET DATA APDU includes a trailing `0x00` Le byte. yubico-piv-tool adds Le only for
T=1 protocol; ykman always omits it at the PIV layer (transport adds it). In practice the
card ignores a spurious `Le=00` for short responses, so this is benign on real hardware.

**4. general_authenticate_ecdh omits `82 00` response placeholder**

Our ECDH payload:
```rust
let inner = encode_tlv(0x85, peer_point);    // no 82 00
let outer = encode_tlv(0x7C, &inner);
```

ykman and yubico-piv-tool both include `82 00` before the `85` tag:
```
7C <n>  82 00  85 <n> <peer_point>
```

On current YubiKey firmware this works without the placeholder (the card infers the
response slot), but including `82 00` is the spec-compliant form. Same applies to
`general_authenticate_sign` which does include `82 00` — so there is an inconsistency
between the two methods.

**5. GET_METADATA (INS=F7) not implemented**

No Rust code issues GET_METADATA. It is not needed for yb's current use cases but would
be required for default-credential detection (use case #10 in the list above). The
emulated backend returns a minimal stub.
