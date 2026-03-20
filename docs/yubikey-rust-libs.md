# YubiKey Rust Library Landscape

*Research date: 2026-03-20*

## Goal

Identify Rust crates that can replace the three CLI tools currently invoked
by the `yb` Rust port:

| CLI tool | Purpose in `yb` |
|---|---|
| `yubico-piv-tool` | List devices, read/write PIV objects, PIN verify, cert ops, mgmt-key auth |
| `ykman` | Read PIN-protected management key from PRINTED object (0x5FC109) |
| `pkcs11-tool` | ECDH key agreement using on-card P-256 key (decryption path) |

---

## Crates Found

### 1. `yubikey` v0.8.0 — primary candidate

- **Repository:** https://github.com/iqlusioninc/yubikey.rs
- **Maintainer:** iqlusion (Tony Arcieri); derived from Yubico's own
  `yubico-piv-tool` C code. Not an official Yubico product, but the
  community de facto standard.
- **Status:** Active. Last commit Feb 2026. ~352k downloads.
- **Caveat:** No security audit. Self-described as "experimental stage."
  Several operations are gated behind `features = ["untested"]` (see below).

### 2. `pcsc` v2.9.0 — raw APDU transport

- **Repository:** https://github.com/bluetech/pcsc-rust
- **Status:** Active. Last release Dec 2024. ~1M downloads.
- **Purpose:** Safe Rust bindings to the OS PC/SC API (`pcsclite` on Linux).
  Gives `Card::transmit(apdu, buf)` — raw send/receive, no YubiKey logic.
  Used internally by `yubikey`.

### 3. `cryptoki` v0.12.0 — PKCS#11 wrapper

- **Repository:** https://github.com/parallaxsecond/rust-cryptoki
- **Status:** Active (Parsec project). Last release Jan 2026.
- **Purpose:** Idiomatic Rust wrapper over the PKCS#11 C API.
  Requires the Yubico PKCS#11 shared library (`ykcs11.so`) at runtime.
  This is a deployment dependency — it must be installed on the target system.

### Irrelevant crates (noted for completeness)

| Crate | Reason irrelevant |
|---|---|
| `yubihsm` | Targets YubiHSM2 (a different device), not YubiKey PIV |
| `yubico` | OTP cloud validation only |
| `yubikey-management` | Only enables/disables YubiKey applets (OTP on/off) |
| `pkcs11` v0.5.0 | Explicitly unmaintained; README says "use `cryptoki` instead" |

---

## Operation-by-Operation Coverage

| # | Operation | `yubikey` | `pcsc` | `cryptoki` |
|---|---|---|---|---|
| 1 | List devices (serial, firmware) | ✓ | — | — |
| 2 | Read arbitrary PIV data objects | ✓ `untested` | raw APDU | — |
| 3 | Write arbitrary PIV data objects | ✓ `untested` | raw APDU | — |
| 4 | Verify PIV PIN | ✓ | — | — |
| 5 | Read PIN-protected mgmt key (0x5FC109) | ✓ `untested` | — | — |
| 6 | Authenticate with management key | ✓ | — | — |
| 7 | ECDH on-card (P-256, slot 0x82 etc.) | ✓ `untested` | — | ✓ (needs ykcs11) |
| 8 | Generate EC P-256 key pair | ✓ | — | ✓ (needs ykcs11) |
| 9 | Import X.509 certificate into slot | ✓ `untested` | — | ✓ (needs ykcs11) |
| 10 | Read X.509 certificate / public key | ✓ | — | ✓ (needs ykcs11) |
| 11 | Raw APDUs (GET_METADATA 0xF7, etc.) | ✗ (not public) | ✓ | — |

---

## Key Details

### The `untested` Feature Flag

The `yubikey` crate gates several critical operations behind
`features = ["untested"]`:

- `fetch_object` / `save_object` — arbitrary data object read/write
- `decrypt_data` — ECDH (despite the misleading name, this is ECDH for
  ECC algorithm IDs — it sends GENERAL AUTHENTICATE with tag `0x85`)
- `import_ecc_key`, `import_cv_key` — key import
- `Certificate::write` — certificate import
- PIN management (`change_pin`, `unblock_pin`, `set_pin_retries`)

The flag exists for historical caution ("not yet battle-tested"), not known
breakage. The tracking issue (#280) has been open since 2021. Enabling
`untested` unconditionally is the pragmatic approach.

### ECDH via `yubikey::piv::decrypt_data`

`piv::decrypt_data(yk, peer_point, AlgorithmId::EccP256, slot)` sends a
PIV GENERAL AUTHENTICATE APDU with tag `0x85` (the ECC "subject" field per
SP 800-73-4). The YubiKey interprets this as ECDH: given the peer's
uncompressed EC point (65 bytes for P-256), it returns the shared secret
point. This is exactly what `pkcs11-tool --derive` does under the hood via
`CKM_ECDH1_DERIVE`. The function name is misleading but the mechanism is
correct for ECDH.

### Reading the PIN-Protected Management Key (operation 5)

Currently done by calling `ykman piv objects export 0x5FC109 - --pin <pin>`
because `yubico-piv-tool` subprocess calls lose PIN state between
invocations. With `yubikey`:

```rust
yk.verify_pin(pin)?;               // PIN auth — caches in session
MgmKey::get_protected(&mut yk)?;   // reads 0x5FC109 in same session
```

The `yubikey` crate keeps PIN state on the `YubiKey` handle, so the two
operations share the same PC/SC session. The `ykman` dependency goes away.

### Raw APDU Gap (operation 11)

The `yubikey` crate's APDU layer is entirely `pub(crate)` — no public
`transmit()` method. For proprietary Yubico instructions not exposed by the
high-level API (GET_METADATA INS=0xF7 with arbitrary tag queries, GET_SERIAL
INS=0xF8, future extensions), the only path is `pcsc::Card::transmit`.

**Constraint:** A `yubikey::YubiKey` and a `pcsc::Card` cannot be open to
the same device simultaneously (PC/SC exclusive transaction). Raw APDU calls
must open a fresh `pcsc::Card` connection after closing (or before opening)
the `YubiKey` session.

In practice, GET_SERIAL is already cached in `YubiKey::serial()`, and the
admin-data object (0x5FFF00) is readable via `fetch_object`. The raw APDU
path is needed only for truly proprietary commands.

---

## Recommended Plan

Replace all three CLI tools with two crates:

```toml
yubikey = { version = "0.8", features = ["untested"] }
pcsc = "2.9"   # already present; keep for raw APDU fallback
```

Do **not** add `cryptoki` — it requires `ykcs11.so` at runtime, which
reintroduces a Yubico native dependency. The `yubikey` crate's `decrypt_data`
covers ECDH without it.

### Migration mapping

| Current subprocess | Replacement |
|---|---|
| `yubico-piv-tool list-readers` | `yubikey::reader::Context::open()` + `Context::iter()` |
| `yubico-piv-tool read-object --id X` | `yk.fetch_object(X)` (`untested`) |
| `yubico-piv-tool write-object --id X` | `yk.save_object(X, data)` (`untested`) |
| `yubico-piv-tool verify-pin` | `yk.verify_pin(pin)` |
| `yubico-piv-tool read-certificate --slot X` | `Certificate::read(&mut yk, slot)` |
| `yubico-piv-tool generate --slot X` | `piv::generate(&mut yk, slot, AlgorithmId::EccP256, ...)` |
| `yubico-piv-tool selfsign` + `import-certificate` | `Certificate::write(&mut yk, slot, ...)` (`untested`) |
| `ykman piv objects export 0x5FC109 --pin P` | `yk.verify_pin(p)` + `MgmKey::get_protected(&mut yk)` |
| `pkcs11-tool --derive` | `piv::decrypt_data(&mut yk, peer_point, AlgorithmId::EccP256, slot)` (`untested`) |
| GET_METADATA / GET_SERIAL raw APDUs | `pcsc::Card::transmit` (already used) |

---

## References

- `yubikey` crate docs: https://docs.rs/yubikey
- `yubikey` source: https://github.com/iqlusioninc/yubikey.rs
- `pcsc` crate docs: https://docs.rs/pcsc
- PIV standard (SP 800-73-4): https://csrc.nist.gov/publications/detail/sp/800-73/4/final
- `cryptoki` crate docs: https://docs.rs/cryptoki

---

## Hard-Won APDU Implementation Notes

*Recorded 2026-03-20 after implementing `piv/hardware.rs` from scratch.*

These are non-obvious gotchas that cost significant debugging time.

### GET DATA — SW=61xx chaining

A GET DATA response can arrive in chunks.  When `SW1=0x61`, `SW2` is the
number of remaining bytes (0x00 means 256).  You must loop issuing
`GET RESPONSE` (00 C0 00 00 Le) until you receive `SW=9000`.  Forgetting
this causes silent truncation: the outer `53` TLV length is correct but the
content is incomplete.

```
00 CB 3F FF 05 5C 03 XX XX XX 00   ← GET DATA
→ <partial data> 61 nn              ← more to come
00 C0 00 00 nn                      ← GET RESPONSE
→ <rest of data> 90 00
```

### GET DATA response — strip the outer 53 wrapper

The raw GET DATA response is `53 <len> <content>`, not just `<content>`.
The `53` wrapper must be stripped before parsing the inner TLV.  Cert objects
have the additional inner structure `70 <len> <DER cert> 71 01 00 FE 00`.

### PUT DATA — ISO 7816-4 extended APDU Lc encoding

For data fields longer than 255 bytes, the Lc encoding changes from 1 byte
to 3 bytes: `00 Lc_hi Lc_lo` (the leading `00` signals extended format).
This is **not** BER-TLV length encoding — do not use `81 xx` or `82 xx yy`.

```
Short  (≤255):  00 DB 3F FF Lc <data>
Extended (>255): 00 DB 3F FF 00 Lc_hi Lc_lo <data>
```

Sending BER-TLV length encoding instead of ISO 7816-4 encoding corrupts
the YubiKey object (it gets written as a 3-byte blob).

### VERIFY PIN — pad to 8 bytes with 0xFF

The YubiKey PIV spec requires the PIN buffer in the VERIFY APDU to be exactly
8 bytes, with unused trailing bytes filled with `0xFF`:

```
00 20 00 80 08 36 35 34 33 32 31 FF FF   ← PIN "654321"
```

Sending the PIN without padding produces `SW=6A80`.

### GENERAL AUTHENTICATE ECDH — response tag is 0x82, not 0x85

The ECDH request wraps the peer point under tag `0x85`:
```
7C <len> [ 85 <len> <65-byte peer point> ]
```
But the response wraps the shared secret under tag `0x82`:
```
7C <len> [ 82 <len> <shared secret> ]
```
Using `0x85` to parse the response yields "missing tag" errors.

### Management key mutual auth — 3DES uses P1=0x03, block size=8

GENERAL AUTHENTICATE P1 encodes the algorithm:
- `0x03` = 3DES (24-byte key, 8-byte block)
- `0x08` = AES-128 (16-byte key, 16-byte block)
- `0x0E` = AES-256 (32-byte key, 16-byte block)

The PRINTED object on a `ykman --protect` YubiKey today is typically a
24-byte key even though the ykman docs say AES-192.  Treat the actual key
length as ground truth.

### PIN-protected management key — single PC/SC session required

When the management key is stored in the PRINTED object (0x5FC109), the
following operations **must all happen within the same PC/SC session**:

1. VERIFY PIN (`00 20 00 80 08 ...`)
2. GET DATA for PRINTED (`00 CB 3F FF ...`)
3. GENERAL AUTHENTICATE (management key mutual auth)
4. PUT DATA (`00 DB 3F FF ...`)

Opening a new `Card` connection between any of these steps resets the
PIN-verified state, causing `PUT DATA` to return
`SCARD_E_NOT_TRANSACTED (0x80100016)`.

In the `pcsc` crate this means: open one `Card`, do all four steps, then
drop it.  In pyscard, `SCardBeginTransaction` alone is not sufficient
because pyscard wraps each `transmit` call in its own internal transaction;
use raw `SCardTransmit` via ctypes or `yubico-piv-tool` directly.

### PRINTED object TLV layout (with outer 53 wrapper intact)

After `get_data()` (which strips the `53` wrapper), the content is:
```
88 1A 89 18 <24 bytes of management key>
```
If you have the raw GET DATA response (with the `53` wrapper), parse as:
```
53 <len> [ 88 <len> [ 89 <len> <key bytes> ] ]
```

### parse_tlv_flat is single-level only

The `parse_tlv_flat` helper in `hardware.rs` parses a flat sequence of
single-byte-tag TLVs into a `HashMap<u8, Vec<u8>>`.  It is **not**
recursive.  To reach nested tags (e.g. `88 → 89`), call it twice:
```rust
let outer = parse_tlv_flat(data);          // finds tag 0x88
let inner = parse_tlv_flat(&outer[&0x88]); // finds tag 0x89
```
