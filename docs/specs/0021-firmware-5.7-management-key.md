<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0021 — Firmware 5.7+ Support: Management Key Algorithms and Pivman Interoperability

**Status:** implemented
**App:** yb
**Implemented in:** 2026-09-29

## Problem

### 1. yb cannot authenticate to a YubiKey with firmware 5.7+

Starting with firmware 5.7, the factory-default PIV management key is
**AES-192** (same 24 bytes `010203…0708`, algorithm id `0x0A`) instead
of **3DES** (algorithm id `0x03`).

yb infers the algorithm from the key length alone
(`rust/yb-core/src/piv/session/auth.rs`):

```rust
24 => (0x03, 8),  // 3DES
16 => (0x08, 16), // AES-128
32 => (0x0C, 16), // AES-256
```

A 24-byte key is always treated as 3DES, and AES-192 is not handled at
all.  On a 5.7+ key, any operation that needs the management key fails:

```
$ yb --allow-defaults format --generate --protect
Warning: YubiKey has default credentials: management key. ...
Enter YubiKey PIN:
Error: MGMT AUTH step1 failed: SW=6a80 (incorrect parameters in data field)
```

The same assumption is repeated elsewhere:

- `crypto_ecb` (`piv/tlv.rs`) selects the cipher from the key length
  (24 bytes → 3DES), so it cannot do AES-192.
- `set_management_key` (`piv/hardware.rs`) rejects any new key that is
  not 24 bytes long and always sends algorithm `0x03` (3DES).
- `generate_random_management_key` (`auxiliaries.rs`) always produces a
  24-byte key meant for 3DES.

### 2. yb misreads and miswrites the pivman ADMIN DATA flags

Yubico's tools (ykman, yubico-piv-tool) store "pivman" metadata in the
ADMIN DATA object `0x5FFF00`: `80 L [ 81 01 <flags> | 82 L <salt> |
83 04 <pin timestamp> ]`.  Per ykman 5.9.1 (`ykman/piv.py`,
`PivmanData`):

| Field | Meaning |
|---|---|
| flags bit `0x01` | PUK blocked |
| flags bit `0x02` | management key stored in PRINTED object (PIN-protected) |
| tag `0x82` present | PIN-derived management key (deprecated) |
| tag `0x83` | PIN last-changed timestamp |

yb (Rust, since 0.4.x) deviates from this:

- `yb format --protect` writes flags `0x01`, i.e. it tells ykman that
  **the PUK is blocked**, and does not set `0x02`.  ykman therefore does
  not recognize a yb-protected card as PIN-protected.
- It overwrites ADMIN DATA in full, dropping any `0x83` timestamp or
  other flags.
- Detection treats `flags & 0x03` as "PIN-protected", so a card whose
  PUK was really blocked by ykman is treated as PIN-protected, and yb
  then fails trying to read the key from PRINTED.
- It detects PIN-derived mode from bit `0x04`, which no Yubico tool
  sets.  The actual signal, the presence of the salt tag `0x82`, is
  ignored.

The earlier Python implementation never wrote ADMIN DATA itself: it
told users to run `ykman piv access change-management-key --generate
--protect`, which sets `0x02`.  So the cards out there fall into two
groups: ykman-protected cards (`0x02`) and cards protected by Rust
yb ≥ 0.4 (`0x01`).

## Goals

- yb works with management keys of every algorithm the YubiKey supports:
  3DES, AES-128, AES-192, AES-256.
- It learns the algorithm from the card, not from the key length.
- `yb format --protect` works on firmware 5.7+ keys with their default
  AES-192 management key.
- `--protect` keeps the card's current management key algorithm (see
  Specification §3).
- ADMIN DATA is read and written exactly as ykman does, so a card
  protected by yb is recognized by ykman and the reverse.
- Cards protected by earlier yb versions (flags `0x01`) keep working:
  they can still be read and written, and are migrated to the correct
  flag.
- When a card is in a state yb does not support, yb says so before it
  modifies anything, and does not fail partway through.

## Non-goals

- Changing a card's management key algorithm, e.g. upgrading a 3DES key
  to AES-192.  A later spec may add a `--mgmt-algorithm` option.
- Supporting PIN-derived management keys.  They stay rejected, as
  today, but are detected correctly.
- Store keys other than EC P-256 in the store slot (RSA, Ed25519,
  X25519).
- FIPS-series specific behavior.
- A management key with touch policy "always" (it is detected and
  warned about, not supported).
- Changes to the yblob storage format.

## Specification

### 1. Management key algorithm

Add to `yb-core`:

```rust
pub enum MgmtAlgo { Tdes, Aes128, Aes192, Aes256 }
```

| Variant | PIV id | Key length | Block size |
|---|---|---|---|
| `Tdes`   | `0x03` | 24 | 8  |
| `Aes128` | `0x08` | 16 | 16 |
| `Aes192` | `0x0A` | 24 | 16 |
| `Aes256` | `0x0C` | 32 | 16 |

**Detection.** Send GET METADATA for slot `9B` (`00 F7 00 9B 00`):

- **Success**: read tag `0x01` (algorithm id).  Unknown ids are an error:
  `unsupported management key algorithm 0xNN`.  If tag `0x02` (policy)
  reports touch "always", print a warning; operations will need touch.
- **SW `6D00`** (INS not supported; firmware < 5.3): assume `Tdes`.
  AES management keys require firmware ≥ 5.4, which also supports GET
  METADATA, so this cannot guess wrong on a real YubiKey.
- **Any other status word**: propagate the error.

Detection runs in the same PC/SC session as the authentication that
needs it; no extra session is opened.  The result is **cached on the
session** (`PcscSession` gains an `Option<MgmtAlgo>` field).  Only the
first authentication in a session sends GET METADATA.  `nvm.rs`
authenticates hundreds of times within one session, so without the
cache every one of those authentications would repeat the query.  A
successful SET MANAGEMENT KEY updates the cached value.  The backend
trait gains:

```rust
fn management_key_algorithm(&self, reader: &str) -> Result<MgmtAlgo>;
```

**Key validation.** A key from `YB_MANAGEMENT_KEY`, from the deprecated
`--key`, or from PRINTED must be exactly the algorithm's key length.
Otherwise yb fails before attempting authentication:

```
management key is 16 bytes but the card uses AES-192 (24 bytes)
```

### 2. Authentication and ECB helper

- `authenticate_management_key` uses the detected `MgmtAlgo` for P1 and
  the block size.
- `crypto_ecb` takes a `MgmtAlgo` instead of inferring the cipher from
  the key length, and implements AES-192.
- If authentication still fails with SW `6A80`, the error names the
  algorithm yb used and the one the card reported, so the next
  occurrence can be diagnosed without a hex dump.

### 3. SET MANAGEMENT KEY and `--protect`

- `generate_random_management_key(algo)` returns `algo.key_len()`
  random bytes.
- `set_management_key(reader, old, new, algo)` sends
  `00 FF FF FF <Lc> <algo id> 9B <len> <key>`, with `Lc = 3 + len`.
  P2 stays `0xFF` (no touch).
- `--protect` sets a new key **with the same algorithm the card
  currently has**:
  - Firmware 5.7+ with a default key: AES-192.
  - Older keys: 3DES, which is what they support and what older yb
    versions can use.

  This keeps older yb versions able to write to any card they could
  write to before (see §6).
- `--protect` obtains the **current** management key like every other
  write, through `Context::management_key_for_write`: `YB_MANAGEMENT_KEY`,
  else PRINTED (standard or legacy flag), else the factory default.
  yb ≤ 0.4.x always assumed the factory default.  On a card that was
  already protected, SET MANAGEMENT KEY then failed with `SW=6982`, after
  `--generate` had already replaced the store key.  This was reproduced on
  hardware, and is the likely cause of the "bar CORRUPTED" incident in
  spec 0022.

### 4. ADMIN DATA

**Reading.** Parse flags `F` (tag `0x81`, default 0) and salt `S` (tag
`0x82`) from inside tag `0x80`.

| Condition | Meaning |
|---|---|
| `S` present | PIN-derived: unsupported.  Refused when a management key is needed (write commands), with today's message.  Read-only commands work normally. |
| `F & 0x02` | PIN-protected (key in PRINTED) |
| `F & 0x01` and not `F & 0x02` | *ambiguous*: really PUK-blocked (ykman) **or** protected by legacy yb |
| otherwise | not protected |

The ambiguous case is resolved lazily, the first time a management key
is needed.  Every write operation already requires the PIN at that
point:

- Verify the PIN and read PRINTED.
- If PRINTED parses as `88 { 89 <key> }`, treat the card as a
  **legacy-yb protected card**.
- Otherwise treat it as not protected, so the management key must come
  from `YB_MANAGEMENT_KEY` or be the default.

Read-only commands (`ls`, `fsck`, `fetch`) never need the management
key, so they are not affected by the ambiguity.

Bit `0x04` is no longer interpreted.

**Where the decision is made.** `Context` is the single place that
decides how the management key is obtained.  It replaces today's
`pin_protected: bool` / `pin_derived: bool` with:

```rust
pub enum ProtectionMode { None, Standard, LegacyOrPukBlocked, Derived }
```

- The mode is set at `Context` construction from ADMIN DATA (read-only,
  no PIN).
- `management_key_for_write` settles `LegacyOrPukBlocked` as described
  above.  It remembers whether a legacy migration is due, and refuses on
  `Derived`.
- The hardware layer keeps its existing PIN-only fallback
  (`resolve_management_key` reads PRINTED when no key but a PIN is
  given).  `format --protect` relies on it right after the key changes.
  It no longer drives any decision: it only carries out what `Context`
  asked for.

**Writing** (`--protect` and legacy migration) is a read-modify-write
of ADMIN DATA:

- Set `0x02`.
- Bit `0x01` means "PUK blocked":
  - On firmware ≥ 5.3, set it if GET METADATA for the PUK (`P2 = 0x81`)
    reports 0 retries remaining, and clear it otherwise.
  - On older firmware, keep its current value, except when migrating a
    legacy-yb card (see below), where it is cleared.
- Keep tag `0x83` and any unknown tags and flag bits unchanged.
- Never write tag `0x82`.  A salt means PIN-derived mode, which yb
  rejects before reaching this point.

**Legacy migration.** When a write command (`store`, `rm`, `format`) has
resolved the management key through the legacy-yb path, it rewrites
ADMIN DATA as described above, once all of the command's own writes
have succeeded.  This is one extra `write_object` call.  The hardware
backend opens a PC/SC session per object write, so the migration cannot
share a session with the command's writes.  Unless `--quiet` is given,
it prints once on stderr:

```
yb: note: upgraded PIN-protected management key metadata to the standard (ykman-compatible) layout
```

The management key and PRINTED are left unchanged.  Because the rewrite
comes after the main operation, a failure in it is reported as a
warning and does not fail the operation.

### 5. Test backends

- The virtual PIV fixture gains optional `firmware_version` and
  `management_key_algorithm` fields.  Missing fields mean 5.4.3 and
  3DES, so existing fixtures load unchanged.
- The virtual backend enforces the algorithm: authenticating with the
  wrong P1 returns `6A80`, like real hardware.
- The virtual backend's ADMIN DATA handling follows §4.
- The `EmulatedPiv` backend (`piv/emulated.rs`) does not model the
  management key.  It reports `Tdes` from `management_key_algorithm`,
  and its `set_management_key` stays a no-op (the new `algo` parameter
  is ignored).
- New tests:
  - `format --protect` on a 5.7 / AES-192 fixture.
  - A legacy flags-`0x01` fixture, which is migrated on first write.
  - A ykman flags-`0x02` fixture, used as-is.
  - A PUK-blocked fixture (`0x01`, empty PRINTED), which must not be
    treated as protected.
  - A salt fixture, which is rejected.
  - A key whose length does not match the algorithm, which is rejected
    before any APDU is sent.

### 6. Backward compatibility contract

This contract also applies to specs 0022 and 0023.

- **The yblob format does not change.**  Stores written by any earlier
  yb (yb0/yb1/yb2, Python or Rust) are read and written by new yb
  exactly as before.
- **Card metadata written by new yb stays readable by old yb:**
  - Rust yb ≥ 0.4 detects protection with `flags & 0x03`, so it sees
    `0x02`.
  - Python yb accepts `0x01` or `0x02`.
  - Neither interprets `0x83`.
- **Card metadata written by old yb stays usable by new yb**, through
  the legacy path in §4.
- **When new yb cannot operate safely, it refuses before writing
  anything** and names the reason.  This covers a PIN-derived key, an
  unknown management key algorithm, and an unparseable ADMIN DATA or
  PRINTED object.

| Card last set up by | New yb read | New yb write | Old yb (≥ 0.4) read | Old yb write |
|---|---|---|---|---|
| Python yb + ykman `--protect` (`0x02`) | ✓ | ✓ | ✓ | ✓ (3DES) |
| Rust yb ≤ 0.4.x `--protect` (`0x01`) | ✓ | ✓ (migrates) | ✓ | ✓ |
| New yb, firmware < 5.7 (3DES) | ✓ | ✓ | ✓ | ✓ |
| New yb, firmware ≥ 5.7 (AES-192) | ✓ | ✓ | ✓ | ✗ `6A80` (as with an unmodified 5.7 key) |

Old yb cannot write to a 5.7+ key in any configuration, so the last row
takes nothing away from older versions.

### 7. Hardware validation

These are manual checks on real devices, run before the spec is marked
`implemented`.

- **Old yb**: a git worktree at the last pre-0021 commit,
  `../yb-pre-0021` (commit `2785d09`, yb 0.4.2), built with `cargo build
  --release`.
- **New yb**: the release build of the implementation.

**YubiKey with firmware < 5.7 (3DES)**:

1. With old yb: `format --generate --protect` (writes the legacy `0x01`
   flag), then `store` a blob.
2. With new yb:
   - `ls` and `fetch` work;
   - the first `store` prints the migration note;
   - ADMIN DATA now has `0x02` and no `0x01` (check with `ykman piv
     objects export 0x5fff00 -`);
   - `ykman piv info` reports the management key as protected.
3. With old yb again: `ls`, `fetch`, `store` and `rm` all work on the
   migrated card.

**YubiKey with firmware ≥ 5.7 (AES-192 default)**:

1. With new yb: `format --generate --protect` succeeds.
2. `ykman piv info` shows the management key algorithm is AES-192 and
   the key is protected.
3. With new yb: `store`, `fetch`, `rm`, `fsck`.
4. With old yb: `ls` and `fetch` work.  `store` fails with `6A80`, as
   expected (§6 table).

## Open questions

None.  Resolved:

- Legacy migration (§4) happens automatically on any write operation.
- `--protect` keeps the card's current algorithm (§3).  It does not
  upgrade 3DES to AES-192 on firmware 5.4–5.6, so that Rust yb ≤ 0.4.x
  keeps write access.

## References

- [spec 0022](0022-format-sequence.md) — format sequencing (depends on §1–§4)
- [spec 0023](0023-guided-format.md) — guided format
- ykman 5.9.1 `ykman/piv.py`: `PivmanData`, `PivmanProtectedData`, `pivman_set_mgm_key`
- Yubico: *PIV management key algorithms*, firmware 5.7 release notes (default AES-192)
- `docs/yubikey-apdu-reference.md`
