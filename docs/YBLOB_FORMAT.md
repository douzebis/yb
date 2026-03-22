<!--
SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# yblob Storage Format Specification

This document describes the binary format used to store named blobs in a
YubiKey PIV application.  It is intended to be self-contained: any
implementation that can read and write YubiKey PIV data objects can
interoperate with a yblob store without depending on the `yb` tool.

---

## 1. Overview

A yblob store occupies a contiguous range of **PIV data objects** (retired key
certificate slots).  Each PIV object holds exactly one **chunk** — a
variable-length binary record that is either empty or carries part of a blob's
payload.

Large blobs are split across multiple chunks, linked by index into a singly
linked list.  Each chunk is written at exactly the size its content requires
(9 bytes for an empty sentinel, up to 3,063 bytes for an occupied chunk).

The format is self-describing: every chunk encodes the total object count, so
any single object is sufficient to reconstruct the full store layout.  Each
object's actual byte length is inferred from the `GET DATA` response.

---

## 2. PIV Object Allocation

### Object IDs

Chunks are stored in consecutive PIV data object IDs starting at `0x5F_0000`:

| Index | PIV object ID |
|-------|---------------|
| 0     | `0x5F_0000`   |
| 1     | `0x5F_0001`   |
| …     | …             |
| N−1   | `0x5F_00(N-1)`|

The default store uses 20 objects (`0x5F_0000`–`0x5F_0013`).

### Object size

Each PIV object is written at exactly the size its content requires:

| Chunk type | Minimum | Maximum |
|---|---|---|
| Empty sentinel | 9 bytes | 9 bytes |
| Head chunk | 23 + name_len + 1 bytes | 3,063 bytes |
| Continuation chunk | 12 bytes | 3,063 bytes |

The maximum of 3,063 bytes derives from the YubiKey APDU buffer (3,072 bytes)
minus 9 bytes of BER-TLV framing overhead (`5C 03 …` + `53 82 HH LL`).

Object sizes are not encoded in the chunk header; each object's length is
inferred from the byte length returned by the PIV `GET DATA` command.

### YubiKey NVM budget

The YubiKey 5 PIV application allocates 51,200 bytes of NVM shared across all
data objects.  Standard-slot certificates (slots 9A, 9C, 9D, 9E, and the
pre-loaded attestation certificate) typically consume 3–5 KB, leaving roughly
46–48 KB for a yblob store.  A freshly formatted 20-object store occupies only
20 × 9 = 180 bytes of NVM; objects grow as blobs are written.  In practice,
20 fully occupied objects consume up to 20 × 3,063 ≈ 60 KB — the object-count
limit (20 slots) is reached well before the NVM pool is exhausted.

---

## 3. Chunk Layout

All integers are **little-endian**.  Each chunk is written at the exact size
its content requires (see section 2).  Fields are laid out at fixed offsets;
no trailing padding bytes are written.

### 3.1 Common header (present in every chunk)

```
Offset  Size  Type    Field
──────  ────  ──────  ──────────────────────────────────────────────────────
0x00     4    u32 LE  MAGIC = 0xF2ED5F0B
0x04     1    u8      OBJECT_COUNT  — total number of chunks in this store
0x05     1    u8      STORE_KEY_SLOT — PIV slot of the ECDH encryption key
0x06     3    u24 LE  OBJECT_AGE    — monotonic write counter; 0 = empty slot
```

A chunk with `OBJECT_AGE == 0` is **empty** (free).  All fields beyond
`OBJECT_AGE` are zero and carry no meaning.

### 3.2 Occupied chunk header (present when `OBJECT_AGE != 0`)

```
Offset  Size  Type    Field
──────  ────  ──────  ──────────────────────────────────────────────────────
0x09     1    u8      CHUNK_POS   — position of this chunk in its blob chain
                                    (0 = head, 1 = first continuation, …)
0x0A     1    u8      NEXT_CHUNK  — index of the next chunk in the chain;
                                    equals this chunk's own index if last
```

### 3.3 Head chunk extra fields (present when `CHUNK_POS == 0`)

```
Offset  Size  Type    Field
──────  ────  ──────  ──────────────────────────────────────────────────────
0x0B     4    u32 LE  BLOB_MTIME      — modification time, Unix seconds
0x0F     3    u24 LE  BLOB_SIZE       — byte length of the stored payload
                                        (encrypted size if encrypted)
0x12     1    u8      BLOB_KEY_SLOT   — PIV slot used for encryption;
                                        0x00 = unencrypted
0x13     3    u24 LE  BLOB_PLAIN_SIZE — byte length of the plaintext before
                                        encryption (equals BLOB_SIZE when
                                        unencrypted)
0x16     1    u8      BLOB_NAME_LEN   — byte length of the blob name (1–255)
0x17   N_len  UTF-8   BLOB_NAME       — blob name, not NUL-terminated
```

Payload bytes begin immediately after `BLOB_NAME`:

```
0x17 + BLOB_NAME_LEN  …  end of object
```

Head payload capacity (bytes available for payload data in a head chunk):

```
min(MAX_OBJECT_SIZE, needed) − 0x17 − BLOB_NAME_LEN
```

where `MAX_OBJECT_SIZE = 3,063` and `needed` is the total content size.

### 3.4 Continuation chunk payload

Continuation chunks (`CHUNK_POS >= 1`) carry no blob metadata.  Payload
begins at a fixed offset:

```
Offset  Size  Field
──────  ────  ─────────────────────────────────────────────────────────────
0x0B    …     Payload bytes (continuation payload capacity = MAX_OBJECT_SIZE − 0x0B = 3,052 bytes)
```

---

## 4. Blob Assembly

To read a blob named `N`:

1. Scan all chunks in the store for a head chunk (`CHUNK_POS == 0`,
   `OBJECT_AGE != 0`) whose `BLOB_NAME` equals `N`.
2. Starting from that head chunk, follow the `NEXT_CHUNK` index chain,
   collecting payload bytes from each chunk in order, until a chunk whose
   `NEXT_CHUNK` equals its own index (end-of-chain sentinel).
3. Concatenate all payload bytes.  The result is `BLOB_SIZE` bytes long
   (trim if the last chunk's payload region extends beyond the blob boundary
   due to zero-padding).
4. If `BLOB_KEY_SLOT != 0`, decrypt the concatenated bytes as described in
   section 5.

---

## 5. Encryption Format

Encrypted blob payloads use a hybrid scheme: ECDH key agreement on the
YubiKey, HKDF-SHA256 key derivation, and AES-256-GCM authenticated
encryption.

Two wire formats exist, distinguished by the first byte of the stored payload.

### 5.1 Format v2 — AES-256-GCM (current)

```
Offset   Size  Field
───────  ────  ──────────────────────────────────────────────────────────────
0         1    VERSION = 0x02
1        65    EPHEMERAL_PUBKEY — X9.62 uncompressed P-256 point (first byte
                                  is always 0x04)
66       12    NONCE — random 96-bit GCM nonce
78        N    CIPHERTEXT — AES-256-GCM ciphertext + 16-byte authentication tag
```

Total overhead: 1 + 65 + 12 + 16 = **94 bytes**.  Stored payload length
equals plaintext length + 94.

### 5.2 Format v1 — AES-256-CBC (legacy, read-only)

Blobs written by earlier versions of yb (Python implementation) start with
`0x04` (the X9.62 uncompressed-point prefix byte) and have no version field:

```
Offset   Size  Field
───────  ────  ──────────────────────────────────────────────────────────────
0        65    EPHEMERAL_PUBKEY — X9.62 uncompressed P-256 point
65       16    IV — AES-CBC initialisation vector
81        N    CIPHERTEXT — AES-256-CBC + PKCS7 padding
```

Format detection: if the first byte is `0x02`, use v2; if `0x04`, use v1.
New implementations should write v2 only.

### 5.3 Decryption procedure

1. Extract `EPHEMERAL_PUBKEY` from the stored payload.
2. Issue a PIV GENERAL AUTHENTICATE (ECDH) command to the YubiKey using the
   slot identified by `BLOB_KEY_SLOT`, with `EPHEMERAL_PUBKEY` as the peer
   point.  The YubiKey returns the raw shared secret bytes (X coordinate of
   the ECDH result point).
3. Derive a 32-byte AES key:
   ```
   aes_key = HKDF-SHA256(ikm=shared_secret, salt=none, info="hybrid-encryption", len=32)
   ```
4. **v2**: Decrypt with AES-256-GCM using `NONCE` and `aes_key`.  The GCM
   tag covers the ciphertext; authentication failure means the blob is
   corrupt or tampered.
   **v1**: Decrypt with AES-256-CBC using `IV` and `aes_key`, then strip
   PKCS7 padding.

---

## 6. Age Counter and Ordering

`OBJECT_AGE` is a store-wide monotonic counter.  Each new chunk written
receives `max(all current ages) + 1`.  This allows detection of the most
recently written copy when duplicate blob names exist (which should not occur
in a well-formed store but can arise after an interrupted write).

The store age is the maximum `OBJECT_AGE` value across all chunks.

---

## 7. Invariants and Constraints

| Property | Value |
|----------|-------|
| Magic | `0xF2ED5F0B` (LE u32 at offset 0x00) |
| Object size range | 9–3,063 bytes (written at exact content size; no padding) |
| Object count range | 1–20 |
| Object IDs | `0x5F_0000` + index (contiguous) |
| Blob name encoding | UTF-8, no NUL bytes, no `/`, length 1–255 bytes |
| OBJECT_AGE = 0 | empty slot; all other fields are zero |
| CHUNK_POS = 0 | head chunk; blob metadata fields are present |
| CHUNK_POS ≥ 1 | continuation chunk; blob metadata fields are absent |
| NEXT_CHUNK = own index | end-of-chain sentinel (last chunk of a blob) |
| BLOB_KEY_SLOT = 0 | unencrypted blob |
| BLOB_KEY_SLOT ≠ 0 | encrypted; value is the PIV slot used for ECDH |
| All integers | little-endian |

---

## 8. File Magic

The yblob format is registered in the
[`file` magic database](https://github.com/file/file)
([bug #666](https://bugs.astron.com/view.php?id=666), merged June 2025):

```
# yblob object store
0    lelong    0xF2ED5F0B    yblob object store image data
```

A raw PIV object dump is identified automatically:

```shell
$ file yubikey_object_dump.bin
yubikey_object_dump.bin: yblob object store image data
```

---

## 9. Example: Reading a Store

```
1. Read PIV object 0x5F_0000.
   object_size = len(response)          # 9 (empty) to 3063 (full)

2. Parse common header:
   magic        = LE32(response[0:4])   # must be 0xF2ED5F0B
   object_count = response[4]           # e.g. 20
   key_slot     = response[5]           # e.g. 0x82

3. For i in 1..object_count:
     Read PIV object 0x5F_0000 + i.
     Parse common header (same structure).

4. For each chunk with OBJECT_AGE != 0 and CHUNK_POS == 0:
     This is a blob head.  Read BLOB_NAME, BLOB_SIZE, BLOB_KEY_SLOT, etc.

5. To fetch blob named "my-key":
     Find the head chunk where BLOB_NAME == "my-key".
     Follow NEXT_CHUNK links, collecting payload bytes.
     Concatenate; trim to BLOB_SIZE bytes.
     If BLOB_KEY_SLOT != 0: decrypt (section 5).
```
