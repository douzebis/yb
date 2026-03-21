# yb — Rust Implementation Design

**Version:** 2025-03 (post security-hardening)
**Crates:** `yb-core` (library), `yb` (CLI binary), `yb-piv-harness` (tier-2 test harness)

---

## 1. Overview

`yb` stores arbitrary blobs on a YubiKey using PIV data objects as a
key-value store.  Blobs can be stored in plaintext or encrypted with
hybrid encryption (ECDH + HKDF + AES-256-GCM) using an EC P-256 key
that lives in a PIV slot — the private key never leaves the card.

The Rust implementation is a clean-room port of the Python version.
It retains full binary compatibility with blobs written by the Python
version (including backward-compatible decryption of the legacy AES-CBC
format).  All PIV operations are performed via native PC/SC APDUs; no
subprocesses are spawned.

---

## 2. Architecture

```
┌─────────────────────────────────────────┐
│              yb (CLI binary)            │
│  clap → Commands: format/store/fetch/   │
│          list/remove/fsck/list-readers  │
└────────────────┬────────────────────────┘
                 │ Context (reader, piv, pin, …)
                 ▼
┌─────────────────────────────────────────┐
│           orchestrator.rs               │
│  store_blob / fetch_blob / remove_blob  │
│  list_blobs / validate_name             │
└────────────┬────────────┬───────────────┘
             │            │
             ▼            ▼
┌────────────────┐  ┌──────────────────────┐
│   store/       │  │   crypto.rs          │
│   mod.rs       │  │   hybrid_encrypt     │
│   Object /     │  │   hybrid_decrypt     │
│   Store        │  │   (GCM + legacy CBC) │
└──────┬─────────┘  └──────────────────────┘
       │
       ▼
┌─────────────────────────────────────────┐
│           PivBackend trait              │
│  ┌──────────────┐  ┌───────────────┐    │
│  │ HardwarePiv  │  │  VirtualPiv   │    │
│  │ (PC/SC)      │  │  (in-memory)  │    │
│  └──────────────┘  └───────────────┘    │
└─────────────────────────────────────────┘
```

### Layer responsibilities

| Layer | Module | Responsibility |
|---|---|---|
| CLI | `yb/src/main.rs`, `yb/src/cli/` | Argument parsing, user-facing errors |
| Context | `yb-core/src/context.rs` | Device selection, credential detection |
| Orchestrator | `yb-core/src/orchestrator.rs` | Blob operations, name validation |
| Store | `yb-core/src/store/` | Binary serialization of PIV objects |
| Crypto | `yb-core/src/crypto.rs` | Hybrid encryption/decryption |
| PIV backend | `yb-core/src/piv/` | Smart-card I/O abstraction |
| Auxiliaries | `yb-core/src/auxiliaries.rs` | TLV parsing, PIN-protected key, default-cred check |

---

## 3. Context and Device Selection

`Context` is built once from global CLI flags and passed to every
command handler.

```rust
pub struct Context {
    pub reader: String,           // PC/SC reader name
    pub serial: u32,              // YubiKey serial
    pub management_key: Option<String>, // explicit --key (48 hex chars)
    pub pin: Option<String>,
    pub piv: Arc<dyn PivBackend>,
    pub debug: bool,
    pub pin_protected: bool,      // mgmt key stored in PRINTED object
}
```

**Device selection** (`Context::new`):

1. `HardwarePiv::list_devices()` enumerates all PC/SC readers.
2. If `--serial` is given, select that device; if `--reader` is given,
   match by reader string; if exactly one device is present, use it;
   otherwise print the list and fail.
3. `check_for_default_credentials` queries the YubiKey GET_METADATA
   APDU (fw 5.3+) for PIN, PUK, and management key default status.
   If any credential is default and `--allow-defaults` is not set, the
   CLI aborts with a warning.
4. `detect_pin_protected_mode` reads the PRINTED object (`0x5F_C109`),
   checks for the PIN-protected key structure (TLV tag `0x88`/`0x89`),
   and also checks for the deprecated PIN-derived key (admin-data tag
   `0x03` mask).  PIN-derived mode is rejected outright; PIN-protected
   mode sets `ctx.pin_protected = true`.

**Management key resolution** (`Context::management_key_for_write`):

- Explicit `--key` takes priority.
- If `pin_protected`, decrypt the management key from the PRINTED object
  using the PIN.
- Otherwise return `None` (YubiKey uses its own default key — only
  safe when `--allow-defaults` is in use or the store is being formatted
  for the first time).

**`Context::with_backend`** is the test/library constructor: takes any
`Arc<dyn PivBackend>` (typically a `VirtualPiv`), skips the default-
credential check, and calls `detect_pin_protected_mode` normally.

---

## 4. PIV Backend

### `PivBackend` trait

```rust
pub trait PivBackend: Send + Sync {
    fn list_readers(&self)  -> Result<Vec<String>>;
    fn list_devices(&self)  -> Result<Vec<DeviceInfo>>;
    fn read_object(&self, reader: &str, id: u32) -> Result<Vec<u8>>;
    fn write_object(&self, reader: &str, id: u32, data: &[u8],
                    management_key: Option<&str>, pin: Option<&str>) -> Result<()>;
    fn verify_pin(&self, reader: &str, pin: &str) -> Result<()>;
    fn send_apdu(&self, reader: &str, apdu: &[u8]) -> Result<Vec<u8>>;
    fn ecdh(&self, reader: &str, slot: u8, peer: &[u8],
            pin: Option<&str>) -> Result<Vec<u8>>;
    fn read_certificate(&self, reader: &str, slot: u8) -> Result<Vec<u8>>;
    fn generate_key(&self, reader: &str, slot: u8,
                    management_key: Option<&str>) -> Result<Vec<u8>>;
    fn generate_certificate(&self, reader: &str, slot: u8, subject: &str,
                             management_key: Option<&str>,
                             pin: Option<&str>) -> Result<Vec<u8>>;
}
```

### `HardwarePiv`

Wraps PC/SC via the `pcsc` crate.  Every method opens a fresh
`PcscSession` (SELECT PIV applet on open), executes the operation,
and drops the session.

**`PcscSession` APDU operations:**

| Operation | APDU | Notes |
|---|---|---|
| SELECT PIV | `00 A4 04 00` + AID | AID = `A0 00 00 03 08` |
| GET DATA | `00 CB 3F FF 05 5C 03 xx xx xx 00` | BER-TLV 53 wrapper stripped |
| PUT DATA | `00 DB 3F FF` + data field | Command-chained in 255-byte chunks; wrapped in SCard transaction |
| VERIFY PIN | `00 20 00 80` + PIN (padded with 0xFF to 8 bytes) | SW `63 Cx` → x retries left |
| GENERAL AUTHENTICATE (ECDH) | `00 87 11 xx` | Dynamic Authentication Template, tag 0x85 (peer point) → tag 0x82 (shared secret) |
| GENERATE KEY | `00 47 00 xx` + key algorithm TLV | Returns uncompressed P-256 point |
| GET METADATA | `00 F7 00 yy 00` | YubiKey FW 5.3+; used for default-credential check |

**Management key authentication** (`authenticate_management_key`):

Uses 3DES-ECB challenge-response (NIST SP 800-73-4 mutual auth):
1. Issue GENERAL AUTHENTICATE with an empty witness (get card challenge).
2. Decrypt card challenge with management key via `crypto_ecb_op`.
3. Generate a host challenge; send both to the card.
4. Verify the card response by encrypting host challenge and comparing.

The raw 3DES key is accepted as 48 hex chars (24 raw bytes); the default
factory key is `010203040506070801020304050607080102030405060708`.

**PIN-protected management key:**

Stored in the PIV PRINTED data object (`0x5F_C109`) as:
```
88 <len> [ 89 <len> <key_bytes> ]
```
`extract_pin_protected_key` parses this structure; the PRINTED object
is itself protected by the PIN at the application level (not via PC/SC
access conditions).

### `VirtualPiv`

An in-memory backend with real P-256 cryptography; no hardware required.
Used for tier-1 unit tests.

**State:**

```
VirtualState {
    reader, serial, version,
    pin, puk, management_key_hex,
    pin_retries_left,
    slots: HashMap<u8, SlotKey>,   // PIV key slots
    objects: HashMap<u32, Vec<u8>>, // PIV data objects
    printed_object_raw: Option<Vec<u8>>,
    pin_protected: bool,
}
```

**Fixture loading** (`VirtualPiv::from_fixture`):
Reads a YAML file (`FixtureIdentity` + `FixtureCredentials`) that
provides serial, reader, PIN, PUK, management key, and per-slot key
scalars (hex-encoded P-256 scalars).  The default fixture is created
by `FixtureIdentity::default()`.

**ECDH in `VirtualPiv`:**
Performs the scalar multiplication directly:
```
shared_secret = peer_point × slot_private_scalar
```
Returns the x-coordinate of the resulting EC point (32 bytes), matching
YubiKey GENERAL AUTHENTICATE semantics.

---

## 5. Store Binary Format

All integers are little-endian.  Every PIV object is exactly
`object_size` bytes (default: 3052, range: 512–3052).  Up to 16 objects
are addressable; default is 12.

Object IDs run from `0x5F_0000` (index 0) to `0x5F_000B` (index 11)
for a 12-object default store.

### Object layout

```
Offset  Size  Field
──────  ────  ─────────────────────────────────────────────────────
0x00     4    MAGIC          u32 LE = 0xF2ed5F0b
0x04     1    OBJECT_COUNT   number of objects in the store
0x05     1    STORE_KEY_SLOT PIV slot for ECDH encryption key
0x06     3    OBJECT_AGE     u24 LE; 0 = empty slot
─── present only when age != 0 ───────────────────────────────────
0x09     1    CHUNK_POS      0 = head; 1, 2, … = continuation
0x0A     1    NEXT_CHUNK     index of next chunk; self-ref = last
─── present only in head chunks (chunk_pos == 0) ─────────────────
0x0B     4    BLOB_MTIME     u32 LE, Unix timestamp (seconds)
0x0F     3    BLOB_SIZE      u24 LE, encrypted payload size
0x12     1    BLOB_KEY_SLOT  PIV slot used for encryption; 0 = none
0x13     3    BLOB_PLAIN_SIZE u24 LE, plaintext size
0x16     1    BLOB_NAME_LEN  byte length of name
0x17   var    BLOB_NAME      UTF-8, no null/slash, max 255 bytes
0x17+N  rem   PAYLOAD        blob data (head portion)
─── continuation chunks: payload starts at 0x0B ──────────────────
0x0B   rem    PAYLOAD        blob data (continuation portion)
```

### Chunk chain

A blob spanning multiple objects forms a singly-linked list:

- `NEXT_CHUNK` in each object points to the next object's index.
- The last chunk is self-referential: `NEXT_CHUNK == own_index`.
- `CHUNK_POS` is the position in the chain (0, 1, 2, …); used for
  sanity checks but the chain is traversed via `NEXT_CHUNK`.

Payload continuity: head payload immediately follows the blob name;
continuation payload starts at offset `0x0B`.

### Age counter

Each object has an independent `OBJECT_AGE` (24-bit, monotonically
increasing within a store session).  When a new blob is written, each
of its chunks gets `store_age + 1`, `store_age + 2`, … where
`store_age` is the maximum age currently observed in the store.

On deserialization, `Store::from_device` sets `store_age` = max age
across all objects.

When two head objects have the same blob name (which can occur after an
interrupted write), `Store::sanitize` keeps the one with the higher age
and resets the other, then removes any orphaned continuation chunks.

### Sync

`Store::sync` iterates all `dirty` objects and calls
`piv.write_object(...)` for each, printing a `.` to stderr per write.
Each object is serialized to exactly `object_size` bytes by `Object::to_bytes()`.

---

## 6. Hybrid Encryption

All new blobs are encrypted with AES-256-GCM.  Old blobs encrypted with
AES-256-CBC can still be decrypted.  Detection is by the first byte of
the ciphertext blob.

### Wire formats

**GCM (v2, current):**
```
0x02                  (1 byte  — version tag)
ephemeral_pubkey      (65 bytes — X9.62 uncompressed P-256 point)
nonce                 (12 bytes — random, from OsRng)
GCM ciphertext + tag  (plaintext_len + 16 bytes)
```
Total overhead: 94 bytes.

**Legacy CBC (v1, read-only):**
```
ephemeral_pubkey      (65 bytes — first byte is always 0x04)
IV                    (16 bytes)
AES-256-CBC+PKCS7     (padded to 16-byte blocks)
```
Total overhead: 81 bytes + PKCS7 padding.

**Detection:** first byte `0x02` → GCM; `0x04` → legacy CBC; anything
else → error.  This is unambiguous: `0x04` is the only valid first byte
for an uncompressed P-256 point; `0x02` is the X9.62 compressed-point
indicator and never appears as the first byte of an uncompressed point.

### Encryption pipeline (`hybrid_encrypt`)

1. Generate ephemeral P-256 key pair (from `OsRng`).
2. ECDH: `shared_secret = ephemeral_secret × peer_public_key`.
3. HKDF-SHA256 (no salt, info = `b"hybrid-encryption"`) → 32-byte AES key.
4. Generate 12-byte random nonce.
5. AES-256-GCM encrypt (no AAD — ephemeral key is implicitly authenticated
   by ECDH; tampering changes the shared secret and causes GCM auth failure).
6. Serialize: `0x02 || epk || nonce || ciphertext+tag`.

### Decryption pipeline (`hybrid_decrypt`)

1. Inspect first byte → dispatch to `decrypt_gcm` or `decrypt_cbc_legacy`.
2. Extract ephemeral public key from blob.
3. Call `piv.ecdh(reader, slot, epk_bytes, pin)` → shared secret
   (GENERAL AUTHENTICATE on hardware; scalar multiply on VirtualPiv).
4. HKDF-SHA256 → AES key.
5. AES-256-GCM or AES-256-CBC+PKCS7 decrypt.

The private key for ECDH is the key in `blob_key_slot` (stored in the
head chunk).  For unencrypted blobs, `blob_key_slot == 0`.

---

## 7. Orchestrator Operations

### `store_blob`

1. `validate_name`: not empty, ≤ 255 bytes, no `\0` or `/`.
2. Encrypt payload if requested (calls `hybrid_encrypt`).
3. Calculate chunk count from payload size vs. head/continuation capacities.
4. Check `store.free_count() >= chunks_needed`; return `false` if full.
5. Delete any existing blob with the same name (reset its chunk chain).
6. Allocate chunk indices via `alloc_free`, mark age=1 as placeholder.
7. Fill head object (all metadata fields + first portion of payload).
8. Fill continuation objects (payload only, no blob metadata).
9. `store.sync(piv, management_key, pin)`.

**Head payload capacity:** `object_size - (0x17 + name_len_bytes)`

**Continuation payload capacity:** `object_size - 0x0B`

### `fetch_blob`

1. `store.find_head(name)` → head object or `None`.
2. Walk `store.chunk_chain(head.index)` collecting all payloads.
3. Truncate to `head.blob_size` (trailing zeros in last object).
4. If encrypted, call `hybrid_decrypt`; if unencrypted return raw bytes.

PIN is required for encrypted blobs; `fetch_blob` errors out if
`pin.is_none()` and the blob is encrypted.

### `remove_blob`

1. Find head.
2. Walk chain, call `reset()` on each object (zeros fields, marks dirty).
3. `store.sync(...)`.

### `list_blobs`

Collect all head objects, map to `BlobInfo`, sort by name.

```rust
pub struct BlobInfo {
    pub name: String,
    pub encrypted_size: u32,
    pub plain_size: u32,
    pub is_encrypted: bool,
    pub mtime: u32,        // Unix timestamp
    pub chunk_count: usize,
}
```

The `chrono` feature adds `BlobInfo::mtime_local() -> chrono::DateTime<Local>`.

---

## 8. CLI Commands

All commands share global flags: `--serial`, `--reader`, `--key`,
`--pin`, `--debug`, `--allow-defaults`.

| Command | Alias | Key args | What it does |
|---|---|---|---|
| `format` | — | `--object-count` (def 12), `--object-size` (def 3052), `--key-slot` (def 82), `--generate`, `--subject` | Provisions PIV objects; optionally generates ECDH key |
| `store` | — | `<name>` `<file>`, `--encrypt`, `--key-slot` | Stores a blob |
| `fetch` | — | `[name]` or `--all`, `--output-dir` | Retrieves blob(s) to file(s) |
| `list` | `ls` | `--long`, `--glob` | Lists blob metadata |
| `remove` | `rm` | `<name>` | Removes a blob |
| `fsck` | — | `--verbose` | Dumps store metadata, checks integrity |
| `list-readers` | — | — | Lists PC/SC readers |

### `format`

- Parses `--key-slot` as hex (`u8`).
- With `--generate`: calls `piv.generate_key(slot)` then
  `piv.generate_certificate(slot, subject)`.
- Without `--generate`: verifies an existing certificate is present in
  the slot.
- Calls `Store::format(...)` to write fresh empty objects.

### `store`

- Reads `<file>` from disk (or stdin if `-`).
- If `--encrypt`: calls `ctx.get_public_key(slot)` to read the public
  key from the slot's certificate, then passes it to `store_blob`.
- Returns an error if the store is full.

### `fetch`

- `--all` fetches every blob and writes to `<name>` files under
  `--output-dir` (default: current directory).
- Single-name fetch writes to stdout unless `--output-dir` is given.

### `list`

- `--long` prints mtime, sizes, encryption status, chunk count.
- `--glob` filters by a glob pattern (via `globset`).

### `fsck`

- Calls `Store::from_device`, runs `store.sanitize()` (reporting what
  was removed), and prints a dump of all objects.

---

## 9. Auxiliaries

### TLV parsing

`parse_tlv_flat(data)` → `HashMap<u8, Vec<u8>>`: flat BER-TLV (single-
byte tags, BER length encoding — both short and long forms supported via
`decode_tlv_length`).

Used to parse:
- GET_METADATA responses (default-credential check).
- PRINTED object (PIN-protected management key).
- GENERAL AUTHENTICATE response (shared secret).

### Default-credential check

Queries GET_METADATA for PIN (`0x80`), PUK (`0x81`), and management key
(`0x9B`).  Each response contains TLV tag `0x05`; value `0x01` means the
credential is still at its factory default.  If any is default and
`allow_defaults == false`, the program exits with a clear message.

Skipped when `YB_SKIP_DEFAULT_CHECK` environment variable is set (used
by integration tests that start with a freshly provisioned virtual card).

### X.509 subject parsing

`parse_subject_dn(subject: &str)` converts a `/`-separated DN string
(e.g., `/CN=YBLOB ECCP256`) into an `rcgen::DistinguishedName`.
Recognized attributes: `CN`, `O`, `OU`.  Unknown attributes are silently
skipped.  Validation of individual DN values is delegated to `rcgen`,
which enforces ASN.1 UTF8String encoding rules internally.

---

## 10. Test Architecture

### Tier 1 — Unit tests (VirtualPiv)

Feature flag: `virtual-piv`.

In-memory `VirtualPiv` with real P-256 cryptography; no hardware, no
PC/SC.  Used for all `cargo test` runs.

Test categories:
- `store/mod.rs`: `Object` serialization round-trips; Python binary-
  compatibility vector.
- `crypto.rs`: GCM encrypt/decrypt round-trip; legacy CBC backward-
  compatibility (crafts a CBC blob by hand, verifies `hybrid_decrypt`
  decodes it correctly via a `MockPiv` that injects a precomputed shared
  secret).
- `orchestrator.rs`: `validate_name` accepts/rejects correct inputs.
- `piv/virtual_piv.rs`: store/fetch/remove/list via VirtualPiv.

All 30 unit tests pass with `cargo test --features virtual-piv`.

### Tier 2 — Integration tests (NixOS VM + vsmartcard)

Feature flag: `integration-tests`.  Crate: `yb-piv-harness`.

A NixOS VM test (`pkgs.nixosTest`) spins up a guest with:
- `pcscd` (PC/SC daemon)
- `vsmartcard-vpcd` (virtual PC/SC reader)
- `piv-authenticator` (software PIV applet connected to vpcd)

The pre-built `hardware_piv_tests` binary is copied into the VM and run
with `RUST_TEST_THREADS=1` (sequential — shared virtual card state).

The harness crate (`yb-piv-harness`) provides `with_vsc(f)`:
- **External card mode** (CI/VM): connects to the vsmartcard TCP socket
  (`localhost:35963`) via a `VirtualPivClient` or uses the real PC/SC
  reader exposed by the vsmartcard layer.
- **In-process mode** (developer `nix-shell`): starts `vpicc` in a
  background thread.

Test fixture: `FixtureIdentity::default()` — known test credentials that
match the provisioned virtual card state.

---

## 11. Key Design Decisions

**No subprocesses.** All PIV operations are native PC/SC APDUs.  The Python
version shelled out to `yubico-piv-tool` and `openssl`; the Rust port
eliminates this entirely, removing command-injection risks and making
the CLI work without those tools installed.

**Private key never extracted.** ECDH is always performed on-card via
GENERAL AUTHENTICATE.  Only the shared secret (x-coordinate, 32 bytes)
is returned to the host.

**AES-GCM everywhere.** New blobs are always written with AES-256-GCM,
which provides authenticated encryption.  The legacy AES-256-CBC format
is decryption-only (no new CBC blobs are ever written).

**Age-based ordering, not timestamps.** `OBJECT_AGE` is a monotonically
increasing counter, not a clock value.  Clock skew and NTP issues cannot
corrupt the ordering of objects.  `BLOB_MTIME` records human-visible
wall-clock time but is not used for ordering.

**`dirty` flag, lazy sync.** Objects are modified in memory and written
to the YubiKey only when `Store::sync` is called.  A progress dot is
printed to stderr for each object written.

**Object-count and object-size are stored in every object.** This makes
any single object self-describing enough to reconstruct the full store
layout, which is important for `fsck`.

**Blob name rules.** Only `\0` (C string terminator) and `/` (path
separator convention) are forbidden.  All other UTF-8 is valid, including
spaces, Unicode, and emoji — consistent with Linux `ext4`/`btrfs`
filename semantics.

**`zeroize`.** Private key material held in `p256::SecretKey` and PKCS8
DER is automatically zeroed on drop via `Zeroizing<>` wrappers in the
`p256` crate.

---

## 12. Crate Feature Flags

| Feature | Enables | Default |
|---|---|---|
| `chrono` | `BlobInfo::mtime_local()` | No |
| `virtual-piv` | `VirtualPiv` backend, unit tests | No |
| `integration-tests` | vsmartcard + piv-authenticator tests | No |
| `hardware-tests` | Real YubiKey destructive tests (manual) | No |

---

## 13. Notable PIV Object IDs

| ID | Purpose |
|---|---|
| `0x5F_0000` – `0x5F_000B` | yb blob store (default 12 objects) |
| `0x5F_C109` | PRINTED — PIN-protected management key |
| `0x5F_FF00` | ADMIN DATA — mgmt key storage mode flags |
| `0x5F_C10A` | Key history |
| `0x5F_C101` – `0x5F_C10F` | Certificate slots (9A, 9C, 9D, 9E, 82–95) |

Default key slot for ECDH encryption: **0x82** (first retired key slot).
The corresponding certificate is written to the slot's certificate object
by `yb format --generate`.
