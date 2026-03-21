# yb — Rust Implementation Design

**Version:** 2026-03 (post CLI-improvements + subprocess test suite)
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
    pub quiet: bool,              // suppress informational stderr
    pub pin_protected: bool,      // mgmt key stored in PRINTED object
}
```

**Device selection** (`Context::new`):

1. If `YB_FIXTURE` env var is set (and the `virtual-piv` feature is
   compiled in), a `VirtualPiv` is loaded from that YAML file instead
   of opening a hardware card.  This is the test escape hatch.
2. `HardwarePiv::list_devices()` (or `VirtualPiv::list_devices()`)
   enumerates available devices.
3. If `--serial` is given, select that device; if `--reader` is given,
   match by reader string; if exactly one device is present, use it;
   otherwise print the list and fail.
4. `check_for_default_credentials` queries the YubiKey GET_METADATA
   APDU (fw 5.3+) for PIN, PUK, and management key default status.
   If any credential is default and `--allow-defaults` is not set, the
   CLI aborts with a warning.  Skipped when `YB_SKIP_DEFAULT_CHECK`
   is set (used by all integration tests to avoid spurious failures
   against the fixture's well-known factory credentials).
5. `detect_pin_protected_mode` reads the PRINTED object (`0x5F_C109`),
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
    // Default no-op; VirtualPiv overrides to persist state to disk.
    fn save_fixture(&self, path: &Path) -> Result<()> { Ok(()) }
}
```

`save_fixture` is called by `main.rs` after every successful command
when `YB_FIXTURE` is set.  This allows subprocess tests to share
`VirtualPiv` state across process boundaries: `yb format` writes keys
and objects, `save_fixture` serializes them back to the YAML file, and
the next `yb store` invocation loads that updated state.

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
Reads a YAML file with sections `identity`, `credentials`, `slots`, and
`objects`.  `slots` maps hex slot IDs (e.g. `"0x82"`) to
`{private_key_hex, cert_der_hex?}`; `objects` maps hex object IDs to
hex-encoded raw bytes.

**Fixture saving** (`VirtualPiv::save_fixture`):
Serializes the current in-memory state back to a YAML file in the same
format as `from_fixture`.  Used by the `save_fixture` `PivBackend` hook
so subprocess tests can persist mutations across process boundaries.

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
`object_size` bytes (default: 2048, range: 512–3052).  Up to 20 objects
are addressable; default is 20.

Object IDs run from `0x5F_0000` (index 0) to `0x5F_0013` (index 19)
for a 20-object default store.

**Default sizing rationale.**  The YubiKey 5 PIV NVM pool is 51,200 bytes,
shared across all data objects.  Standard-slot certificates (9A, 9C, 9D,
9E, attestation) typically consume 3–5 KB, leaving roughly 46–48 KB for
the yb store.  Blobs in practice range from small secrets (tokens, keys,
~100–500 B) through medium (TLS certs, ~1–2 KB) to large (GPG exports,
PKCS#12 bundles, ~4–8 KB).

Choosing 20 × 2,048 bytes (40,960 bytes gross) balances three competing
forces:

- **Object count** — 20 slots accommodate a realistic mix without the
  store filling up prematurely; the previous default of 12 was tight for
  users storing several large blobs.
- **Fragmentation** — each blob wastes on average half an object in its
  last (partially filled) chunk.  At 2,048 bytes that waste is ~1,024 B
  per blob vs. ~1,526 B at 3,052; meaningful for stores with many blobs.
- **Write amplification** — each PIV write is a separate GENERAL
  AUTHENTICATE + APDU round-trip.  Smaller objects increase chunk counts
  for large blobs; 2,048 keeps large-blob chunk counts reasonable (an
  8 KB blob needs 5 chunks vs. 3 at 3,052).

20 × 2,048 = 40,960 bytes fits comfortably within the 51,200-byte pool
while leaving ~10 KB for standard-slot certificates.

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
`piv.write_object(...)` for each.  Progress is shown via an `indicatif`
progress bar (`Writing objects: [=====>----] 3/7`) written to stderr;
suppressed when `ctx.quiet` is true.
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

### Global flags

| Flag | Notes |
|---|---|
| `-s/--serial` | Select YubiKey by serial number |
| `-r/--reader` | Select by PC/SC reader name (legacy) |
| `-q/--quiet` | Suppress informational stderr output |
| `--pin-stdin` | Read PIN from stdin (one line) |
| `--debug` | Enable debug output |
| `--allow-defaults` | Skip default-credential check |
| `--pin` | Hidden, deprecated — use `YB_PIN`, `--pin-stdin`, or TTY prompt |
| `--key`/`-k` | Hidden, deprecated — use `YB_MANAGEMENT_KEY` |

**PIN resolution order** (first match wins):
`--pin-stdin` → deprecated `--pin` → `YB_PIN` env var → interactive
`rpassword` TTY prompt → `None` (operations requiring PIN will fail).

**Management key resolution:** deprecated `--key` → `YB_MANAGEMENT_KEY`
env var → `None`.

**`list-readers` is dispatched before `Context::new`** — it works even
when no YubiKey is connected.  It also respects `YB_FIXTURE` (uses the
fixture's reader list when set).

| Command | Alias | Key args | What it does |
|---|---|---|---|
| `format` | — | `--object-count` (def 20), `--object-size` (def 2048), `--key-slot` (def `0x82`), `-g/--generate`, `--subject` | Provisions PIV objects; optionally generates ECDH key |
| `store` | — | `[files…]` (stdin if empty), `-n/--name`, `-e/--encrypted`, `-u/--unencrypted` | Stores one or more blobs |
| `fetch` | — | `[patterns…]` (glob), `-p/--stdout`, `-o/--output`, `-O/--output-dir` | Retrieves blob(s) |
| `list` | `ls` | `[pattern]` (glob), `-l/--long`, `-1`, `-t/--sort-time`, `-r/--reverse` | Lists blobs |
| `remove` | `rm` | `[patterns…]` (glob), `-f/--ignore-missing` | Removes blobs |
| `fsck` | — | `-v/--verbose` | Store integrity check |
| `list-readers` | — | — | Lists PC/SC readers |

### `format`

- `--key-slot` accepts `0x`-prefixed hex or decimal; warns for
  non-standard PIV slots (outside `0x80–0x95`, `0x9A/9C/9D/9E`).
- With `-g/--generate`: calls `piv.generate_key(slot)` then
  `piv.generate_certificate(slot, subject)`.
- Without `-g`: verifies an existing certificate is present in the slot.
- Calls `Store::format(...)` to write fresh empty objects.

### `store`

- Positional `[files…]`: each file is stored under its basename.
- No files + `--name`: reads from stdin.
- `-n/--name` with a single file: overrides the stored name.
- `-e/--encrypted` / `-u/--unencrypted`: explicit encryption choice
  (default: encrypted if an ECDH key slot is present).
- Performs basename-collision check and all-or-nothing capacity check
  before writing anything.

### `fetch`

- Patterns are glob-matched against stored blob names (via `globset`).
- Default: save each matching blob to a file in the current directory.
- `-O/--output-dir DIR`: write files into `DIR`.
- `-o/--output FILE`: write to a specific file (single match only).
- `-p/--stdout`: write to stdout (single match only).
- `-x/--extract`: hidden, deprecated alias for `-O`.

### `list`

- No pattern: list all blobs.
- With pattern: glob-filter.
- Default: names only (one per line).
- `-l/--long`: `<flag> <chunks> <date> <size> <name>` where flag is
  `-` (plain) or `P` (encrypted).  Date format: `%b %e %H:%M` if
  modified within 180 days, else `%b %e  %Y`.
- `-t`: sort by mtime descending; `-r`: reverse the sort.

### `remove`

- Patterns are glob-matched; duplicates (patterns matching the same
  blob) are deduplicated before deletion.
- A literal name that matches nothing is an error unless `-f`.
- A glob pattern that matches nothing is silently OK.
- Single `store.sync()` after all deletions.

### `fsck`

- Default: summary only — object count, total bytes, slot, store age,
  free/used blob counts, and `Status: OK` or `Status: ANOMALIES FOUND`.
- `-v/--verbose`: full per-object table before the summary.
- Anomalies detected: duplicate blob names, orphaned continuation chunks.
- Exits 1 if any anomaly is found.

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

### Tier 1 — Unit tests (`cargo test`)

No feature flags required.  52 tests, ~0.1 s.

| File | What it tests |
|---|---|
| `yb-core/src/store/mod.rs` | `Object` serialization round-trips; Python binary-compatibility vector |
| `yb-core/src/crypto.rs` | GCM round-trip; legacy CBC backward-compatibility via a `MockPiv` |
| `yb-core/src/orchestrator.rs` | `validate_name` accepts/rejects inputs |
| `yb-core/tests/virtual_piv_tests.rs` | `VirtualPiv`: store/fetch/remove, ECDH, key/cert generation, fixture round-trip |
| `yb-core/src/lib.rs` | Doc-test for `Context::new` signature |
| `yb/tests/cli_tests.rs` | **Direct-call CLI tests** (spec 0008): calls command handler functions via `Context::with_backend(VirtualPiv)` — 22 tests covering all 6 commands |

**Direct-call CLI tests** (spec 0008) verify command logic without
spawning a subprocess.  They use `Context::with_backend` so clap
parsing and `main.rs` wiring are bypassed — covered separately by the
subprocess tests.

### Tier 2 — Integration tests (NixOS VM + vsmartcard)

Feature flag: `integration-tests`.  Crate: `yb-piv-harness`.

Run with:
```
BINDGEN_EXTRA_CLANG_ARGS="-I${LIBCLANG_PATH}/clang/19/include" \
  cargo test -p yb-piv-harness --features integration-tests
```

#### `hardware_piv_tests` (10 tests)

A NixOS VM test (`pkgs.nixosTest`) spins up a guest with:
- `pcscd` (PC/SC daemon)
- `vsmartcard-vpcd` (virtual PC/SC reader)
- `piv-authenticator` (software PIV applet connected to vpcd)

The harness crate provides `with_vsc(f)`:
- **In-process mode** (developer nix-shell): starts `vpicc` in a
  background thread connected to the local vpcd socket.
- **External card mode** (VM): the vpcd socket is already running;
  `with_vsc` connects to it.

Tests are serialized (`RUST_TEST_THREADS=1`) — shared virtual card state.

#### `yb_cli_tests` (27 tests) — spec 0009

Subprocess tests: invoke the compiled `yb` binary via
`std::process::Command`.  Tests cover clap argument parsing, env vars,
PIN resolution order, exit codes, stderr content, and all six commands.

**`YB_FIXTURE` escape hatch:** when set, `Context::new` and
`list_readers::run` both load a `VirtualPiv` from the named YAML file
instead of opening a hardware card.  After each successful command,
`main.rs` calls `ctx.piv.save_fixture(path)` to persist mutations
(key generation, object writes) back to disk.  This is what allows
`yb format` in one subprocess to be visible to `yb store` in the next.

**`YB_BIN` override:** the `yb_cli_tests` binary finds the `yb`
executable via `YB_BIN` env var (injected in the VM `testScript`) or
falls back to `<CARGO_MANIFEST_DIR>/../target/debug/yb` for local runs.

**Fixture-per-test pattern:** each test calls `Fixture::new()` which
copies `with_key.yaml` to a `TempDir`, then calls `Fixture::format()`
(runs `yb format -g`) to initialize the store, then runs the actual
test steps.

Both test binaries are extracted by `harnessTestBin` and placed in
`$out/bin/`.  The VM `testScript` runs both with `RUST_TEST_THREADS=1`:

```python
out = machine.succeed("RUST_TEST_THREADS=1 hardware_piv_tests 2>&1")
out = machine.succeed(
    f"RUST_TEST_THREADS=1 YB_BIN={ybRust}/bin/yb yb_cli_tests 2>&1"
)
```

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
to the YubiKey only when `Store::sync` is called.  Progress is shown
via an `indicatif` bar; suppressed when `--quiet` / `ctx.quiet` is set.

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
| `0x5F_0000` – `0x5F_0013` | yb blob store (default 20 objects) |
| `0x5F_C109` | PRINTED — PIN-protected management key |
| `0x5F_FF00` | ADMIN DATA — mgmt key storage mode flags |
| `0x5F_C10A` | Key history |
| `0x5F_C101` – `0x5F_C10F` | Certificate slots (9A, 9C, 9D, 9E, 82–95) |

Default key slot for ECDH encryption: **0x82** (first retired key slot).
The corresponding certificate is written to the slot's certificate object
by `yb format --generate`.

---

## 14. Future Opportunities

### Dynamic PIV object sizing

See **[spec 0010](../docs/specs/0010-dynamic-object-sizing.md)** for the full
specification.

The current store writes every PIV object at a fixed `object_size`, padding
the last chunk of every blob with zeros.  Average waste: `object_size / 2`
bytes per blob.

The proposed solution writes each object at **exactly the size its content
requires** — no padding.  Empty reserved slots become 9-byte sentinels.
`MAX_OBJECT_SIZE = 3052` (the PIV slot maximum) replaces `object_size` as a
build-time constant; `--object-size` is removed from `yb format`.

**Backward compatibility** is inherent in the existing design: `from_device`
already infers each object's size from the `GET DATA` response length.  A
uniform-size store is just a special case where all responses happen to be
the same length.  No header changes are needed.

**Capacity reporting** splits into two independent resources:

- *Slot count* — fixed at format time; limits how many distinct blob chunks
  can coexist.
- *NVM bytes* — dynamic and shared with other PIV users (certificates, etc.).

`fsck` reports free capacity conservatively as
`min(free_slots × MAX_OBJECT_SIZE, nvm_remaining)`, where `nvm_remaining` is
derived by summing the sizes of all objects currently written to the device.
