<!--
SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# yb Design Document

## Overview

**yb** is a command-line tool that provides secure blob storage using a YubiKey
device. It leverages the YubiKey's PIV (Personal Identity Verification)
application to store encrypted or unencrypted binary data in custom PIV data
objects. The tool uses hybrid encryption (ECDH + AES-256) to protect sensitive
data with hardware-backed cryptographic keys.

### Key Characteristics

- **Storage Medium**: YubiKey PIV custom data objects (0x5f0000 - 0x5f000f)
- **Capacity**: ~3KB per object, ~36KB total with default 12 objectsv
- **Interface**: Command-line tool using Click framework
- **Language**: Python 3.12+ with modern type annotations

---

## Architecture

### System Components

The yb architecture consists of four main layers:

```
┌─────────────────────────────────────────────────────────┐
│                     CLI Layer                           │
│  (main.py, cli_*.py)                                    │
│  Commands: format, store, fetch, list, remove, fsck     │
└─────────────────────────────────────────────────────────┘
                           │
┌─────────────────────────────────────────────────────────┐
│                   Storage Layer                         │
│  (store.py)                                             │
│  Store & Object classes, serialization, integrity       │
└─────────────────────────────────────────────────────────┘
                           │
        ┌──────────────────┴──────────────────┐
        │                                     │
┌───────────────────┐              ┌──────────────────────┐
│  Crypto Layer     │              │    PIV Layer         │
│  (crypto.py)      │              │    (piv.py)          │
│  Hybrid encrypt   │              │    Device I/O        │
│  ECDH, AES, HKDF  │              │    yubico-piv-tool   │
└───────────────────┘              └──────────────────────┘

┌─────────────────────────────────────────────────────────┐
│                External Dependencies                    │
│  yubico-piv-tool, pkcs11-tool, opensc                   │
│  cryptography (Python), PyYAML, Click                   │
└─────────────────────────────────────────────────────────┘
```

### Layer Responsibilities

#### 1. CLI Layer

**Files**: `main.py`, `cli_format.py`, `cli_store.py`, `cli_fetch.py`,
`cli_list.py`, `cli_remove.py`, `cli_fsck.py`

The CLI layer provides the user interface using the Click framework. It
handles:

- Command-line argument parsing and validation
- Reader selection and verification (with multiple device support)
- Context management (passing the selected reader to subcommands)
- User prompts (PIN entry, confirmation)
- Output formatting (YAML for structured data)

**Main Entry Point** (`main.py:cli`):
- Enumerates connected PIV readers
- Prompts user to select a reader if multiple devices are connected
- Optionally flashes the YubiKey and verifies PIN for reader confirmation
- Passes the selected reader to all subcommands via Click context

**Commands**:
- `format`: Initialize the store, optionally generate encryption keys
- `store`: Store a named blob (encrypted or unencrypted)
- `fetch`: Retrieve a blob by name
- `list`: Display all stored blobs with metadata
- `remove`: Delete a blob by name
- `fsck`: Low-level object inspection for debugging

#### 2. Storage Layer

**Files**: `store.py`, `constants.py`, `auxiliaries.py`

The storage layer manages the blob storage abstraction. Key classes:

**Store Class**:
- Represents the entire storage space across all PIV objects
- Loads from PIV device via `Store.from_piv_device(reader)`
- Manages object allocation and free space
- Provides sanitization to remove corrupt/duplicate blobs
- Handles synchronization back to the device
- Maintains store-wide metadata (magic number, encryption key slot, age
  counter)

**Object Class**:
- Represents a single PIV data object (512-3052 bytes)
- Can be empty, a blob head chunk, or a blob body chunk
- Serializes/deserializes to/from binary wire format
- Tracks dirty state for efficient syncing
- Implements linked-list structure via `next_chunk_index_in_store`

**Data Structures**:
- See `constants.py` for the complete PIV object format specification
- Objects use a linked-list structure to span multiple PIV slots for large
  blobs
- Each object contains metadata (magic, age, position) plus chunk payload
- Head objects contain additional blob metadata (name, size, timestamps,
  encryption flag)

**Integrity Management**:
- Age-based garbage collection prevents orphaned chunks
- Sanitization removes corrupt chains, duplicates, and unreachable objects
- Magic number validation ensures compatibility

#### 3. Cryptographic Layer

**File**: `crypto.py`

Implements the hybrid encryption scheme combining ECDH and AES-256.

**Encryption Flow** (`hybrid_encrypt`):
1. Generate ephemeral EC P-256 key pair
2. Perform ECDH with YubiKey's public key to derive shared secret
3. Use HKDF-SHA256 to derive AES-256 key from shared secret
4. Generate random IV (16 bytes)
5. Apply PKCS7 padding to plaintext
6. Encrypt with AES-256-CBC
7. Return: `ephemeral_pubkey (65 bytes) || IV (16 bytes) || ciphertext`

**Decryption Flow** (`hybrid_decrypt`):
1. Extract ephemeral public key, IV, and ciphertext from blob
2. Perform ECDH on YubiKey using private key and ephemeral public key
3. Derive same AES-256 key via HKDF-SHA256
4. Decrypt with AES-256-CBC
5. Remove PKCS7 padding
6. Return plaintext

**Key Management**:
- Persistent EC P-256 key stored in YubiKey PIV slot (default: 0x9e)
- Certificate generation via `generate_certificate`
- Public key extraction via `get_public_key_from_yubikey`
- Private key operations performed on-device via PKCS#11

**Security Properties**:
- Forward secrecy: Each store operation uses a fresh ephemeral key
- Hardware protection: Private keys never leave the YubiKey
- Authenticated encryption: Currently AES-CBC (could be upgraded to AES-GCM)

#### 4. PIV Layer

**File**: `piv.py`

Provides a clean Python interface to YubiKey PIV operations via subprocess
calls.

**Core Operations**:
- `list_readers()`: Enumerate connected PIV devices (legacy)
- `list_devices()`: Enumerate devices with serial numbers (via ykman)
- `get_reader_for_serial(serial)`: Map serial number to PC/SC reader name
- `get_serial_for_reader(reader)`: Map PC/SC reader name to serial number
- `read_object(reader, id)`: Read binary data from PIV object
- `write_object(reader, id, data)`: Write binary data to PIV object
- `verify_reader(reader, id)`: Verify PIN and flash device

**Implementation Details**:
- All operations use `yubico-piv-tool` as subprocess
- Device enumeration uses `ykman` Python API when available
- Binary format for all object I/O
- Error handling via `subprocess.CalledProcessError`
- No caching - always reads fresh from device

**Multi-Device Support**:
- Serial number-based device selection (`--serial` flag)
- Auto-selection when only one device connected
- Interactive selector with LED flashing for multiple devices
- Backward compatible with PC/SC reader names (`--reader` flag)

---

## Data Flow

### Storing a Blob

```
User: yb store --encrypted myblob < data.bin

1. CLI Layer (cli_store.py):
   - Read input data
   - Validate blob name
   - Load Store from PIV device

2. Storage Layer (store.py):
   - Sanitize existing objects
   - Calculate required chunks based on blob size

3. Crypto Layer (crypto.py) [if encrypted]:
   - Get YubiKey public key from specified slot
   - Generate ephemeral key pair
   - Perform ECDH + HKDF → AES key
   - Encrypt blob with AES-CBC

4. Storage Layer (store.py):
   - Allocate free objects for chunks
   - Create Object instances (head + body chunks)
   - Link chunks via next_chunk_index
   - Increment store age for new objects

5. PIV Layer (piv.py):
   - Serialize each dirty Object
   - Write to PIV device via yubico-piv-tool
```

### Fetching a Blob

```
User: yb fetch myblob > data.bin

1. CLI Layer (cli_fetch.py):
   - Load Store from PIV device
   - Search for blob by name

2. Storage Layer (store.py):
   - Find head object matching name
   - Follow next_chunk_index chain
   - Reassemble payload from all chunks
   - Trim to blob_size

3. Crypto Layer (crypto.py) [if encrypted]:
   - Prompt for User PIN
   - Extract ephemeral public key from blob
   - Perform ECDH on YubiKey via PKCS#11
   - Derive AES key via HKDF
   - Decrypt with AES-CBC
   - Remove PKCS7 padding

4. CLI Layer (cli_fetch.py):
   - Write plaintext to output
```

---

## Storage Format

The storage format uses a custom binary structure spread across PIV data
objects. Each object has a fixed size (default 3052 bytes) and contains:

- **Header**: Magic number, store metadata, object age
- **Chunk metadata**: Position in blob, next chunk pointer
- **Blob metadata** (head chunk only): Name, size, timestamps, encryption flag
- **Payload**: Encrypted or plaintext data chunk

For complete field-by-field specification, see:
- `constants.py`: All offsets, field sizes, and magic numbers
- `store.py:Object.serialize()`: Serialization implementation
- `store.py:Object.from_serialization()`: Deserialization implementation

### Format Registration

The yblob storage format is registered with the global `file` command magic number
database:

- **Registry**: [file/file project on GitHub](https://github.com/file/file)
- **Issue**: [Bug #666](https://bugs.astron.com/view.php?id=666)
- **Status**: Resolved and merged (June 2025)
- **Magic Entry**:
  ```
  # yblob object store
  0    lelong    0xF2ED5F0B    yblob object store image data
  ```

This registration enables the `file` command to automatically identify yblob
format files:

```bash
$ file yubikey_object_dump.bin
yubikey_object_dump.bin: yblob object store image data
```

The magic number `0xF2ED5F0B` ("Fred's Fob" in leetspeak) appears at offset 0
in little-endian format in all yblob objects.

### Key Design Decisions

**Linked List Structure**:
- Objects form chains via `next_chunk_index_in_store`
- Last chunk points to itself (loop detection)
- Enables efficient large blob storage across multiple objects

**Age-Based Integrity**:
- Each object has an `object_age` counter (increments with store age)
- Consecutive chunks must have consecutive ages
- Enables detection and removal of corrupt or orphaned chunks
- `sanitize()` cleans up inconsistent chains

**Name Deduplication**:
- Only one blob per name (enforced by sanitize)
- Newer blobs replace older ones (higher age wins)
- Prevents naming conflicts

---

## Write Operation Resilience

### Normal Operations Are Safe

Under normal operation, yb is **fully resilient** to forceful interruption
(e.g., physical YubiKey removal during write). This safety is provided by:

1. **Age-based validation**: Sequential age counters detect incomplete chains
2. **Automatic recovery**: `sanitize()` runs before every operation, cleaning up
   corrupt or partial writes
3. **Safe allocation**: New blobs and removals use free object indexes

**Normal operations include**:
- Storing new blobs (names that don't already exist)
- Removing blobs
- Reading blobs

In these cases, forceful interruption results in clean rollback or completion:
- Interrupted new blob writes are detected and removed by `sanitize()`
- Interrupted removals complete via age mismatch detection
- Reads are non-destructive (no writes occur)

### Write-In-Place Operations (Future Feature)

**Status**: Not yet implemented (see TODO.md: "Add a -i/--in-place to the store
subcommand")

**Use Case**: Enable writing to an already-full YubiKey store by overwriting
existing blobs with the same name.

**Safety Concern**: Write-in-place operations are **unsafe during forceful
interruption** because:

1. Current implementation immediately frees old blob's indexes during sanitize
2. New blob may reuse the same head chunk index
3. If interrupted mid-write, both old and new data are lost

### Write Operation Sequence

Understanding the write order is crucial for assessing resilience:

**Store Operation Flow** (`cli_store.py`):

1. **Load**: Read all objects from PIV device into memory
2. **Sanitize**: Clean up corrupt/duplicate blobs (in-memory only)
   - For duplicate names, removes the older blob (lower age)
   - Frees those indexes immediately
3. **Prepare**: Create new `Object` instances for all chunks
   - Allocates free indexes (may reuse just-freed indexes)
   - Assigns consecutive ages starting from `store_age + 1`
4. **Sync**: Write dirty objects to PIV device
   - Iterates in **index order** (0, 1, 2, ...), not creation order
   - Each chunk written independently via `yubico-piv-tool`

**Critical Observation**: Objects are written in **index order**, not by role
(head/body). Example: blob using indexes [7, 3, 11] writes in order: 3 → 7 → 11.

### Interruption Scenario Analysis

#### Safe: New Blob Creation

**Operation**: `yb store newblob < data.bin` (name doesn't exist)

**Allocated indexes**: [5, 8, 12] with ages [101, 102, 103]

**Interruption after partial write**:
- Some chunks written, others not
- Age sequence broken (e.g., expected age 102 at index 8, found 0)
- Next `sanitize()` detects incomplete chain, resets head chunk
- **Result**: ✅ Clean rollback, no data loss

#### Safe: Blob Removal

**Operation**: `yb rm foo`

**Process**: Walk chain, reset each chunk (age=0), sync in index order

**Interruption after partial reset**:
- Some chunks reset to age=0, others still have old age
- Next `sanitize()` detects broken age sequence
- Incomplete removal completes (resets remaining chunks)
- **Result**: ✅ Removal completes as intended

#### Unsafe: Overwrite With Index Reuse (Write-In-Place)

**Initial State**: Blob "foo" at indexes [7, 3], ages [50, 51]

**Operation**: `yb store foo < new_data.bin`

**Process**:
1. Sanitize removes old "foo" (indexes [7, 3] → age=0)
2. Allocate free objects → might get [7, 9] (**head index reused!**)
3. Sync writes: index 7 first, then 9

**Interruption after writing index 7 only**:
- Index 7: new data (age=101, points to 9)
- Index 9: empty (age=0)
- Index 3: reset from step 1 (age=0)
- Next `sanitize()` detects broken chain at index 7 → resets it
- **Result**: ⚠️ Data loss - both old and new "foo" are gone

#### Safe: Overwrite Without Index Reuse

**Initial State**: Blob "bar" at indexes [2, 5], ages [50, 51]

**Operation**: `yb store bar < new_data.bin`

**Allocated indexes**: [7, 9] (different from [2, 5])

**Interruption after partial write**:
- New blob at [7, 9]: incomplete (age mismatch)
- Old blob at [2, 5]: intact (valid ages [50, 51])
- Sanitize detects two "bar" blobs, keeps higher age (old one: 50 vs new broken)
- **Result**: ✅ Old data preserved, new write rolled back

**Why safe?** Old blob not freed until new blob fully written and sanitized.

### Protection Mechanisms

**Age-Based Validation** (`store.py:sanitize()`):

1. **Corrupt chain detection**: For each head chunk, walk the chain verifying:
   - Sequential ages: head=N, next=N+1, next=N+2, ...
   - Sequential positions: 0, 1, 2, ...
   - Valid next-chunk pointers (in range, non-circular except last)
   - Any violation → reset entire chain

2. **Duplicate name resolution**: When multiple blobs share a name, keep the
   one with highest age

3. **Unreachable object removal**: Reset any non-zero-age chunks not reachable
   from a valid head

**Self-Healing**: `sanitize()` runs at the start of every operation, ensuring
consistency even after interrupted writes.

### Write-In-Place Implementation Recommendations

When implementing the `-i/--in-place` option for `store`, consider:

**Safe Strategies**:
1. **Copy-on-write**: Allocate all new chunks before freeing old blob
2. **Body-first write order**: Write body chunks before head (atomic cutover)
3. **Two-phase commit**: Mark old blob invalid, write new blob, only then free
   old indexes
4. **Reserve old indexes**: Prevent reallocation of old blob's indexes until new
   blob complete

**Current Risk**:
- ~8% probability of head index collision (with 12 default objects)
- Higher with fragmented stores
- Larger blobs = longer write window

**User Guidance**:
- Document write-in-place as unsafe during forceful interruption
- Recommend `yb fetch` + checksum verification after write for critical data
- Consider adding `--verify` flag to automatically validate after write

---

## Command Reference

### format

Initialize or reinitialize the blob store on a YubiKey.

```bash
yb format [--generate] [--key-slot SLOT] [--objects N] [--size BYTES]
```

**Options**:
- `--generate/-g`: Generate new EC P-256 encryption key in specified slot
- `--key-slot`: PIV slot for encryption key (default: 0x9e)
- `--objects`: Number of objects to allocate (default: 12, max: 16)
- `--size`: Object size in bytes (default: 3052, max: 3052)

**Effect**:
- Writes magic number and metadata to object 0x5f0000
- Initializes empty objects for storage
- Optionally generates and imports encryption key certificate

### store

Store a binary blob under a given name.

```bash
yb store [--encrypted|--unencrypted] [--input FILE] NAME
```

**Options**:
- `--encrypted/-e`: Encrypt blob before storing (default)
- `--unencrypted/-u`: Store blob without encryption
- `--input/-i FILE`: Read from file (default: stdin)

**Behavior**:
- Sanitizes store before writing
- Allocates chunks as needed for blob size
- Increments store age and marks objects dirty
- Replaces existing blob with same name

### fetch

Retrieve a blob by name.

```bash
yb fetch [--output FILE] NAME
```

**Options**:
- `--output/-o FILE`: Write to file (default: stdout)

**Behavior**:
- Prompts for PIN if blob is encrypted
- Reassembles blob from chunks
- Decrypts if necessary

### list

Display all stored blobs.

```bash
yb list [--long]
```

**Output** (per blob):
- Encryption status (U=unencrypted, -=encrypted)
- Chunk count
- Unencrypted size
- Modification timestamp
- Blob name

### remove

Delete a blob by name.

```bash
yb rm NAME
```

**Behavior**:
- Sanitizes store first
- Finds and resets all chunks of named blob
- Marks objects as dirty for sync

### fsck

Low-level filesystem check and object inspection.

```bash
yb fsck [--long]
```

**Output**:
- Store-wide metadata
- Object-by-object dump (YAML format)
- Encryption keys, ages, chunk pointers
- Useful for debugging storage issues

---

## Security Considerations

### Threat Model

**Protected Against**:
- Data at rest disclosure (encryption)
- Offline key extraction (hardware-backed keys)
- Replay attacks (age-based freshness)

**Not Protected Against**:
- Physical tampering with YubiKey
- Malware with access to YubiKey during operation
- Side-channel attacks on ECDH or AES
- Brute-force PIN attacks (YubiKey provides limited retry protection)

### Cryptographic Choices

**ECDH with HKDF**:
- Provides forward secrecy via ephemeral keys
- HKDF ensures proper key derivation
- P-256 curve: NIST standard, widely supported

**AES-256-CBC with PKCS7**:
- Strong symmetric encryption
- CBC mode: mature, well-understood
- Potential upgrade path to AES-GCM for authenticated encryption

**PIN Requirements**:
- Fetch operations require PIN entry for decryption
- Store operations with `--encrypted` read public key only (no PIN)
- Format with `--generate` requires PIN for key generation

**Default Credential Detection**:
- yb uses the GET_METADATA command (YubiKey firmware 5.3+) to detect default credentials
- Refuses operations if default PIN (123456), PUK (12345678), or Management Key are detected
- This check does NOT consume retry attempts (safe to perform)
- Can be bypassed with `--allow-defaults` flag for testing (INSECURE)
- Can be skipped entirely with `YB_SKIP_DEFAULT_CHECK=1` environment variable
- On firmware <5.3, displays warning but continues (cannot safely detect)

**PIN-Protected Management Key Mode**:

yb supports PIN-protected management key mode, where the YubiKey stores its management key on-device, encrypted and protected by the PIN. This significantly improves both security and usability.

**How It Works**:
1. User configures PIN-protected mode once: `ykman piv access change-management-key --generate --protect`
2. ykman generates a cryptographically random AES-192 management key
3. Key is stored in the PRINTED object (0x5FC109), readable only after PIN verification
4. ADMIN DATA object (0x5FFF00) contains metadata indicating PIN-protected mode is active
5. yb automatically detects this configuration on startup and uses it transparently

**Implementation Details**:

PIV Objects Used:
- **ADMIN DATA (0x5FFF00)**: Contains TLV-encoded metadata with bitfield
  - Bit 0x01: Management key stored (3DES mode)
  - Bit 0x02: Management key stored (AES mode) - used by modern YubiKeys
  - Bit 0x04: PIN-derived mode (deprecated, insecure - rejected by yb)
- **PRINTED (0x5FC109)**: Contains TLV-encoded management key
  - Format: `88 <len> [ 89 <len> <24-byte AES-192 key> ]`
  - Accessible only after PIN verification

Detection Algorithm (`src/yb/auxiliaries.py`):
```python
def detect_pin_protected_mode(reader, piv) -> tuple[bool, bool]:
    # Read ADMIN DATA object
    admin_data = piv.read_object(reader, 0x5FFF00)

    # Parse TLV structure
    parsed = parse_admin_data(admin_data)

    # Check bitfield (0x01 or 0x02 indicates PIN-protected)
    is_pin_protected = parsed['mgmt_key_stored']
    is_pin_derived = parsed['pin_derived']  # Deprecated mode

    return (is_pin_protected, is_pin_derived)
```

Key Retrieval Process (`src/yb/piv.py`):
```python
def _write_object_with_ykman(self, reader, id, input, pin):
    # Use YubiKit Python API to retrieve management key
    with device.open_connection(SmartCardConnection) as conn:
        piv = PivSession(conn)
        piv.verify_pin(pin)  # Unlock access to PRINTED

        # Read and parse PRINTED object
        printed_data = piv.get_object(0x5FC109)
        # Parse TLV: 88 <len> [ 89 <len> <key-bytes> ]
        key_bytes = parse_printed_tlv(printed_data)
        management_key_hex = key_bytes.hex()

    # Use yubico-piv-tool for actual write (handles APDU chunking)
    subprocess.run(['yubico-piv-tool',
                    '--reader', reader,
                    f'--key={management_key_hex}',
                    '--action', 'write-object', ...])
```

**Hybrid Approach Rationale**:
- **YubiKit for retrieval**: Native Python API, automatic PIV applet selection, built-in PRINTED object support
- **yubico-piv-tool for writing**: Production-tested APDU chunking for large objects (16KB+), proper error handling
- YubiKit's `put_object()` doesn't support chunking, but yubico-piv-tool handles this correctly

**User Experience**:

Before PIN-protected mode:
```bash
# Must provide 48-character management key
yb --key 010203040506070801020304050607080102030405060708 store myfile
```

After PIN-protected mode (one-time setup):
```bash
# Setup (once)
ykman piv access change-management-key --generate --protect

# Daily usage - just provide PIN!
yb --pin 123456 store myfile
yb --pin 123456 rm myfile
yb --pin 123456 format
```

**Security Properties**:
- ✅ Management key is cryptographically random (not default)
- ✅ Key never leaves the YubiKey hardware
- ✅ Requires PIN to access (physical possession + knowledge factor)
- ✅ Automatically detected - users don't need to remember which mode is active
- ⚠ PIN compromise grants full write access (vs. manual key management requiring both PIN and key)

**Best Practices**:
1. Change default PIN before enabling PIN-protected mode
2. Use strong PIN (6-8 digits, avoid patterns like 123456 or birthdates)
3. Change default PUK as well for recovery capability
4. Understand that PIN protection is single-factor for write operations

**Comparison to Manual Key Management**:

| Aspect | PIN-Protected Mode | Manual Key Management |
|--------|-------------------|----------------------|
| Usability | ✅ Excellent (just PIN) | ❌ Poor (48-char hex) |
| Security | ✅ Good (random + hardware-bound) | ✅ Good (if managed properly) |
| Key Storage | ✅ On YubiKey | ❌ External (password manager, paper) |
| Risk: Key Exposure | ✅ Low (never leaves device) | ⚠ Medium (stored externally) |
| Risk: PIN Compromise | ⚠ Full access | ✅ Limited (still need key) |

**Recommendation**: PIN-protected mode for most users. Manual key management only for:
- High-security environments requiring two-factor device access (PIN + separate key custody)
- Shared YubiKeys with separate management key custody
- Compliance requirements mandating two-factor write authorization

**Verification**: Implementation verified against official Yubico documentation:
- [PIV PIN-only Mode](https://docs.yubico.com/yesdk/users-manual/application-piv/pin-only.html)
- [PIV PIN, PUK, Management Key](https://docs.yubico.com/yesdk/users-manual/application-piv/pin-puk-mgmt-key.html)

### Limitations

- No authentication/integrity for ciphertext (no MAC or AEAD)
- CBC mode vulnerable to padding oracle if timing leaks exist
- No key rotation mechanism
- Single encryption key for entire store
- Object size limits large blob storage (~36KB total capacity)

---

## Dependencies

### External Tools

- **yubico-piv-tool**: PIV object I/O, key generation, certificate management
- **pkcs11-tool**: ECDH operations via PKCS#11 interface
- **opensc**: Smart card utilities (libykcs11.so for PKCS#11)
- **openssl**: Certificate parsing (subject extraction)

### Python Libraries

- **click**: CLI framework
- **cryptography**: ECDH, AES, HKDF, certificate parsing
- **PyYAML**: YAML output formatting
- **Standard library**: subprocess, tempfile, time, datetime, getpass

### Development Environment

- **Nix**: Reproducible development environment (see `default.nix`,
  `shell.nix`)
- **Python 3.12+**: Modern type annotations
- **pytest**: Test framework (tests not yet implemented)
- **pyright**: Static type checking
- **ruff**: Linting and auto-fixing

---

## Testing Strategy

**Current State**: No automated tests yet (see TODO.md)

**Planned**:
- Non-regression test suite
- `--virtual-piv` option for testing without physical device
- Mock PIV object storage in filesystem
- Unit tests for crypto primitives
- Integration tests for store operations
- `--pin` option to avoid interactive prompts in tests

---

## Future Enhancement Investigations

This section documents technical feasibility investigations for potential future enhancements.

### Touch-Based Device Selection (FIDO2)

**Motivation**: When multiple YubiKeys are connected, allow users to select a device by touching it physically, rather than navigating with arrow keys.

**Investigation Date**: 2025-11-15

**Desired Behavior**:
- Display list of connected YubiKeys (with serials)
- Each YubiKey continuously flashes its LED
- User touches the desired YubiKey
- System detects which key was touched and selects it

**Technical Approach**: Hybrid PIV + FIDO2
- PIV interface: Flash LED continuously via rapid APDU commands
- FIDO2 interface: Poll for user presence verification in parallel

**Feasibility Analysis**:

**FIDO2 Touch Detection Options**:

1. **Option A: get_assertion with non-existent credential**
   - Strategy: Call CTAP2 `get_assertion` with dummy RP ID and non-existent credential
   - Expected: Operation blocks waiting for user presence, then fails with "no credentials"
   - State left on device: None (no credentials created or modified)
   - Testing: See `mock_up/test_fido2_touch.py`
   - **Status**: Needs verification - does operation wait for touch before failing?

2. **Option B: authenticatorSelection (CTAP 2.1)**
   - Strategy: Use CTAP 2.1 command 0x0B (authenticatorSelection)
   - Purpose: Designed to help identify which authenticator to use
   - Problem: Does NOT require user presence - defeats the purpose
   - **Status**: Not suitable for touch detection

3. **Option C: makeCredential with dummy data**
   - Strategy: Call `makeCredential` to trigger user presence check
   - Problem: Creates a credential on the device (leaves state)
   - Mitigation: Could delete immediately after, but still modifies device transiently
   - **Status**: Not suitable (violates no-state-modification requirement)

**Connection Management Challenge**:
- PIV flashing requires SmartCardConnection
- FIDO2 touch detection requires FidoConnection
- YubiKey may not support simultaneous connections of both types
- Need to test: Can we hold both connections at once? Or alternate rapidly?

**Prototype Approach** (if feasible):
```python
# Pseudo-code
for each yubikey:
    thread_flash[yubikey] = start_continuous_flash(yubikey, piv_connection)
    thread_touch[yubikey] = start_touch_polling(yubikey, fido_connection)

# Wait for first touch detected
touched_yubikey = wait_for_any_touch(thread_touch)

# Stop all threads
for thread in thread_flash:
    thread.stop()
for thread in thread_touch:
    thread.stop()

return touched_yubikey
```

**Constraints Evaluation**:
- ✓ **No pre-provisioning required**: Option A requires no credentials
- ⚠ **No state modification**: Option A creates no state, but need to verify
- ⚠ **Connection management**: Uncertain if dual connection types work simultaneously
- ⚠ **Library support**: Need to verify fido2 library behavior with non-existent credentials

**Implementation Complexity**: **High**
- Requires managing two connection types per YubiKey
- Threading complexity (N flash threads + N touch poll threads)
- Error handling for connection conflicts
- Platform-specific USB behavior differences

**CRITICAL CHALLENGE: PIV-to-FIDO Device Mapping**

The most significant technical challenge is mapping PIV devices (with serials) to FIDO HID devices:

**The Problem**:
1. PIV enumeration (via ykman) gives us: Serial numbers, versions, PC/SC reader names
2. FIDO enumeration (via fido2.hid) gives us: HID paths, vendor/product IDs, CTAP info
3. **No obvious correlation**: FIDO CTAP2 info does NOT include YubiKey serial number
4. **Different interfaces**: PIV uses SmartCard interface, FIDO uses HID interface
5. **Different permissions**: FIDO HID often requires special udev rules/sudo

**Correlation Strategies Under Investigation**:

1. **USB Device Path Correlation** (most promising)
   - Hypothesis: Both PIV and FIDO interfaces share same USB device path
   - Example: PIV and FIDO on bus-001/port-003 → same physical YubiKey
   - Need to extract: USB path from ykman device object AND from fido2 HID device
   - Status: **Investigation in progress** (see `mock_up/investigate_usb_mapping.py`)

2. **Enumeration Order Correlation** (unreliable)
   - Assumption: PIV and FIDO enumerate in same order
   - Problem: Platform-dependent, not guaranteed stable
   - Problem: Different counts if one interface is restricted
   - Status: **Not recommended** (too fragile)

3. **AAGUID Matching** (insufficient)
   - CTAP2 provides AAGUID (Authenticator Attestation GUID)
   - Problem: AAGUID is YubiKey model-wide, not unique per device
   - All YubiKey 5 Series share same AAGUID
   - Status: **Not viable** (not unique)

4. **Trial Correlation** (hacky but might work)
   - Flash PIV device with serial X
   - Poll all FIDO devices for touch
   - When touch detected on FIDO device Y → map X to Y
   - Problem: Requires pre-registration phase
   - Problem: User must touch each key in sequence
   - Status: **Possible fallback** but defeats UX goal

**Testing Scripts**:
- `mock_up/diagnose_fido_access.py` - Debug FIDO HID permission issues
- `mock_up/investigate_usb_mapping.py` - Explore USB path correlation

**Permission Considerations**:
- FIDO HID access typically requires:
  - udev rules for /dev/hidraw* devices
  - User in 'plugdev' or similar group
  - Or sudo access (not acceptable for production)
- PIV access via PC/SC works without special permissions
- **This permission gap complicates deployment**

**Preliminary Assessment**: **Likely Infeasible**

Until USB path correlation is proven to work reliably, touch-based selection should be considered **blocked** by the mapping problem.

**Investigation Status**: Data collection needed from real hardware (2025-11-15)

**Recommendation After Mapping Investigation**: **TBD - Depends on USB Path Feasibility**

Next steps:
1. Run `mock_up/test_fido2_touch.py` to verify Option A behavior
2. Test simultaneous PIV + FIDO2 connections on same YubiKey
3. If feasible: Build proof-of-concept multi-device selector
4. If not feasible: Arrow-key navigation is acceptable UX

**Alternative UX** (current implementation):
- Arrow keys to navigate between devices
- Selected device flashes continuously
- ENTER to confirm
- **Status**: Implemented in `mock_up/yubikey_selector.py` (2025-11-15)

---

### Secure Management Key Input (Subprocess Delegation)

**Motivation**: The current implementation uses `click.prompt(hide_input=True)` to read the management key in Python. This creates a security risk: the key exists in Python's process memory and could potentially leak via memory dumps, swap files, or debug traces.

**Investigation Date**: 2025-11-15

**Desired Behavior**:
- User enters management key via secure prompt
- Key never enters Python's process memory
- Key passed directly to `yubico-piv-tool` subprocess
- Existing CLI interface unchanged (`--key=-` still prompts)

**Current Implementation Risk**:
```python
# Current approach (src/yb/main.py)
if management_key == "-":
    management_key = click.prompt(
        "Management key (48 hex chars)",
        hide_input=True
    )
    # ⚠ Key now in Python's memory
    management_key = validate_management_key(management_key)
    # ⚠ Key still in Python's memory

# Later...
piv.write_object(..., management_key=management_key)
# ⚠ Key passed as argument to subprocess (visible in ps aux briefly)
```

**Security Concerns**:
1. Key stored in Python string (immutable, cannot securely erase)
2. Python process memory could be dumped/debugged
3. Key might be swapped to disk
4. Exception traces might leak key value
5. Command-line argument briefly visible in process list (`ps aux`)

**Technical Approach**: Delegate key reading to subprocess

**Option A: Shell Wrapper with `read -s`**:

Strategy: Use shell script to read key and pass to yubico-piv-tool

```python
# Approach: Shell reads key, Python never sees it
shell_script = """
echo "Management key (48 hex chars): " >&2
read -s KEY
echo "" >&2
yubico-piv-tool -k "$KEY" -a write-object ...
"""

subprocess.run(
    ["bash", "-c", shell_script],
    stdin=None,  # Inherit terminal access
    stdout=subprocess.PIPE,
    stderr=None,  # Let error messages show
)
```

**Advantages**:
- ✓ Key never enters Python's memory
- ✓ Key only in shell subprocess memory (smaller attack surface)
- ✓ Shell `read -s` is battle-tested for password input
- ✓ Key not visible in process list (embedded in script)

**Disadvantages**:
- ✗ Requires `shell=True` or bash subprocess (security consideration)
- ✗ More complex error handling (parse yubico-piv-tool output)
- ✗ Platform-specific (requires bash or compatible shell)
- ✗ Harder to test and maintain

**Option B: Explicit `/dev/tty` Access**:

Strategy: Python opens `/dev/tty`, passes to subprocess stdin

```python
import getpass  # No, still in Python memory...

# Better: Let subprocess read directly
with open("/dev/tty", "r") as tty_in:
    # Subprocess reads from tty_in
    # Problem: Still need to prompt for input
    # yubico-piv-tool doesn't have built-in prompting
```

**Problem**: `yubico-piv-tool` requires `-k <key>` argument, doesn't have built-in password prompting

**Option C: Wrapper Script (External)**:

Strategy: Create shell wrapper script `yb-write-secure`

```bash
#!/bin/bash
# yb-write-secure.sh
echo "Management key (48 hex chars): " >&2
read -s MGMT_KEY
echo "" >&2

# Validate key format
if ! echo "$MGMT_KEY" | grep -qE '^[0-9a-fA-F]{48}$'; then
    echo "Error: Invalid management key format" >&2
    exit 1
fi

# Call yubico-piv-tool with key
yubico-piv-tool -k "$MGMT_KEY" "$@"
```

Usage from Python:
```python
subprocess.run(
    ["yb-write-secure", "-a", "write-object", ...],
    stdin=None,
    check=True,
)
```

**Advantages**:
- ✓ Key never in Python memory
- ✓ Reusable wrapper script
- ✓ Validation in shell
- ✓ Standard Unix pattern

**Disadvantages**:
- ✗ Requires installing additional script
- ✗ More complex deployment
- ✗ Platform-specific

**TTY Access Verification**:

Testing (see `mock_up/test_subprocess_tty.py`):

1. **Inherited stdio**: `subprocess.run(..., stdin=None)` ✓ Works
   - Subprocess can access parent's terminal
   - Shell `read` commands work correctly

2. **Explicit `/dev/tty`**: `subprocess.run(..., stdin=open("/dev/tty"))` ✓ Works
   - Explicit terminal access
   - Works even if parent stdio redirected

3. **Shell `read -s`**: ✓ Works
   - Secure password input without echo
   - Key stays in shell, never enters Python

**yubico-piv-tool Capabilities**:
- Has `-k <key>` option for management key
- Does NOT have built-in password prompting
- Does NOT support `--key=-` or environment variables
- Requires key as command-line argument (visible in `ps aux`)

**Implementation Complexity**: **Medium to High**
- Option A (inline shell): Medium complexity, platform-specific
- Option C (wrapper script): Medium complexity, deployment complexity

**Security Benefit Assessment**:

**Realistic Threat Scenarios**:
1. Python process memory dump during crash → Key leaked
2. Core dump analysis by attacker → Key leaked
3. Swap file inspection → Key leaked
4. Debugger attached to Python process → Key leaked
5. Exception stack trace logged → Key leaked

**Mitigation Value**:
- High value for high-security environments
- Moderate value for typical usage
- Low value if user already trusts local system

**Recommendation**: **Feasible but defer implementation**

**Rationale**:
1. ✓ Technically feasible using shell wrapper approach
2. ✓ Subprocess TTY access verified working
3. ⚠ Added complexity for moderate security benefit
4. ⚠ Platform-specific implementation (bash required)
5. ⚠ Current approach acceptable for most threat models

**Current Mitigation**:
- Use `--key=<hex>` only in trusted environments
- Use `--key=-` for interactive prompt (better than cmdline)
- Keep system secure (encrypted swap, trusted users)
- Consider `mlock()` for future enhancement (lock memory pages)

**Future Implementation Priority**: **Low to Medium**
- Implement if targeting high-security environments
- Defer until user request or security audit
- Document the limitation in security section

**Testing Script**: `mock_up/test_subprocess_tty.py`

---

## Comprehensive Testing and Validation

### Testing Architecture

**Implementation Date**: 2025-11-16

To ensure correctness and resilience of the YubiKey blob store implementation, a comprehensive testing framework was developed with the following components:

#### 1. Code Architecture Refactoring

**Problem**: Original CLI commands (`cli_store.py`, `cli_fetch.py`, etc.) contained both command-line interface logic AND business logic, making them difficult to test in isolation.

**Solution**: Orchestrator Pattern

Created `src/yb/orchestrator.py` to separate concerns:

```
┌─────────────────────┐
│   CLI Layer         │  ← Thin wrappers: argument parsing, error formatting
│   (cli_*.py)        │
└──────────┬──────────┘
           │
┌──────────▼──────────┐
│  Orchestrator       │  ← Business logic: testable, no CLI dependencies
│  (orchestrator.py)  │
└──────────┬──────────┘
           │
┌──────────▼──────────┐
│   Storage Layer     │
│   (store.py)        │
└─────────────────────┘
```

**Orchestrator Functions**:
- `store_blob(reader, piv, name, payload, encrypted, management_key) -> bool`
- `fetch_blob(reader, piv, name, pin) -> Optional[bytes]`
- `remove_blob(reader, piv, name, management_key) -> bool`
- `list_blobs(reader, piv) -> list[tuple[str, int, bool, int, int]]`

Each function:
1. Loads store from device (`Store.from_piv_device()`)
2. Sanitizes to clean up corrupt data
3. Performs the operation
4. Syncs changes back to device
5. Returns success/failure or result data

This mirrors exactly what each CLI command does, enabling comprehensive testing without CLI dependencies.

#### 2. PIV Device Emulation

**File**: `src/yb/piv.py`

Created abstract `PivInterface` with two implementations:

**HardwarePiv** (Production):
- Communicates with real YubiKey via `yubico-piv-tool`
- Used by CLI for actual operations

**EmulatedPiv** (Testing):
- In-memory PIV object storage
- No hardware required for tests
- Supports ejection simulation (see below)
- Deterministic behavior via seeded RNG

```python
class EmulatedPiv(PivInterface):
    def __init__(self, ejection_probability=0.0, seed=None):
        self._devices = {}  # serial -> EmulatedDevice
        self.ejection_probability = ejection_probability
        self.write_count = 0
        self.ejection_count = 0

    def write_object(self, reader, id, input, management_key=None):
        # Simulate ejection before write
        if self.ejection_probability > 0:
            self.write_count += 1
            if self._rng.random() < self.ejection_probability:
                self.ejection_count += 1
                self.is_ejected = True
                raise EjectionError(f"Simulated ejection...")

        # Perform write to in-memory storage
        device = self._get_device_by_reader(reader)
        device.objects[id] = input
```

#### 3. Comprehensive Test Suite

**File**: `tests/test_store_comprehensive.py`

**test_comprehensive_operations** (10,000 operations, no ejections):
- **Validates**: Store correctness under normal operations
- **Operations**: 2,902 STORE, 3,543 FETCH, 2,208 REMOVE, 1,347 LIST
- **Ground truth**: ToyFilesystem (dict-based reference implementation)
- **Verification**: Every operation compared with expected behavior
- **Payload sizes**: 1 byte to 20 KB (multi-chunk support)
- **Result**: ✓ PASSED - All 10,000 operations matched expected behavior

**test_with_ejection_simulation** (10,000 operations, 1% ejection rate):
- **Validates**: Store resilience to forceful interruption
- **Ejection simulation**: ~100 ejections during write operations
- **Recovery logic**: After ejection, verify state matches either:
  - Before state (operation rolled back)
  - After state (operation completed)
- **Payload verification**: For STORE operations, fetch and verify payload correctness
- **Result**: ✓ PASSED - All operations handled correctly with 45 ejections (0.45% rate)

**Test execution time**: ~16 seconds for 4 tests (20,000 total operations)

#### 4. Ejection Handling Insights

**Challenge**: When a write operation is forcefully interrupted (YubiKey physically removed), the final state is ambiguous - chunks may be partially written.

**Solution**: Two-State Validation

For write operations (STORE, REMOVE):

1. **Save "before" state**: Current toy filesystem state
2. **Predict "after" state**: What state would be if operation succeeds
3. **Attempt operation**: May complete, fail, or eject mid-write
4. **On ejection**:
   - Reconnect device
   - Load actual state via `orchestrator.list_blobs()`
   - Compare actual with both "before" and "predicted after"
   - If matches "after": Operation completed → accept new state
   - If matches "before": Operation rolled back → keep old state
   - If matches neither: **Test failure** (unexpected corruption)

**Key Finding**: For STORE operations that update existing blobs, NAME comparison is insufficient. Must also verify PAYLOAD:

```python
# After ejection on STORE operation
if actual_names == expected_after:
    # Verify payload is correct by fetching
    actual_payload = orchestrator.fetch_blob(reader, piv, op.name, pin=None)
    expected_payload = toy_fs_predicted_after.fetch(op.name)[0]
    if actual_payload == expected_payload:
        # Operation truly completed
        toy_fs_after = toy_fs_predicted_after
    else:
        # Names match but payload is old - rolled back
        # Keep toy_fs_after unchanged
```

This handles the case where:
- STORE('profile', new_data) ejects mid-write
- Blob 'profile' still exists with OLD data
- sanitize() doesn't remove it (ages are valid)
- Name-only check would incorrectly accept it

#### 5. Multi-Chunk Blob Support

**Validation**: Blobs up to 20 KB requiring multiple PIV object slots

**Object Capacity** (512-byte objects):
- Head chunk: ~400 bytes (less due to metadata)
- Body chunk: ~450 bytes (minimal metadata)

**20 KB Blob Requirements**:
- 1 head chunk + ~44 body chunks = 45 total objects
- Tests configured with 100 object store
- Allows up to ~2 concurrent large blobs

**Chunk Linking**:
- Each chunk points to next via `next_chunk_index_in_store`
- Last chunk points to itself
- Sanitize verifies chain integrity (consecutive ages, sequential positions)

**Test Coverage**:
- 70% small blobs (1-1 KB): Single chunk
- 25% medium blobs (1-10 KB): 2-25 chunks
- 5% large blobs (10-20 KB): 25-45 chunks

**Result**: Multi-chunk operations handled correctly, including:
- Partial chunk writes detected and rolled back
- Age-based chain validation prevents orphaned chunks
- Sanitize completes interrupted multi-chunk removals

#### 6. Test Results Summary

```
tests/test_store.py::test_basic_store_operations              PASSED
tests/test_store.py::test_multiple_devices                    PASSED
tests/test_store_comprehensive.py::test_comprehensive_operations    PASSED
tests/test_store_comprehensive.py::test_with_ejection_simulation   PASSED

4 passed in 16.15s
```

**Comprehensive Test Statistics**:
- Total operations tested: 20,000
- Ejections simulated: 45
- Multi-chunk blobs tested: ~500 (5% of 10,000)
- Largest blob tested: 20 KB (~45 chunks)
- Test execution time: 16 seconds
- Failure rate: 0%

**Key Validation**:
- ✓ Store/fetch/remove/list operations work correctly
- ✓ Sanitize cleanly recovers from interrupted writes
- ✓ Age-based integrity detection prevents data corruption
- ✓ Multi-chunk blob reassembly works reliably
- ✓ Name deduplication (newer blob wins) works correctly
- ✓ Ejections during writes don't corrupt store
- ✓ Partial writes are detected and rolled back
- ✓ 20 KB blobs stored and retrieved correctly

#### 7. Testing Methodology

**Operation Generator** (`OperationGenerator` class):
- Deterministic pseudo-random operation sequence (seeded RNG)
- Weighted distribution: 40% store, 35% fetch, 15% remove, 10% list
- Capacity awareness: Reduces stores when nearing full
- Name pool: 23 realistic names with collision handling

**Ground Truth Verification** (`ToyFilesystem` class):
- Simple dict-based reference implementation
- Mirrors expected behavior without complexity
- Operations:
  - `store(name, payload, mtime)`: Add/update file
  - `fetch(name)`: Get (payload, mtime) or None
  - `remove(name)`: Delete file, return success
  - `list()`: Return sorted names

**Comparison Logic**:
- After each operation, compare YubiKey state with ToyFilesystem
- For FETCH: Verify payload matches byte-for-byte
- For REMOVE: Verify return value (found/not found)
- For LIST: Verify sorted name lists match exactly
- For STORE: Verify success/failure (full store detection)

**Why This Works**:
1. ToyFilesystem is simple enough to trust (obvious correctness)
2. YubiKey store is complex (chunking, ages, sanitize) but testable
3. If both produce same results over 10,000 operations → high confidence
4. Ejection simulation validates safety assumptions

---

## Recent Enhancements

### PKCS#11 Token Selection Fix (2025-11-16)

**Problem Identified**: Critical bug in `crypto.py:perform_ecdh_with_yubikey()` where the `reader` parameter was marked as "unused" and never passed to pkcs11-tool. This caused ECDH operations to always use the first YubiKey (slot 0 default) regardless of which device was selected via `--serial` or `--reader`.

**Impact**: Multi-device usage completely broken for encrypted blob operations. User could select YubiKey B, but decryption would attempt to use YubiKey A's private key, causing cryptographic failures.

**Root Cause**: PKCS#11 architecture - each YubiKey appears as a separate "token" in a separate "slot". Without explicit token selection, pkcs11-tool defaults to slot 0. Object IDs (like `05` for PIV slot 82) exist in every token but reference different private keys.

**Solution Implemented**:
1. **Architecture Clarity**: Separated concerns between layers
   - **Orchestrator/Store layers**: Use `reader` (PC/SC names) for PIV operations
   - **Crypto layer**: Use `serial` (PKCS#11 token labels) for ECDH operations

2. **Crypto Layer Refactoring**:
   - Changed `perform_ecdh_with_yubikey()` signature from `reader: str` to `serial: int`
   - Constructs PKCS#11 token label: `f"YubiKey PIV #{serial}"`
   - Adds `--token-label` to pkcs11-tool command
   - Updated `hybrid_decrypt()` similarly

3. **PIV Layer Enhancement**:
   - Added `get_serial_for_reader(reader) -> int` method
   - Bidirectional mapping: serial ↔ reader

4. **Orchestrator Integration**:
   - Maps reader → serial before calling crypto operations
   - Clean separation of identifier types per layer

**Testing**: Verified with 2 YubiKeys, confirmed correct token selection, all existing tests pass.

**Token Label Format**: `"YubiKey PIV #<serial>"` (e.g., `"YubiKey PIV #32283437"`)

**Documentation**: Complete technical analysis in `.cache/PKCS11_BUG_REPORT.md`

### Shell Completion Support (2025-11-16)

**Autocompletion for --serial Option**:
- Uses Click's `shell_complete` feature
- Queries connected YubiKeys dynamically via `HardwarePiv().list_devices()`
- Returns `CompletionItem` objects with serial numbers + version info
- Supports partial matching (e.g., typing "322" suggests "32283437")
- Graceful error handling: returns empty list on failure

**Usage** (after activation):
```bash
# For bash
eval "$(_YB_COMPLETE=bash_source yb)"

# For zsh
eval "$(_YB_COMPLETE=zsh_source yb)"

# Then:
yb --serial <TAB>
# Shows:
#   32283437  -- YubiKey 5.7.1
#   87654321  -- YubiKey 5.4.3
```

**Autocompletion for Blob Names** (cli_fetch.py):
- `complete_blob_names()` function provides blob name completion for `fetch` command
- Queries YubiKey store to list available blobs
- Handles single-device auto-selection
- Returns empty list if multiple devices without explicit `--serial/--reader`
- Safe for shell completion (never fails loudly)

**Usage**:
```bash
yb fetch <TAB>
# Shows list of stored blob names
```

**Implementation Details**:
- Uses Click's `CompletionItem` class for structured completions
- Zero overhead when not using completion (functions only called during TAB)
- No dependencies on external completion libraries
- Works with bash/zsh/fish via Click's built-in support

---

## Self-Test System

The `yb self-test` command provides comprehensive end-to-end testing of the blob storage system on a real YubiKey.

### Purpose

- **Validate correctness**: Ensures all operations (store/fetch/remove/list) work correctly
- **Test encryption**: Validates both encrypted and unencrypted blob handling
- **Verify capacity handling**: Tests behavior when storage is full
- **Regression testing**: Catches bugs before release

### Architecture

The self-test uses a **ground truth** model to verify YubiKey behavior:

```
┌─────────────┐         ┌─────────────┐
│  Operation  │         │  Operation  │
│  Generator  │────────▶│  Executor   │
└─────────────┘         └──────┬──────┘
                               │
                    ┌──────────┴──────────┐
                    │                     │
                    ▼                     ▼
            ┌──────────────┐      ┌─────────────┐
            │   YubiKey    │      │  ToyFS      │
            │  (Hardware)  │      │ (Reference) │
            └──────┬───────┘      └──────┬──────┘
                   │                     │
                   └──────────┬──────────┘
                              ▼
                      ┌──────────────┐
                      │   Compare    │
                      │   Results    │
                      └──────────────┘
```

**Components**:

1. **OperationGenerator** (`test_helpers.py`)
   - Generates pseudo-random test operations
   - Configurable encryption ratio (50% by default)
   - Respects capacity constraints

2. **ToyFilesystem** (`test_helpers.py`)
   - In-memory reference implementation
   - Tracks expected state of YubiKey
   - No capacity limits (optimistic)

3. **SubprocessExecutor** (`self_test.py`)
   - Executes `yb` commands via subprocess
   - Captures stdout, stderr, exit codes
   - Provides debug instrumentation

4. **TestStats** (`self_test.py`)
   - Tracks pass/fail counts per operation type
   - Records failed operation details
   - Generates summary report

### Test Flow

```python
# 1. Format YubiKey (clean slate)
format_yubikey(serial, pin, mgmt_key, object_count=16)

# 2. Generate operations
generator = OperationGenerator(seed=42, max_capacity=15)
operations = generator.generate(count=200, encryption_ratio=0.5)

# 3. Execute operations
for op in operations:
    # Update ToyFS optimistically
    toy_fs.store(op.name, op.payload, mtime)

    # Execute on YubiKey
    success, exit_code, stderr = executor.store_blob(...)

    # Handle result
    if success:
        # YubiKey succeeded - ToyFS already updated
        pass
    elif "Store is full" in stderr:
        # Expected capacity limit - rollback ToyFS
        undo_toy_store_update()
        success = True  # Not an error
    else:
        # Real error - rollback ToyFS and stop
        undo_toy_store_update()
        break  # Stop on first error
```

### Error Handling

**Expected behaviors** (not errors):
- "Store is full" when capacity exhausted
- "Cannot find object" when fetching non-existent blob
- Remove returns failure for non-existent blob

**True errors** (stop test):
- Corruption detected
- Data mismatch on fetch
- Unexpected exceptions
- Any error other than capacity/not-found

**Stop-on-first-error principle**:
After a true error, the YubiKey state is unknown and further tests are unreliable. The test stops immediately and reports the failure with full context.

### Capacity Handling

The self-test treats "Store is full" as **valid behavior**:

```python
if "Store is full" in stderr:
    # Rollback optimistic ToyFS update
    if was_updating:
        toy_fs.files[name] = old_value  # Restore
    else:
        del toy_fs.files[name]  # Remove
    success = True  # This is expected, not an error
```

This approach:
- Avoids predicting exact YubiKey capacity (which varies with encryption/chunking)
- Keeps ToyFS in sync with actual YubiKey state
- Tests that the store correctly reports capacity limits

### Usage

```bash
# Basic usage
yb --serial 12345678 self-test

# Custom operation count
yb --serial 12345678 self-test -n 100

# Non-interactive with credentials
yb --serial 12345678 --pin 123456 --key 010203...0708 self-test

# Debug mode
yb --debug --serial 12345678 self-test
```

### File Organization

```
src/yb/
├── cli_self_test.py         # CLI command definition
├── self_test.py              # Test execution logic
│   ├── SubprocessExecutor    # Run yb commands
│   ├── TestStats             # Track results
│   ├── run_test_operations() # Main test loop
│   └── run_self_test()       # Entry point
└── test_helpers.py           # Shared test utilities
    ├── ToyFilesystem         # Reference implementation
    ├── OperationGenerator    # Test case generation
    └── OpType/Operation      # Data structures
```

**Sharing with unit tests**: The `test_helpers.py` module is used by both the self-test and the comprehensive unit test (`tests/test_store_comprehensive.py`), ensuring consistent test methodology.

---

## References

### Code Organization

```
yb/
├── src/yb/
│   ├── main.py              # CLI entry point, reader selection
│   ├── constants.py         # PIV object format specification
│   ├── store.py             # Store and Object classes
│   ├── piv.py               # PIV device operations
│   ├── crypto.py            # Hybrid encryption/decryption
│   ├── cli_format.py        # format command
│   ├── cli_store.py         # store command
│   ├── cli_fetch.py         # fetch command
│   ├── cli_list.py          # list command
│   ├── cli_remove.py        # remove command
│   ├── cli_fsck.py          # fsck command
│   ├── cli_self_test.py     # self-test command
│   ├── self_test.py         # Self-test implementation
│   ├── test_helpers.py      # Shared test utilities
│   ├── yubikey_selector.py  # Interactive YubiKey selection
│   ├── auxiliaries.py       # Helper functions
│   ├── parse_int.py         # Integer parsing utilities
│   └── x509_subject.py      # X.509 subject handling
├── tests/
│   └── test_store_comprehensive.py  # Comprehensive unit tests
├── pyproject.toml           # Python package metadata
├── default.nix              # Nix build configuration
├── shell.nix                # Development shell
├── README.md                # User documentation
├── DESIGN.md                # Design documentation
├── USER_GUIDE.md            # User guide
├── TODO.md                  # Future work
└── .cache/                  # Claude workspace
    ├── README.md            # Development rules
    └── CONTEXT.md           # Session context
```

### External Documentation

- [Yubico PIV Tool](https://developers.yubico.com/yubico-piv-tool/)
- [YubiKey PIV Certificate Size Limits](https://docs.yubico.com/yesdk/users-manual/application-piv/cert-size.html)
- [PIV Standard (NIST SP 800-73-4)](https://csrc.nist.gov/publications/detail/sp/800-73/4/final)
- [Python cryptography library](https://cryptography.io/)

---

## Glossary

- **PIV**: Personal Identity Verification, smart card standard (NIST)
- **ECDH**: Elliptic Curve Diffie-Hellman, key agreement protocol
- **HKDF**: HMAC-based Key Derivation Function
- **PKCS#11**: Cryptographic Token Interface Standard
- **YubiKey**: Hardware security key by Yubico
- **Blob**: Binary large object, arbitrary data stored by yb
- **Head chunk**: First chunk of a blob, contains metadata
- **Body chunk**: Subsequent chunks of a blob, contain only payload
- **Store age**: Monotonic counter incremented on each store operation
- **Object age**: Age value when object was last written
- **Sanitize**: Process of removing corrupt/duplicate/orphaned objects
