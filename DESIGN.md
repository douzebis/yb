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
                           │
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
- `list_readers()`: Enumerate connected PIV devices
- `read_object(reader, id)`: Read binary data from PIV object
- `write_object(reader, id, data)`: Write binary data to PIV object
- `verify_reader(reader, id)`: Verify PIN and flash device

**Implementation Details**:
- All operations use `yubico-piv-tool` as subprocess
- Binary format for all object I/O
- Error handling via `subprocess.CalledProcessError`
- No caching - always reads fresh from device

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
│   ├── auxiliaries.py       # Helper functions
│   ├── parse_int.py         # Integer parsing utilities
│   └── x509_subject.py      # X.509 subject handling
├── pyproject.toml           # Python package metadata
├── default.nix              # Nix build configuration
├── shell.nix                # Development shell
├── README.md                # User documentation
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
