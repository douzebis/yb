# PIN and Management Key Analysis Report

## Executive Summary

The yubiblob CLI unnecessarily prompts for the YubiKey PIN in several scenarios where it is not required by the underlying PIV operations. The Management Key handling is generally correct, but the PIN verification mechanism adds friction to normal write operations.

### Key Findings

1. **Unnecessary PIN Verification**: Write operations (`store`, `rm`, `format`) prompt for PIN even though PIV write-object operations only require the Management Key, not the PIN.

2. **Default Credentials Risk**: Currently yubiblob requires non-default PIN/PUK and Management Key. While this improves security, it creates a usability challenge: users must provide a 48-character hex management key for every write operation.

3. **Solution: PIN-Protected Management Key Mode**: YubiKeys can store the management key on-device, encrypted and protected by the PIN. This provides both security (non-default, random management key) and convenience (users only provide PIN).

### Recommended Approach

**Phase 1**: Remove unnecessary PIN verification from write operations
- PIN should only be requested when cryptographically required (encrypted blob operations, key generation)
- Management key authentication is sufficient for write operations

**Phase 6**: Add support for PIN-protected management key mode
- Detect when YubiKey uses PIN-protected mode (read ADMIN DATA object 0x5FFF00)
- Automatically retrieve management key from PRINTED object (0x5FC109) after PIN verification
- Users only provide PIN, not the full management key

**Phase 5**: Enforce non-default credentials with helpful guidance
- Detect and refuse default PIN/PUK/Management Key
- Guide users to set up PIN-protected mode: `ykman piv access change-management-key --generate --protect`
- Provide `--allow-defaults` flag for testing/development

### User Experience After Implementation

**Current problematic workflow:**
```bash
$ yb store myfile
# Prompted for PIN (unnecessary)
# Must provide 48-char management key for every write
```

**Improved workflow with PIN-protected mode:**
```bash
# One-time setup:
$ ykman piv access change-management-key --generate --protect

# Daily usage (unencrypted blob):
$ yb store myfile
# No PIN prompt needed (Phase 1: unnecessary PIN verification removed)
# Management key retrieved automatically from YubiKey using PIN internally
# User doesn't see any prompts for simple operations

# Daily usage (encrypted blob):
$ yb store --encrypted myfile
# Prompted for PIN once (needed for encryption key access)
# Same PIN also unlocks management key from PRINTED object
# Single authentication for both operations
```

This combines security (random, non-default management key) with usability (no credential prompts for unencrypted operations, single PIN for encrypted operations).

**Note**: After Phase 1, write operations won't ask for PIN at all. However, PIN-protected management key mode works by having the YubiKey retrieve the management key internally when needed (user doesn't interact with this process). For encrypted operations, PIN is still needed for the actual cryptographic operation.

## Issues Identified

### 1. PIN Verification for Write Operations (HIGH PRIORITY)

**Location:** `src/yb/auxiliaries.py:15-42` (function `verify_device_if_needed`)

**Affected Commands:**
- `yb store` (`src/yb/cli_store.py:56`)
- `yb rm` (`src/yb/cli_remove.py:33`)
- `yb format` (`src/yb/cli_format.py:90` - except when `--generate` is used)

**Issue:**
These commands call `verify_device_if_needed()` which prompts for and verifies the YubiKey PIN before performing write operations. However, **PIV write-object operations only require the Management Key, not the PIN**.

**Technical Details:**
The YubiKey PIV application distinguishes between:
1. **Administrative operations** (write-object, etc.) - require Management Key only
2. **Cryptographic operations** (signing, decryption, ECDH) - require PIN

The `verify_device_if_needed()` function calls `piv.verify_reader()` which executes:
```
yubico-piv-tool --action verify-pin
```

This is unnecessary for operations that only write PIV objects. The actual write operation (`piv.write_object()` at `src/yb/piv.py:269-321`) only uses the management key.

**User Impact:**
- Users must enter their PIN for operations that don't cryptographically require it
- Added friction for basic operations like storing/removing unencrypted blobs
- Security theater: PIN verification doesn't add meaningful security since the operation doesn't use the PIN-protected private keys

**When PIN IS Actually Required:**
1. Generating certificates (`format --generate`) - the selfsign operation requires PIN
2. Fetching encrypted blobs - ECDH key derivation requires PIN
3. These cases already handle PIN correctly in their respective implementations

### 2. Confusing Message When PIN Provided via Command Line (MEDIUM PRIORITY)

**Location:** `src/yb/auxiliaries.py:37-38`

**Issue:**
The message "Confirm by entering your PIN..." is displayed even when the user has already provided the PIN via the `--pin` command-line flag.

**Code:**
```python
if pin is None:
    print('Confirm by entering your PIN...', file=sys.stderr)

if not piv.verify_reader(reader, 0x9a, pin=pin):
    raise click.ClickException('Could not verify the PIN.')
```

**Problem:**
The condition only checks if `pin is None` before printing the message, but the message suggests the user needs to "enter" the PIN. When PIN is provided via `--pin`, the message is misleading since no user interaction is required.

**User Impact:**
Confusion about whether they need to take action when they've already provided credentials

### 3. Management Key Handling (WORKING CORRECTLY)

**Location:** `src/yb/main.py:286-299`

**Current Behavior (CORRECT):**
- If `--key` is not specified: `management_key = None` → Uses YubiKey default key
- If `--key -` is specified: Prompts for management key (hidden input)
- If `--key <value>` is specified: Validates and uses the provided key

**Analysis:**
This implementation is correct. The management key is only requested when explicitly needed for non-default configurations.

## Commands Analyzed - Correctness

### Read-Only Commands (CORRECT)

1. **`yb ls`** (`src/yb/cli_list.py`)
   - ✅ Does NOT call `verify_device_if_needed`
   - ✅ Only reads PIV objects via `Store.from_piv_device()`
   - ✅ No PIN or Management Key needed

2. **`yb fsck`** (`src/yb/cli_fsck.py`)
   - ✅ Does NOT call `verify_device_if_needed`
   - ✅ Only reads and displays PIV objects
   - ✅ No credentials needed

3. **`yb fetch`** (`src/yb/cli_fetch.py`)
   - ✅ Does NOT call `verify_device_if_needed`
   - ✅ Intelligently checks if blob is encrypted (lines 153-161)
   - ✅ Only prompts for PIN if fetching encrypted blob (lines 164-171)
   - ✅ PIN used for PKCS#11 ECDH operation (actually required)
   - **EXCELLENT IMPLEMENTATION** - this is how PIN handling should work

### Write Commands (ISSUES PRESENT)

1. **`yb store`** (`src/yb/cli_store.py:56`)
   - ❌ Calls `verify_device_if_needed()` unnecessarily
   - Uses management key for write (correct)
   - Only needs PIN if storing encrypted blob for key generation (but that's during encryption setup, not the write itself)

2. **`yb rm`** (`src/yb/cli_remove.py:33`)
   - ❌ Calls `verify_device_if_needed()` unnecessarily
   - Uses management key for write (correct)
   - Never needs PIN for the removal operation

3. **`yb format`** (`src/yb/cli_format.py`)
   - ❌ Calls `verify_device_if_needed()` when `--generate` is NOT used (line 90)
   - ✅ Correctly skips verification when `--generate` IS used (line 89)
   - When generating: `Crypto.generate_certificate()` handles PIN during selfsign (correct)
   - Uses management key for all write operations (correct)

## Remediation Plan

### Phase 1: Remove Unnecessary PIN Verification (Breaking Change)

**Option A: Complete Removal (Recommended)**

Remove `verify_device_if_needed()` calls from write operations entirely:

1. **Remove from `cli_store.py`** (line 56):
   ```python
   # DELETE: verify_device_if_needed(ctx)
   ```

2. **Remove from `cli_remove.py`** (line 33):
   ```python
   # DELETE: verify_device_if_needed(ctx)
   ```

3. **Remove from `cli_format.py`** (lines 87-90):
   ```python
   # DELETE entire block:
   # if not generate:
   #     verify_device_if_needed(ctx)
   ```

**Rationale:**
- Write operations already have sufficient authentication via Management Key
- PIN verification adds no security benefit for these operations
- More aligned with PIV specification and user expectations
- `fetch` command demonstrates the correct pattern: only ask for credentials when cryptographically required

**Option B: Make PIN Verification Optional**

Add a flag to disable verification:
- Add `--verify-pin` flag (default: False) to explicitly enable PIN verification
- Keep current behavior as opt-in for paranoid users
- This is more conservative but adds complexity

**Recommendation:** Choose Option A. The PIN verification is security theater and should be removed.

### Phase 2: Fix Confusing Message

**Fix in `src/yb/auxiliaries.py:37-38`:**

```python
# BEFORE:
if pin is None:
    print('Confirm by entering your PIN...', file=sys.stderr)

# AFTER:
if pin is None:
    print('Verifying YubiKey PIN...', file=sys.stderr)
else:
    print('Verifying YubiKey with provided PIN...', file=sys.stderr)
```

**Alternative (if keeping verification):**
```python
# More context-aware message:
if pin is None:
    print('Please enter YubiKey PIN to confirm:', file=sys.stderr)
# No message if PIN already provided - verification is silent
```

### Phase 3: Improve Documentation

Update help text to clarify credential requirements:

1. **Global `--pin` option** (`src/yb/main.py:146-149`):
   ```python
   help='YubiKey PIN (required for decrypting encrypted blobs)'
   ```

2. **Global `--key` option** (`src/yb/main.py:140-143`):
   ```python
   help='Management key (required for write operations if non-default key is configured)'
   ```

3. **Command help text:**
   - `store`: Mention management key requirement
   - `fetch`: Mention PIN requirement for encrypted blobs
   - `format --generate`: Mention PIN requirement for certificate generation

### Phase 4: Avoid Passing Default Values to Underlying Commands

**Current Behavior:**
When the user does not provide `--pin` or `--key`, the code passes `None` to underlying commands. This is mostly correct, but we should ensure consistency.

**Implementation:**
Ensure that when `--pin` or `--key` are not provided:
- `pin = None` is passed (let underlying tools prompt if needed)
- `management_key = None` is passed (use YubiKey default key)
- Do NOT hardcode default values like `123456` or `010203...` in the code
- Let `yubico-piv-tool` and `pkcs11-tool` handle defaults

**Current Status:**
- ✅ Already implemented correctly in `src/yb/main.py:286-299` for management key
- ✅ Already implemented correctly for PIN (defaults to `None`)

This phase is mostly documentation - the current code already follows this pattern.

### Phase 5: Security Check for Default Credentials

**Goal:**
Refuse to work if the YubiKey uses default PIN, PUK, or Management Key values.

**Default Values to Check:**
- Default PIN: `123456`
- Default PUK: `12345678`
- Default Management Key: `010203040506070801020304050607080102030405060708`

**Detection Methods:**

**IMPORTANT: Use GET_METADATA command (does NOT consume retry attempts)**

YubiKey firmware 5.3+ supports the `GET_METADATA` command (INS 0xF7) which provides metadata about PIN/PUK/Management Key including whether they use default values, **without requiring authentication**.

**APDU Structure:**
```
CLA: 00
INS: F7 (GET_METADATA)
P1:  00
P2:  <slot> (0x80=PIN, 0x81=PUK, 0x9B=Management Key)
```

**Response TLV Tags:**
- Tag 0x01: Algorithm
- Tag 0x05: IS_DEFAULT flag (0x01 = default, 0x00 = changed)
- Tag 0x06: Retry counts (PIN/PUK only)

**Detection Logic:**

1. **PIN Detection (slot 0x80):**
   ```python
   # Send APDU: 00 F7 00 80
   response = piv.send_apdu(0x00, 0xF7, 0x00, 0x80)
   tlv_data = parse_tlv(response)
   is_default_pin = (tlv_data[0x05] == b'\x01')
   ```

2. **PUK Detection (slot 0x81):**
   ```python
   # Send APDU: 00 F7 00 81
   response = piv.send_apdu(0x00, 0xF7, 0x00, 0x81)
   tlv_data = parse_tlv(response)
   is_default_puk = (tlv_data[0x05] == b'\x01')
   ```

3. **Management Key Detection (slot 0x9B):**
   ```python
   # Send APDU: 00 F7 00 9B
   response = piv.send_apdu(0x00, 0xF7, 0x00, 0x9B)
   tlv_data = parse_tlv(response)
   is_default_mgmt_key = (tlv_data[0x05] == b'\x01')
   ```

**Advantages:**
- **No retry counter impact** - Safe to check anytime
- **No authentication required** - Works before PIN/key verification
- **Fast and reliable** - Single APDU per credential
- **No risk of lockout** - Cannot accidentally block PIN/PUK

**Fallback for Older Firmware (<5.3):**
- GET_METADATA not available on firmware <5.3
- Must either skip check or warn user
- Do NOT attempt verification with default values (consumes retries)
- Recommend: Display warning and continue if firmware version unknown

**Implementation Strategy:**

**Step 1: Add low-level APDU support to PivInterface**

Extend `PivInterface` in `src/yb/piv.py` to support raw APDU commands:

```python
class PivInterface(ABC):
    @abstractmethod
    def send_apdu(
        self,
        reader: Hashable,
        cla: int,
        ins: int,
        p1: int,
        p2: int,
        data: bytes = b''
    ) -> bytes:
        """Send raw APDU to PIV application and return response."""
        pass
```

For `HardwarePiv`, implement using `yubico-piv-tool --action send-apdu` or direct smartcard APDU.

For `EmulatedPiv`, implement mock responses for testing.

**Step 2: Add TLV parser**

Add TLV parsing utility in `src/yb/auxiliaries.py` or new `src/yb/tlv_parser.py`:

```python
def parse_tlv(data: bytes) -> dict[int, bytes]:
    """
    Parse DER-encoded TLV data into dictionary.

    Args:
        data: Raw TLV bytes from APDU response

    Returns:
        Dictionary mapping tag (int) to value (bytes)
    """
    result = {}
    offset = 0
    while offset < len(data):
        tag = data[offset]
        offset += 1

        # Parse length (supports single-byte and multi-byte lengths)
        length = data[offset]
        offset += 1
        if length & 0x80:  # Multi-byte length
            num_bytes = length & 0x7F
            length = int.from_bytes(data[offset:offset+num_bytes], 'big')
            offset += num_bytes

        # Extract value
        value = data[offset:offset+length]
        offset += length

        result[tag] = value

    return result
```

**Step 3: Add metadata detection functions**

Add in `src/yb/auxiliaries.py`:

```python
# Constants
INS_GET_METADATA = 0xF7
SLOT_PIN = 0x80
SLOT_PUK = 0x81
SLOT_CARD_MANAGEMENT = 0x9B
TAG_METADATA_IS_DEFAULT = 0x05

def get_pin_metadata(reader: Hashable, piv: PivInterface) -> tuple[bool, int, int]:
    """
    Get PIN metadata including default status and retry counts.

    Returns:
        Tuple of (is_default, total_retries, remaining_retries)

    Raises:
        RuntimeError: If firmware <5.3 or command fails
    """
    try:
        response = piv.send_apdu(reader, 0x00, INS_GET_METADATA, 0x00, SLOT_PIN)
        tlv_data = parse_tlv(response)

        is_default = (tlv_data.get(TAG_METADATA_IS_DEFAULT, b'\x00') == b'\x01')

        # Tag 0x06 contains retry counts
        retry_data = tlv_data.get(0x06, b'\x00\x00')
        total_retries = retry_data[0] if len(retry_data) > 0 else 0
        remaining_retries = retry_data[1] if len(retry_data) > 1 else 0

        return (is_default, total_retries, remaining_retries)
    except Exception as e:
        raise RuntimeError(f"Failed to get PIN metadata (firmware <5.3?): {e}")

def get_puk_metadata(reader: Hashable, piv: PivInterface) -> tuple[bool, int, int]:
    """Get PUK metadata. Same structure as get_pin_metadata."""
    try:
        response = piv.send_apdu(reader, 0x00, INS_GET_METADATA, 0x00, SLOT_PUK)
        tlv_data = parse_tlv(response)

        is_default = (tlv_data.get(TAG_METADATA_IS_DEFAULT, b'\x00') == b'\x01')
        retry_data = tlv_data.get(0x06, b'\x00\x00')
        total_retries = retry_data[0] if len(retry_data) > 0 else 0
        remaining_retries = retry_data[1] if len(retry_data) > 1 else 0

        return (is_default, total_retries, remaining_retries)
    except Exception as e:
        raise RuntimeError(f"Failed to get PUK metadata (firmware <5.3?): {e}")

def get_management_key_metadata(reader: Hashable, piv: PivInterface) -> bool:
    """
    Get management key default status.

    Returns:
        True if using default management key, False otherwise

    Raises:
        RuntimeError: If firmware <5.3 or command fails
    """
    try:
        response = piv.send_apdu(reader, 0x00, INS_GET_METADATA, 0x00, SLOT_CARD_MANAGEMENT)
        tlv_data = parse_tlv(response)

        is_default = (tlv_data.get(TAG_METADATA_IS_DEFAULT, b'\x00') == b'\x01')
        return is_default
    except Exception as e:
        raise RuntimeError(f"Failed to get management key metadata (firmware <5.3?): {e}")
```

**Step 4: Add main security check function**

Add in `src/yb/auxiliaries.py`:

```python
def check_for_default_credentials(
    reader: Hashable,
    piv: PivInterface,
    force_defaults: bool = False
) -> None:
    """
    Check if YubiKey uses default PIN, PUK, or Management Key.

    Uses GET_METADATA command (firmware 5.3+) which does NOT consume retry attempts.

    Args:
        reader: PC/SC reader name
        piv: PIV interface
        force_defaults: Allow operation even with default credentials

    Raises:
        click.ClickException: If defaults detected and not forced

    Note:
        On firmware <5.3, displays warning but continues (cannot detect safely).
    """
    import click
    import sys

    defaults_found = []

    # Try to detect defaults (safe on firmware 5.3+)
    try:
        # Check PIN
        pin_is_default, _, pin_remaining = get_pin_metadata(reader, piv)
        if pin_is_default:
            defaults_found.append(f"PIN (default: 123456, {pin_remaining} attempts remaining)")

        # Check PUK
        puk_is_default, _, puk_remaining = get_puk_metadata(reader, piv)
        if puk_is_default:
            defaults_found.append(f"PUK (default: 12345678, {puk_remaining} attempts remaining)")

        # Check Management Key
        mgmt_key_is_default = get_management_key_metadata(reader, piv)
        if mgmt_key_is_default:
            defaults_found.append("Management Key (default: 010203...)")

    except RuntimeError as e:
        # Firmware <5.3 or other error
        print(
            f"WARNING: Cannot verify default credentials (firmware <5.3?): {e}",
            file=sys.stderr
        )
        print(
            "Continuing anyway. For security, ensure your YubiKey uses non-default credentials.",
            file=sys.stderr
        )
        return

    # If defaults found and not forced, error out
    if defaults_found and not force_defaults:
        defaults_list = '\n  - '.join([''] + defaults_found)
        raise click.ClickException(
            f"YubiKey is using default credentials (INSECURE):{defaults_list}\n\n"
            "This is a security risk. Please change your YubiKey credentials:\n"
            "  - Change PIN: ykman piv access change-pin\n"
            "  - Change PUK: ykman piv access change-puk\n"
            "  - Change Management Key (recommended with PIN-protected mode):\n"
            "    ykman piv access change-management-key --generate --protect\n\n"
            "To proceed anyway (NOT RECOMMENDED), use --allow-defaults flag."
        )

    # If defaults found but forced, warn
    if defaults_found and force_defaults:
        defaults_list = '\n  - '.join([''] + defaults_found)
        print(
            f"WARNING: YubiKey is using default credentials:{defaults_list}",
            file=sys.stderr
        )
        print("Continuing with --allow-defaults flag (INSECURE)", file=sys.stderr)
```

**Step 5: Add global flag and integrate into main.py**

Add in `src/yb/main.py`:

```python
@click.option(
    '--allow-defaults',
    is_flag=True,
    default=False,
    help='Allow operations even with default PIN/PUK/Management Key (INSECURE)'
)
```

Call check function from `main.py` after reader selection (around line 307):

```python
# After choosing reader, before commands execute
# Skip check if YB_SKIP_DEFAULT_CHECK environment variable is set
import os
if not os.environ.get('YB_SKIP_DEFAULT_CHECK'):
    from yb.auxiliaries import check_for_default_credentials
    check_for_default_credentials(
        reader=chosen_reader,
        piv=piv,
        force_defaults=allow_defaults  # From click option
    )
```

Store the flag in context:

```python
ctx.obj['allow_defaults'] = allow_defaults
```

**Step 6: Implement send_apdu for HardwarePiv**

Add to `HardwarePiv` class in `src/yb/piv.py`:

```python
def send_apdu(
    self,
    reader: Hashable,
    cla: int,
    ins: int,
    p1: int,
    p2: int,
    data: bytes = b''
) -> bytes:
    """
    Send raw APDU command to YubiKey.

    Implementation options:
    1. Use yubico-piv-tool with custom APDU (if supported)
    2. Use pyscard library for direct smartcard communication
    3. Use subprocess to call pkcs11-tool or similar

    For simplicity, use subprocess with python smartcard library:
    """
    try:
        from smartcard.System import readers
        from smartcard.util import toHexString, toBytes

        # Find the reader
        reader_list = readers()
        card_reader = None
        for r in reader_list:
            if str(reader) in str(r):
                card_reader = r
                break

        if not card_reader:
            raise RuntimeError(f"Reader not found: {reader}")

        # Connect to card
        connection = card_reader.createConnection()
        connection.connect()

        # Build APDU
        if data:
            apdu = [cla, ins, p1, p2, len(data)] + list(data)
        else:
            apdu = [cla, ins, p1, p2]

        # Send APDU
        response, sw1, sw2 = connection.transmit(apdu)

        # Check status
        if sw1 != 0x90 or sw2 != 0x00:
            raise RuntimeError(f"APDU failed: SW={sw1:02X}{sw2:02X}")

        return bytes(response)

    except ImportError:
        raise RuntimeError(
            "pyscard library required for APDU commands. "
            "Install with: pip install pyscard"
        )
    except Exception as e:
        raise RuntimeError(f"APDU transmission failed: {e}")
```

**Alternative**: If pyscard is not available, use `yubico-piv-tool` raw mode (if supported in newer versions).

**Step 7: Implement send_apdu for EmulatedPiv**

Add to `EmulatedPiv` class for testing:

```python
def send_apdu(
    self,
    reader: Hashable,
    cla: int,
    ins: int,
    p1: int,
    p2: int,
    data: bytes = b''
) -> bytes:
    """
    Emulate APDU responses for testing.

    Supports GET_METADATA (INS 0xF7) for testing default credential detection.
    """
    # GET_METADATA command
    if ins == 0xF7:  # GET_METADATA
        # Return mock metadata based on slot
        # P2 contains slot number

        if p2 == 0x80:  # PIN metadata
            # Mock: PIN is default, 3 total retries, 3 remaining
            # Tag 05: is_default = 01
            # Tag 06: retries = 03 03
            return bytes([0x05, 0x01, 0x01, 0x06, 0x02, 0x03, 0x03])

        elif p2 == 0x81:  # PUK metadata
            # Mock: PUK is default
            return bytes([0x05, 0x01, 0x01, 0x06, 0x02, 0x03, 0x03])

        elif p2 == 0x9B:  # Management key metadata
            # Mock: Management key is default
            # Tag 01: algorithm = 03 (3DES)
            # Tag 05: is_default = 01
            return bytes([0x01, 0x01, 0x03, 0x05, 0x01, 0x01])

        else:
            raise RuntimeError(f"Unsupported metadata slot: {p2:#x}")

    # Other APDUs not implemented in emulation
    raise RuntimeError(f"Unsupported APDU in emulation: INS={ins:#x}")
```

For more sophisticated testing, allow EmulatedPiv to be configured with different credential states.

**Step 8: Error message examples**

The implementation will produce helpful error messages like:

```
Error: YubiKey is using default credentials (INSECURE):
  - PIN (default: 123456, 3 attempts remaining)
  - Management Key (default: 010203...)

This is a security risk. Please change your YubiKey credentials:
  - Change PIN: ykman piv access change-pin
  - Change PUK: ykman piv access change-puk
  - Change Management Key (recommended with PIN-protected mode):
    ykman piv access change-management-key --generate --protect

To proceed anyway (NOT RECOMMENDED), use --allow-defaults flag.
```

Or for older firmware:

```
WARNING: Cannot verify default credentials (firmware <5.3?): APDU failed: SW=6A86
Continuing anyway. For security, ensure your YubiKey uses non-default credentials.
```

**Implementation Notes:**

- **CRITICAL**: GET_METADATA does NOT consume retry attempts (safe to call repeatedly)
- Detection should happen early (in main CLI) not in individual commands
- Use `--allow-defaults` flag sparingly and warn users prominently
- Environment variable `YB_SKIP_DEFAULT_CHECK=1` skips all checks (for testing)
- Requires firmware 5.3+ (YubiKey 5 series with updated firmware)
- Falls back gracefully on older firmware with warning

**Edge Cases:**

1. **PIN is default but management key is not?**
   - Still refuse (any default credential is a security problem)
   - User must change all defaults

2. **Cannot detect defaults (firmware <5.3 or APDU error)?**
   - Display warning but allow operation
   - Security check is best-effort, not mandatory
   - Better to warn and continue than block legitimate users

3. **User is testing on a fresh YubiKey?**
   - Use `--allow-defaults` during initial setup/testing
   - Or use `YB_SKIP_DEFAULT_CHECK=1` environment variable

4. **EmulatedPiv in tests?**
   - Mock responses return configurable default status
   - Allow testing both default and non-default scenarios

5. **Partial defaults (e.g., only PUK is default)?**
   - Still refuse unless `--allow-defaults`
   - All credentials should be changed for proper security

**Security Rationale:**

Default credentials on YubiKeys are well-known and documented. Using them in production:
- Allows anyone with physical access to modify/read stored data
- Defeats the purpose of using a hardware security token
- May violate security policies/compliance requirements

This check protects users from accidentally deploying insecure configurations.

**Key Advantages of GET_METADATA Approach:**

1. **Safe Detection**: No retry attempts consumed, cannot lock YubiKey
2. **Non-Interactive**: No user prompts needed for detection
3. **Efficient**: Single APDU per credential (3 total APDUs)
4. **Reliable**: Works on all YubiKey 5 series with firmware 5.3+
5. **Official**: Documented in Yubico specifications, used by ykman

**Dependencies:**

- YubiKey firmware 5.3+ (released ~2020, most YubiKey 5 series have this)
- Python `pyscard` library for direct APDU communication
  - Or alternative: subprocess call to `ykman` or custom APDU tool
- TLV parser (simple Python implementation, no external deps)

### Phase 6: Support PIN-Protected Management Key Mode

**Goal:**
Support YubiKeys configured with PIN-protected management key, allowing users to perform write operations using only their PIN instead of providing the management key explicitly.

**Why This Matters:**
After implementing Phase 5 (default credential detection), users will be required to use non-default management keys. Requiring users to provide a 48-character hex management key for every write operation is cumbersome. PIN-protected mode solves this by storing the management key on the YubiKey itself, protected by the PIN.

**Implementation Strategy:**

#### 6.1 Detection of PIN-Protected Mode

Add function to detect if YubiKey is in PIN-protected mode:

```python
def detect_pin_protected_mode(reader: Hashable, piv: PivInterface) -> bool:
    """
    Detect if YubiKey has PIN-protected management key enabled.

    Returns:
        True if PIN-protected mode is active, False otherwise

    Implementation:
        1. Read ADMIN DATA object (0x5FFF00)
        2. Parse TLV structure
        3. Check tag 0x81 (bit field) for management key storage indicator
        4. Verify PRINTED object (0x5FC109) exists
    """
    try:
        # Read ADMIN DATA object
        admin_data = piv.read_object(reader, 0x5FFF00)

        # Parse TLV to find tag 0x81
        # Bit field format: bit 0x01 = mgmt key stored in PRINTED
        # Parse according to: 53 len 80 L1 81 01 <bitfield>

        # Check if bit indicating "management key in protected data" is set
        # Return True if detected

    except RuntimeError:
        # ADMIN DATA not readable or doesn't exist
        return False
```

**Location:** `src/yb/piv.py` or `src/yb/auxiliaries.py`

#### 6.2 Retrieve Management Key from PRINTED Object

Add function to retrieve the stored management key:

```python
def get_pin_protected_management_key(
    reader: Hashable,
    piv: PivInterface,
    pin: str | None = None
) -> str:
    """
    Retrieve management key from PRINTED object (requires prior PIN verification).

    Args:
        reader: PC/SC reader name
        piv: PIV interface
        pin: YubiKey PIN (will prompt if None)

    Returns:
        Management key as 48-character hex string

    Raises:
        RuntimeError: If PIN verification fails or PRINTED object unreadable

    Implementation:
        1. Verify PIN (piv.verify_reader())
        2. Read PRINTED object (0x5FC109)
        3. Extract management key from object data
        4. Return as hex string
    """
    # Verify PIN first (PRINTED is only readable after PIN verification)
    if not piv.verify_reader(reader, 0x9a, pin=pin):
        raise RuntimeError("PIN verification failed - cannot read PRINTED object")

    # Read PRINTED object
    try:
        printed_data = piv.read_object(reader, 0x5FC109)
    except RuntimeError as e:
        raise RuntimeError(f"Failed to read PRINTED object: {e}")

    # Parse PRINTED object to extract management key
    # Format may be raw key bytes or TLV-encoded
    # Return as hex string (48 chars for 24-byte TDES key)
```

**Location:** `src/yb/piv.py` or `src/yb/crypto.py`

#### 6.3 Integrate into Main CLI Logic

Modify `src/yb/main.py` to automatically detect and use PIN-protected mode:

```python
# In main CLI function, after reader selection (around line 285):

# Check if YubiKey uses PIN-protected management key
pin_protected = False
try:
    from yb.auxiliaries import detect_pin_protected_mode
    pin_protected = detect_pin_protected_mode(chosen_reader, piv)
except Exception:
    # Detection failed, assume not PIN-protected
    pin_protected = False

# Process management key
management_key: str | None = None
if key is not None:
    # User explicitly provided --key, use it
    if key == '-':
        key_input = click.prompt(
            'Management key (48 hex chars)',
            hide_input=True,
            type=str
        )
        management_key = validate_management_key(key_input)
    else:
        management_key = validate_management_key(key)

elif pin_protected:
    # YubiKey is PIN-protected, retrieve management key from PRINTED
    # This will happen lazily when first needed (see Phase 6.4)
    ctx.obj['pin_protected_mode'] = True
else:
    # Not PIN-protected, no --key provided: use default management key
    management_key = None

ctx.obj['management_key'] = management_key
```

#### 6.4 Lazy Retrieval in Write Commands

Modify write commands to retrieve management key on-demand:

```python
# In cli_store.py, cli_remove.py, cli_format.py:

def cli_store(ctx, ...):
    reader = ctx.obj['reader']
    piv = ctx.obj['piv']
    management_key = ctx.obj.get('management_key')

    # If PIN-protected mode and no explicit key, retrieve it
    if management_key is None and ctx.obj.get('pin_protected_mode', False):
        pin = ctx.obj.get('pin')
        from yb.auxiliaries import get_pin_protected_management_key

        try:
            management_key = get_pin_protected_management_key(
                reader=reader,
                piv=piv,
                pin=pin
            )
        except RuntimeError as e:
            raise click.ClickException(
                f"Failed to retrieve PIN-protected management key: {e}"
            )

    # Proceed with operation using management_key
    orchestrator.store_blob(..., management_key=management_key)
```

#### 6.5 Update Help Text and Documentation

1. Update global `--key` option help:
   ```python
   help='Management key as 48-char hex string, or "-" to prompt. '
        'Not needed if YubiKey uses PIN-protected management key mode.'
   ```

2. Add note to main help text:
   ```
   For YubiKeys with PIN-protected management key (recommended):
     - Setup: ykman piv access change-management-key --generate --protect
     - Write operations will only require PIN (no --key needed)
     - More convenient and secure than default management key
   ```

3. Update command help for write operations (store, rm, format):
   ```
   This command requires management key authentication.

   If your YubiKey uses PIN-protected mode, only PIN is needed.
   Otherwise, use --key to provide the management key.
   ```

#### 6.6 Handle Edge Cases

**Case 1: PIN-protected mode but user provides --key explicitly**
- Use the provided key (user override)
- Don't attempt to read PRINTED

**Case 2: PIN-protected mode but PIN verification fails**
- Clear error message: "PIN-protected management key requires valid PIN"
- Suggest checking PIN or using --pin option

**Case 3: PRINTED object readable but contains invalid data**
- Fall back to default behavior (management_key = None)
- Warn user: "Warning: PIN-protected mode detected but key retrieval failed"

**Case 4: PIN-derived mode (deprecated) detected**
- Refuse to work (insecure mode)
- Error message: "PIN-derived management key mode detected (insecure, deprecated). Please reconfigure with: ykman piv access change-management-key --generate --protect"

#### 6.7 TLV Parsing for ADMIN DATA

Implement TLV parser for ADMIN DATA object:

```python
def parse_admin_data(data: bytes) -> dict:
    """
    Parse PIV ADMIN DATA object (0x5FFF00).

    Format: 53 len 80 L1 81 01 <bitfield> 82 L2 <salt> 83 L3 <timestamp>

    Returns:
        Dictionary with parsed fields:
        - 'puk_blocked': bool
        - 'mgmt_key_stored': bool (in PRINTED object)
        - 'salt': bytes (for PIN-derived mode, if present)
        - 'timestamp': int (PIN last updated, if present)
    """
    # TLV parsing implementation
    # Tag 0x53 = ADMIN DATA wrapper
    # Tag 0x80 = PUK blocked status (optional)
    # Tag 0x81 = Bit field (bit 0x01 = mgmt key stored)
    # Tag 0x82 = Salt for PIN-derived (optional, deprecated)
    # Tag 0x83 = Timestamp (optional)
```

**Location:** `src/yb/auxiliaries.py` or new file `src/yb/tlv_parser.py`

#### 6.8 Testing Requirements

**Unit Tests:**
1. TLV parsing for various ADMIN DATA formats
2. Detection of PIN-protected mode
3. Retrieval of management key from PRINTED
4. Handling of malformed ADMIN DATA

**Integration Tests:**
1. Write operations with PIN-protected YubiKey (no --key needed)
2. Write operations with explicit --key (overrides PIN-protected)
3. PIN-protected mode with wrong PIN (should fail gracefully)
4. Detection and rejection of PIN-derived mode

**Test Fixtures:**
- EmulatedPiv needs to support ADMIN DATA and PRINTED objects
- Mock YubiKeys in various configurations:
  - Default credentials
  - Custom management key (not PIN-protected)
  - PIN-protected mode
  - PIN-derived mode (for rejection testing)

#### 6.9 Compatibility Considerations

**Backward Compatibility:**
- Existing behavior unchanged for YubiKeys NOT in PIN-protected mode
- Users can still use --key explicitly
- No breaking changes to command-line interface

**Forward Compatibility:**
- Support both TDES and AES management keys (check algorithm in ADMIN DATA)
- Handle future PIV object format changes gracefully

**ykman vs yubico-piv-tool:**
- This feature brings yubiblob to feature parity with ykman
- Users won't need to switch between tools
- yubico-piv-tool limitation is bypassed by reading PRINTED directly

## Implementation Priority

1. **HIGH:** Remove unnecessary PIN verification (Phase 1, Option A)
2. **MEDIUM:** Fix confusing message (Phase 2) - only if verification is kept
3. **LOW:** Documentation improvements (Phase 3)
4. **MEDIUM:** Security check for default credentials (Phase 5)
5. **HIGH:** Support PIN-protected management key mode (Phase 6)

**Note:** Phase 4 documents existing behavior (already correct). Phases 5 and 6 work together:
- Phase 5 enforces non-default credentials (security requirement)
- Phase 6 makes non-default management keys convenient (usability improvement)

**Recommended Implementation Order:**
1. Phase 1 (remove unnecessary PIN verification)
2. Phase 6 (PIN-protected management key support)
3. Phase 5 (default credential detection)
4. Phase 2 (message improvements, if needed)
5. Phase 3 (documentation polish)

## Testing Recommendations

After implementing fixes, verify:

### Phase 1 Tests (Remove Unnecessary PIN Verification)
1. ✅ `yb store` works without PIN prompt (only needs management key)
2. ✅ `yb rm` works without PIN prompt (only needs management key)
3. ✅ `yb format` works without PIN prompt (only needs management key)
4. ✅ `yb format --generate` still prompts for PIN during selfsign (required)
5. ✅ `yb fetch <encrypted>` still prompts for PIN (required)
6. ✅ `yb fetch <unencrypted>` works without PIN (correct)
7. ✅ `yb --pin <pin> store` doesn't show confusing messages
8. ✅ All operations with `-x` / `--no-verify` flag continue to work

### Phase 5 Tests (Default Credential Detection)
1. ✅ Fresh YubiKey with defaults → Error message displayed
2. ✅ Fresh YubiKey with defaults + `--allow-defaults` → Operation proceeds with warning
3. ✅ YubiKey with changed PIN but default mgmt key → Error message
4. ✅ YubiKey with changed mgmt key but default PIN → Error message
5. ✅ YubiKey with all credentials changed → No error, normal operation
6. ✅ Detection failure (no ykman) → Warning but operation proceeds
7. ✅ Environment variable `YB_SKIP_DEFAULT_CHECK=1` → Skip check entirely
8. ✅ Error message includes helpful instructions (ykman commands to change credentials)

### Phase 6 Tests (PIN-Protected Management Key Support)

**Detection Tests:**
1. ✅ YubiKey in PIN-protected mode → Correctly detected
2. ✅ YubiKey NOT in PIN-protected mode → Correctly detected as false
3. ✅ YubiKey with ADMIN DATA missing → Returns false (no error)
4. ✅ YubiKey with malformed ADMIN DATA → Returns false gracefully
5. ✅ PIN-derived mode detected → Rejected with helpful error

**Management Key Retrieval Tests:**
6. ✅ PIN-protected mode with valid PIN → Key retrieved successfully
7. ✅ PIN-protected mode with invalid PIN → Clear error message
8. ✅ PIN-protected mode with no PIN → Prompts for PIN
9. ✅ PIN-protected mode with `--pin` flag → Uses provided PIN
10. ✅ PRINTED object missing → Graceful error with fallback

**Write Operation Tests:**
11. ✅ `yb store` on PIN-protected YubiKey (only PIN needed) → Success
12. ✅ `yb rm` on PIN-protected YubiKey → Success
13. ✅ `yb format` on PIN-protected YubiKey → Success
14. ✅ PIN-protected mode + explicit `--key` → Uses explicit key (override)
15. ✅ PIN-protected mode + wrong PIN → Clear error, no YubiKey lockout

**TLV Parsing Tests:**
16. ✅ Parse ADMIN DATA with all fields present
17. ✅ Parse ADMIN DATA with minimal fields
18. ✅ Parse ADMIN DATA with PIN-derived salt → Detect deprecated mode
19. ✅ Handle truncated/malformed TLV data

**Integration Tests:**
20. ✅ End-to-end: Setup PIN-protected → Store blob → Retrieve blob
21. ✅ Migration: Default key → PIN-protected → Store/fetch still works
22. ✅ Both AES and TDES management keys supported
23. ✅ Multiple operations in one session (key cached after first retrieval)

## Technical Context

### When PIN is Required in PIV:
- Private key operations: signing, decryption, key agreement (ECDH)
- Some administrative operations depending on key policies
- Self-signing certificates (combines admin + crypto operations)

### When Management Key is Required in PIV:
- Writing PIV objects (certificates, data objects)
- Generating keys
- Importing certificates
- Changing PIN/PUK

### Current YubiKey Default:
- Default Management Key: `010203040506070801020304050607080102030405060708`
- Default PIN: `123456`
- Most users should change these, but write operations still only need management key

### PIN-Protected Management Key Mode

**What It Is:**
YubiKeys can be configured to store the management key ON the device itself, encrypted and protected by the PIN. This eliminates the need for users to remember or provide the management key separately.

**How It Works:**
1. A random management key is generated and stored in the PRINTED data object (0x5FC109)
2. The PRINTED object is only readable after PIN verification in the current session
3. Metadata in ADMIN DATA object (0x5FFF00) indicates PIN-protected mode is active
4. When performing admin operations, user provides PIN only
5. YubiKey retrieves the management key from PRINTED automatically
6. The retrieved key is used for the actual administrative operation

**Setup with ykman:**
```bash
# Generate random management key and store it protected by PIN
ykman piv access change-management-key --generate --protect
```

**Advantages:**
- Users only need to remember the PIN (not the 48-character hex management key)
- More convenient for frequent administrative operations
- Management key is still cryptographically strong (randomly generated)
- Reduces risk of management key exposure (never leaves the YubiKey)

**Important Limitation:**
- If PIN becomes blocked, administrative operations are impossible until PIN is unblocked with PUK
- The management key cannot be retrieved without the PIN

**Security Considerations:**
- PIN-protected mode is secure and recommended by Yubico
- Do NOT confuse with "PIN-derived" mode (deprecated, derives key from PIN - insecure)
- The actual management key is still 24 bytes and cryptographically strong
- Access still requires both physical possession of YubiKey AND knowledge of PIN

**Detection:**
Can be detected by reading ADMIN DATA object (0x5FFF00) and checking:
- Tag 0x81 (bit field) - indicates management key storage status
- Presence of data in PRINTED object (0x5FC109) after PIN verification

**Current Limitation in yubico-piv-tool:**
`yubico-piv-tool` does NOT support PIN-protected management key mode automatically. This is a known limitation (GitHub issue #500). Users must:
- Either provide the management key explicitly with `--key`
- Or use `ykman` instead which has full PIN-protected support

## Conclusion

The main issue is architectural: `verify_device_if_needed()` is being used as a "user confirmation" mechanism rather than for actual authentication requirements. The solution is to remove it from write operations and let the YubiKey's own access controls (Management Key for writes, PIN for crypto operations) enforce security.

The `fetch` command demonstrates the correct pattern: only request credentials when they are cryptographically required by the underlying operation.
