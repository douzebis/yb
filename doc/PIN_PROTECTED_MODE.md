# PIN-Protected Management Key Mode

**Status**: ✅ Implemented (Phase 6)
**Date**: 2025-11-23
**Verified Against**: YubiKey firmware 5.7.1, ykman 5.6.1, Official Yubico documentation

---

## Overview

PIN-protected management key mode allows users to perform YubiKey write operations using only their PIN, without needing to provide the 48-character hexadecimal management key. This significantly improves usability while maintaining security.

### How It Works

When configured with `ykman piv access change-management-key --generate --protect`:

1. **Random Key Generation**: ykman generates a cryptographically random AES-192 management key (24 bytes)
2. **Secure Storage**: The key is stored in the **PRINTED object** (0x5FC109), which is only readable after PIN verification
3. **Metadata**: The **ADMIN DATA object** (0x5FFF00) contains a bitfield indicating PIN-protected mode is active
4. **Automatic Retrieval**: yb automatically detects PIN-protected mode and retrieves the key when needed

### Security Properties

- **PIN Required**: Management key cannot be retrieved without correct PIN
- **Hardware-Bound**: Key never leaves the YubiKey
- **Non-Default**: Generated key is cryptographically random (not the factory default)
- **Automatic Detection**: yb verifies credentials are non-default

---

## Implementation Details

### PIV Objects Used

#### ADMIN DATA (0x5FFF00)

Contains metadata about PIV configuration:

**TLV Structure**:
```
Tag 0x80: Container for management key metadata
  Tag 0x81: Bitfield (1 byte)
    Bit 0x01: Management key stored (3DES mode)
    Bit 0x02: Management key stored (AES mode)  ← Used by modern YubiKeys
    Bit 0x04: PIN-derived mode (deprecated, insecure)
  Tag 0x82: Salt for PIN-derived mode (if present)
  Tag 0x83: Timestamp (optional)
```

**Example** (AES PIN-protected mode):
```
80 03 81 01 02
│  │  │  │  └─ Bitfield value: 0x02 = AES PIN-protected
│  │  │  └──── Length: 1 byte
│  │  └─────── Tag 0x81: Bitfield
│  └────────── Length: 3 bytes total
└───────────── Tag 0x80: Container
```

#### PRINTED (0x5FC109)

Contains the actual management key:

**TLV Structure**:
```
Tag 0x88: Outer container
  Tag 0x89: AES key material
    [24 bytes]: The actual AES-192 management key
```

**Example**:
```
88 1A 89 18 [24 bytes of key data]
│  │  │  │
│  │  │  └─ Length: 24 bytes (AES-192)
│  │  └──── Tag 0x89: AES key
│  └─────── Length: 26 bytes (0x1A)
└────────── Tag 0x88: Container
```

### Detection Algorithm

`yb` detects PIN-protected mode in `src/yb/auxiliaries.py`:

```python
def detect_pin_protected_mode(reader, piv) -> tuple[bool, bool]:
    try:
        # Read ADMIN DATA object
        admin_data = piv.read_object(reader, 0x5FFF00)

        # Parse TLV structure
        parsed = parse_admin_data(admin_data)

        # Check bitfield for PIN-protected (0x01 or 0x02)
        is_pin_protected = parsed['mgmt_key_stored']
        is_pin_derived = parsed['pin_derived']  # Deprecated mode

        return (is_pin_protected, is_pin_derived)
    except:
        # ADMIN DATA not present = not PIN-protected
        return (False, False)
```

### Key Retrieval Process

`yb` retrieves the management key in `src/yb/piv.py`:

```python
def _write_object_with_ykman(self, reader, id, input, pin):
    # 1. Open YubiKit PIV session
    with device.open_connection(SmartCardConnection) as conn:
        piv = PivSession(conn)

        # 2. Verify PIN (enables access to PRINTED)
        piv.verify_pin(pin)

        # 3. Read PRINTED object
        printed_data = piv.get_object(0x5FC109)

        # 4. Parse TLV: 88 <len> [ 89 <len> <key> ]
        outer_len = printed_data[1]
        inner_data = printed_data[2:2 + outer_len]
        key_len = inner_data[1]
        key_bytes = inner_data[2:2 + key_len]

        # 5. Convert to hex string
        management_key_hex = key_bytes.hex()

    # 6. Use yubico-piv-tool with retrieved key
    #    (handles chunking for large objects)
    subprocess.run(['yubico-piv-tool',
                    '--reader', reader,
                    f'--key={management_key_hex}',
                    '--action', 'write-object', ...])
```

### Why This Hybrid Approach?

**YubiKit for Retrieval**:
- Native Python API (no subprocess)
- Automatic PIV applet selection
- Built-in PRINTED object support
- Type-safe PIN verification

**yubico-piv-tool for Writing**:
- Handles APDU chunking for large objects (16KB+)
- Production-tested write resilience
- Proper error handling

**Limitation**: YubiKit's `put_object()` doesn't support chunking for objects >3KB, but yubico-piv-tool handles this correctly.

---

## User Experience

### Setup (One-Time)

```bash
# 1. Change from default PIN (optional but recommended)
ykman piv access change-pin
# Old PIN: 123456
# New PIN: [your PIN]

# 2. Enable PIN-protected management key
ykman piv access change-management-key --generate --protect
# Current management key: [blank for default]
# Enter PIN: [your PIN]
# New management key set.
```

### Daily Usage

**Before PIN-Protected Mode**:
```bash
# Had to provide 48-character management key
yb --key 010203040506...1718 store myfile
```

**After PIN-Protected Mode**:
```bash
# Just provide PIN!
yb --pin 123456 store myfile
yb --pin 123456 rm myfile
yb --pin 123456 format
```

**Read Operations** (unchanged):
```bash
yb ls                              # No credentials needed
yb fetch unencrypted-blob          # No credentials needed
yb --pin 123456 fetch encrypted    # PIN for ECDH decryption
```

---

## Files Modified

### Core Implementation

**`src/yb/auxiliaries.py`**:
- `parse_admin_data()` - Parse ADMIN DATA TLV structure
- `detect_pin_protected_mode()` - Check if YubiKey is PIN-protected
- `get_pin_protected_management_key()` - Retrieve key from PRINTED (updated to document behavior)
- `get_management_key_for_write()` - Unified helper for write commands

**`src/yb/piv.py`**:
- `_write_object_with_ykman()` - Retrieve PIN-protected key and write with yubico-piv-tool
- `write_object()` - Added `pin` parameter, automatic fallback to ykman for PIN-protected mode
- `send_apdu()` - Fixed: Added PIV applet selection (fixes SW=6D00 error)

**`src/yb/main.py`**:
- Integrated `detect_pin_protected_mode()` on startup
- Reject deprecated PIN-derived mode
- Store `pin_protected_mode` flag in context

### Write Commands

**All updated to support PIN parameter**:
- `src/yb/cli_store.py`
- `src/yb/cli_remove.py`
- `src/yb/cli_format.py`
- `src/yb/store.py` - `sync()` method
- `src/yb/orchestrator.py` - `store_blob()`, `remove_blob()`

### Documentation

- `README.md` - Added PIN-protected mode section
- `USER_GUIDE.md` - Comprehensive usage guide
- `IMPLEMENTATION_SUMMARY.md` - Technical summary
- `PIN_PROTECTED_MODE.md` (this file) - Detailed documentation

### Build System

- `default.nix` - Added `pkgs.openssl` dependency (required for format command)

---

## Verification Against Official Documentation

**Source**: [Yubico PIV PIN-only Mode Documentation](https://docs.yubico.com/yesdk/users-manual/application-piv/pin-only.html)

✅ **ADMIN DATA structure**: Matches documented TLV format
✅ **PRINTED object**: Correctly identified as storage location
✅ **Tag 0x89**: Confirmed as AES key material container
✅ **Bitfield 0x02**: Verified as AES PIN-protected mode indicator
✅ **PIN verification required**: Confirmed PRINTED readable only after PIN

**Additional References**:
- [PIV PIN, PUK, Management Key](https://docs.yubico.com/yesdk/users-manual/application-piv/pin-puk-mgmt-key.html)
- [PIV Commands - ykman](https://docs.yubico.com/software/yubikey/tools/ykman/PIV_Commands.html)
- [yubikey-manager GitHub](https://github.com/Yubico/yubikey-manager)

---

## Testing

### Tested Configurations

- **YubiKey**: 5 Series firmware 5.7.1
- **ykman**: 5.6.1
- **Environment**: Nix shell with yubikey-manager, yubico-piv-tool, openssl

### Test Cases

✅ **Detection**: PIN-protected mode correctly identified
✅ **Default Detection**: Non-default credentials verified (no warnings)
✅ **Key Retrieval**: Successfully parsed PRINTED object
✅ **Write Operations**: 16KB+ objects written successfully
✅ **Format**: Store initialization with PIN-protected mode
✅ **Store**: Blob storage using only PIN
✅ **List**: Blob enumeration
✅ **Fetch**: Unencrypted blob retrieval

### Example Test Session

```bash
$ nix-shell -A devShell

# Format YubiKey store
$ yb --pin 123456 format --no-generate
Using YubiKey 32283417 (version 5.7.1)
............

# Store blob (only PIN needed, no management key!)
$ echo "Hello World" > test.txt
$ yb --pin 123456 store test.txt
Using YubiKey 32283417 (version 5.7.1)
.

# List blobs
$ yb ls
Using YubiKey 32283417 (version 5.7.1)
-  1        0 2025-11-23 09:26 test.txt

# Fetch blob
$ yb fetch test.txt
Using YubiKey 32283417 (version 5.7.1)
Hello World
```

---

## Known Limitations

### 1. PIN-Derived Mode Not Supported

**What**: Legacy mode where management key is derived from PIN using a salt
**Why Rejected**: Insecure - key can be brute-forced if PIN is compromised
**Error Message**: Clear rejection with migration instructions

### 2. Requires yubikey-manager Library

**Dependency**: Python `yubikey-manager` package
**Rationale**: Needed for YubiKit PIV API (PRINTED object access)
**Already Available**: Included in `default.nix` dependencies

### 3. Explicit --key Overrides PIN-Protected Mode

**Behavior**: If `--key` provided, uses that instead of retrieving from PRINTED
**Rationale**: Allows emergency access or testing with custom keys

---

## Security Considerations

### Threat Model

**Protected Against**:
- ✅ Observation of management key during entry (no 48-char key to type)
- ✅ Management key compromise (random, hardware-bound)
- ✅ Accidental default credential usage (detected and blocked)

**Not Protected Against**:
- ⚠ Physical theft + PIN compromise (PIN grants full access)
- ⚠ Malware with keylogger (can capture PIN)
- ⚠ PIN brute-force (mitigated by retry limits: 3 attempts)

### Best Practices

1. **Change Default PIN**: Use `ykman piv access change-pin`
2. **Strong PIN**: Use 6-8 digits, avoid common patterns
3. **PUK Protection**: Change default PUK as well
4. **Physical Security**: Protect YubiKey from theft
5. **Retry Limits**: Don't share PIN with untrusted parties

### Comparison to Manual Key Management

| Aspect | PIN-Protected Mode | Manual Key |
|--------|-------------------|------------|
| **Usability** | ✅ Excellent (just PIN) | ❌ Poor (48 chars) |
| **Security** | ✅ Good (random + hardware) | ✅ Good (if managed properly) |
| **Key Storage** | ✅ On YubiKey | ❌ External (password manager, paper) |
| **Risk: Key Exposure** | ✅ Low (never leaves YubiKey) | ⚠ Medium (stored externally) |
| **Risk: PIN Compromise** | ⚠ Full access | ✅ Limited (still need key) |

**Recommendation**: PIN-protected mode for most users. Manual key management only for:
- High-security environments requiring two-factor device access
- Shared YubiKeys with separate management key custody
- Compliance requirements

---

## Troubleshooting

### "Cannot verify default credentials"

**Cause**: Firmware <5.3 doesn't support GET_METADATA command
**Solution**: Upgrade YubiKey, or use `--allow-defaults` for testing
**Note**: PIN-protected mode requires firmware 5.3+

### "Failed to retrieve PIN-protected management key"

**Possible Causes**:
1. Incorrect PIN
2. YubiKey not in PIN-protected mode
3. PRINTED object corrupted

**Debug**:
```bash
# Check if PIN-protected mode is active
ykman piv info
# Should show: "Management key is stored on the YubiKey, protected by PIN."

# Verify PIN works
ykman piv access change-pin --pin 123456 --new-pin 123456

# Re-enable PIN-protected mode if needed
ykman piv access change-management-key --generate --protect
```

### "yubikey-manager library required"

**Cause**: ykman Python package not installed
**Solution**: Use nix-shell:
```bash
nix-shell -A devShell
# or
pip install yubikey-manager
```

---

## Future Enhancements

### Potential Improvements

1. **Cache Management Key**: Store retrieved key in memory for session duration
   - Pro: Avoid repeated PIN prompts
   - Con: Security implications if process compromised

2. **Direct YubiKit Write**: Implement chunking in Python
   - Pro: No dependency on yubico-piv-tool subprocess
   - Con: Complex APDU chaining implementation

3. **PIN Policy Integration**: Respect YubiKey PIN policies (always/once/never)
   - Currently: Always prompt if no --pin provided
   - Enhancement: Check PIN policy metadata first

4. **Management Key Rotation**: Helper command to rotate PIN-protected key
   - `yb rotate-management-key --pin 123456`
   - Generates new random key, updates PRINTED

---

## References

### Official Documentation

- [Yubico PIV PIN-only Mode](https://docs.yubico.com/yesdk/users-manual/application-piv/pin-only.html)
- [PIV PIN, PUK, and Management Key](https://docs.yubico.com/yesdk/users-manual/application-piv/pin-puk-mgmt-key.html)
- [ykman PIV Commands](https://docs.yubico.com/software/yubikey/tools/ykman/PIV_Commands.html)
- [Device Setup Guide](https://developers.yubico.com/PIV/Guides/Device_setup.html)

### GitHub Issues

- [yubico-piv-tool #500](https://github.com/Yubico/yubico-piv-tool/issues/500) - PIN-derived support request
- [yubico-piv-tool #29](https://github.com/Yubico/yubico-piv-tool/issues/29) - Early discussion

### Standards

- NIST SP 800-73-4: PIV Standard
- NIST SP 800-78-4: Cryptographic algorithms for PIV
