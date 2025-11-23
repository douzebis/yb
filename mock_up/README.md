# ykman Python API Mock-ups and Verification Tests

**Date**: 2025-11-15
**Purpose**: Evaluation and verification of ykman Python API for YubiKey serial number support

This directory contains mock-ups, tests, and documentation created to evaluate the
feasibility of using the ykman Python API for multi-device YubiKey selection.

---

## Overview

These mock-ups demonstrate that the ykman Python API can:
- Enumerate YubiKeys with serial numbers
- Select a specific YubiKey by serial
- Access the PIV application
- Bridge to existing yb code via `device.fingerprint`

**Key Finding**: The ykman device object provides the PC/SC reader name directly
via its `.fingerprint` attribute, enabling seamless integration with existing code.

---

## Files

### Python Scripts

#### Core Mock-ups

**`ykman_working_mockup.py`** - Comprehensive working demonstration
- Lists all YubiKeys with serial numbers
- Selects device by serial
- Reads/writes custom PIV objects (0x5f0000-0x5f000f)
- Compares old vs new approaches
- **Run**: `python mock_up/ykman_working_mockup.py`

**`ykman_mockup.py`** - Initial draft (has import issues, kept for reference)

#### Verification Tests

**`verify_connectivity.py`** - Comprehensive end-to-end verification
- 4 test categories: device selection, LED activity, touch slots, raw APDUs
- All tests pass
- **Run**: `python mock_up/verify_connectivity.py`

**`test_bridge_ykman_to_reader.py`** - Critical bridging test
- Maps serial numbers to PC/SC reader names
- Verifies compatibility with yubico-piv-tool
- Discovered `device.fingerprint` attribute
- **Run**: `python mock_up/test_bridge_ykman_to_reader.py`

**`blink_yubikey.py`** - Interactive LED blinking demonstration
- 20 rapid operations to trigger LED
- Visual confirmation of connectivity
- **Run**: `python mock_up/blink_yubikey.py`

**`test_led_blink.py`** - Multiple LED triggering methods
- Configuration reads
- PIV operations

### Documentation

**`YKMAN_API_FINDINGS.md`** - Complete technical evaluation
- API structure and usage patterns
- Integration strategy (3 phases)
- Migration recommendations
- Code quality impact analysis

**`ANSWERS_TO_QUESTIONS.md`** - Pre-implementation verification
- Answers to Fred's questions about PIV access and LED blinking
- Test results summary
- Verification of end-to-end connectivity

---

## Test Results Summary

**Environment**:
- YubiKey: 5.7.1, Serial 32283437
- ykman: 5.6.1
- OS: Linux 6.12.57

**Results**:
- ✓ Device enumeration via ykman
- ✓ PIV application access
- ✓ Serial number retrieval
- ✓ Bridge to existing code (via device.fingerprint)
- ✓ LED activity during operations
- ✓ End-to-end connectivity verified

---

## Key Technical Findings

### 1. Device Enumeration

```python
from ykman.device import list_all_devices

devices = list(list_all_devices())
for device, info in devices:
    print(f"Serial: {info.serial}")  # e.g., 32283437
    print(f"Version: {info.version}")  # e.g., 5.7.1
```

### 2. Serial Number Access

Serial numbers are directly accessible via `DeviceInfo.serial` (integer).

### 3. Critical Discovery: device.fingerprint

```python
device, info = devices[0]
reader_name = device.fingerprint
# Returns: 'Yubico YubiKey OTP+FIDO+CCID 00 00'
```

The `.fingerprint` attribute contains the exact PC/SC reader name needed for
existing yb code. This enables:

```python
# New approach
devices = list(list_all_devices())
for device, info in devices:
    if info.serial == target_serial:
        reader = device.fingerprint
        # Use with existing code
        Piv.read_object(reader, object_id)
```

### 4. Custom PIV Objects

Custom PIV objects (0x5f0000-0x5f000f) are not in the `OBJECT_ID` enum, but
work perfectly via raw APDU commands:

```python
from yubikit.core.smartcard import SmartCardConnection
from yubikit.piv import PivSession

with device.open_connection(SmartCardConnection) as conn:
    piv = PivSession(conn)  # Select PIV applet

    # Read custom object via raw APDU
    obj_id = 0x5f0000
    data = [0x5C, 0x03] + list(obj_id.to_bytes(3, 'big'))
    apdu = [0x00, 0xCB, 0x3F, 0xFF, len(data)] + data
    response, sw1, sw2 = conn.connection.transmit(apdu)
```

---

## Implementation Impact

These mock-ups informed the Phase 1 implementation:

**Phase 1: Serial Number Support**
- Add `get_reader_for_serial(serial: int) -> str` to piv.py
- Add `--serial` flag to all CLI commands
- Maintain backward compatibility with `--reader`
- Implementation effort: ~4-6 hours

**Simplified by `.fingerprint` discovery**:
- No need to parse subprocess output
- Direct serial → reader mapping
- Type-safe DeviceInfo objects

---

## Usage Examples

### List YubiKeys with Serials

```bash
python mock_up/ykman_working_mockup.py
```

### Verify Connectivity

```bash
python mock_up/verify_connectivity.py
```

### Test LED Blinking

```bash
python mock_up/blink_yubikey.py
```

### Verify Bridge to Existing Code

```bash
python mock_up/test_bridge_ykman_to_reader.py
```

---

## References

- **MULTI_DEVICE.md** - Multi-device selection analysis (6 implementation paths)
- **DESIGN.md** - yb architecture and technical specification
- ykman documentation: https://developers.yubico.com/yubikey-manager/

---

## Next Steps

Based on these mock-ups, Phase 1 implementation proceeds with:

1. Update `src/yb/piv.py` with ykman support
2. Add `--serial` option to CLI commands
3. Update README.md with usage examples
4. Run pyright for type checking
