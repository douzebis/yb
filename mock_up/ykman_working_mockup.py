#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

"""
Working mock-up of ykman Python API usage for YubiKey PIV operations.

This demonstrates:
1. Listing all YubiKeys with serial numbers
2. Selecting a specific YubiKey by serial
3. Reading/writing custom PIV objects (0x5f0000-0x5f000f)
4. How to integrate with existing yb codebase

Key findings:
- ykman provides excellent serial number support
- Custom PIV objects require raw APDU commands (not in OBJECT_ID enum)
- Can use PivSession to select applet, then raw APDUs for custom objects
- PKCS#11 operations (ECDH) will still work alongside ykman
"""

from __future__ import annotations

import sys
from typing import Protocol, cast

from ykman.pcsc import YkmanDevice
from yubikit.core.smartcard import SmartCardConnection
from yubikit.management import DeviceInfo


class PcscConnection(Protocol):
    """Protocol for pyscard connection object (accessed via conn.connection)."""
    def transmit(self, apdu: list[int]) -> tuple[list[int], int, int]:
        """Send APDU and receive response.

        Args:
            apdu: APDU command as list of bytes

        Returns:
            Tuple of (response_data, sw1, sw2)
        """
        ...


class ScardSmartCardConnection(Protocol):
    """Protocol for ykman.pcsc.ScardSmartCardConnection.

    This is the actual runtime type returned by device.open_connection().
    It provides both yubikit (send_and_receive) and pyscard (connection.transmit) APIs.
    """
    connection: PcscConnection  # The underlying pyscard connection

    def send_and_receive(self, apdu: bytes) -> tuple[bytes, int]:
        """Send APDU and receive response (yubikit API).

        Args:
            apdu: APDU command as bytes

        Returns:
            Tuple of (response_data, combined_status_word)
        """
        ...


def list_yubikeys() -> list[tuple[YkmanDevice, DeviceInfo]]:
    """List all connected YubiKeys with their serial numbers."""
    from ykman.device import list_all_devices

    devices = list(list_all_devices())
    return devices


def select_yubikey_by_serial(serial: int) -> tuple[YkmanDevice, DeviceInfo] | None:
    """Find and return YubiKey device with matching serial number."""
    devices = list_yubikeys()

    for device, info in devices:
        if info.serial == serial:
            return (device, info)

    return None


def read_piv_object(connection: ScardSmartCardConnection, object_id: int) -> bytes | None:
    """
    Read a PIV object using raw APDU.

    Args:
        connection: ScardSmartCardConnection (after PIV applet selected)
        object_id: PIV object ID (e.g., 0x5f0000)

    Returns:
        Object data (without TLV wrapper) or None if not found
    """
    # Build GET DATA APDU: 00 CB 3F FF <len> 5C <id_len> <object_id>
    obj_bytes = object_id.to_bytes(3, 'big')
    data = [0x5C, 0x03] + list(obj_bytes)
    apdu = [0x00, 0xCB, 0x3F, 0xFF, len(data)] + data

    response, sw1, sw2 = connection.connection.transmit(apdu)

    if sw1 == 0x90 and sw2 == 0x00:
        # Success - parse TLV response (tag 0x53)
        if response[0] == 0x53:
            # Parse length
            if response[1] < 0x80:
                payload_start = 2
            elif response[1] == 0x82:
                payload_start = 4
            else:
                payload_start = 2

            return bytes(response[payload_start:])
    elif sw1 == 0x6a and sw2 == 0x82:
        # Object not found
        return None
    else:
        raise RuntimeError(f"PIV GET DATA failed: {sw1:02x}{sw2:02x}")


def write_piv_object(connection: ScardSmartCardConnection, object_id: int, data: bytes) -> None:
    """
    Write a PIV object using raw APDU.

    Args:
        connection: ScardSmartCardConnection (after PIV applet selected)
        object_id: PIV object ID (e.g., 0x5f0000)
        data: Data to write
    """
    # Build PUT DATA APDU: 00 DB 3F FF <len> 5C 03 <object_id> 53 <data_len> <data>
    obj_bytes = object_id.to_bytes(3, 'big')

    # Build TLV: 5C 03 <object_id> 53 <data_len> <data>
    # Length encoding for tag 0x53
    if len(data) < 128:
        tlv = [0x5C, 0x03] + list(obj_bytes) + [0x53, len(data)] + list(data)
    elif len(data) <= 255:
        tlv = [0x5C, 0x03] + list(obj_bytes) + [0x53, 0x81, len(data)] + list(data)
    elif len(data) <= 65535:
        tlv = [0x5C, 0x03] + list(obj_bytes) + [0x53, 0x82, len(data) >> 8, len(data) & 0xFF] + list(data)
    else:
        raise ValueError(f"Data too large: {len(data)} bytes")

    # Check if we need extended APDU
    if len(tlv) <= 255:
        # Standard APDU
        apdu = [0x00, 0xDB, 0x3F, 0xFF, len(tlv)] + tlv
    else:
        # Extended APDU: 00 DB 3F FF 00 <len_hi> <len_lo> <data>
        apdu = [0x00, 0xDB, 0x3F, 0xFF, 0x00, len(tlv) >> 8, len(tlv) & 0xFF] + tlv

    response, sw1, sw2 = connection.connection.transmit(apdu)

    if sw1 != 0x90 or sw2 != 0x00:
        raise RuntimeError(f"PIV PUT DATA failed: {sw1:02x}{sw2:02x}")


def demo_1_list_devices() -> list[tuple[YkmanDevice, DeviceInfo]]:
    """Demo 1: List all YubiKeys with serial numbers."""
    print("=" * 70)
    print("DEMO 1: List all YubiKeys with serial numbers")
    print("=" * 70)

    devices = list_yubikeys()

    if not devices:
        print("\nNo YubiKeys found.")
        return []

    print(f"\nFound {len(devices)} YubiKey(s):\n")

    for i, (device, info) in enumerate(devices, 1):
        print(f"Device {i}:")
        print(f"  Serial Number: {info.serial}")
        print(f"  Version: {info.version}")
        print(f"  Form Factor: {info.form_factor.name if hasattr(info.form_factor, 'name') else info.form_factor}")
        if info.is_fips:
            print("  FIPS: Yes")
        print()

    return devices


def demo_2_select_by_serial(serial: int) -> tuple[object, object] | None:
    """Demo 2: Select a specific YubiKey by serial number."""
    print("=" * 70)
    print(f"DEMO 2: Select YubiKey by serial number ({serial})")
    print("=" * 70)

    result = select_yubikey_by_serial(serial)

    if not result:
        print(f"\n✗ No YubiKey found with serial {serial}")
        return None

    device, info = result
    print(f"\n✓ Found YubiKey {serial}")
    print(f"  Version: {info.version}")
    print(f"  Form Factor: {info.form_factor.name if hasattr(info.form_factor, 'name') else info.form_factor}")
    print()

    return result


def demo_3_read_custom_object(serial: int | None = None) -> None:
    """Demo 3: Read custom PIV object (0x5f0000)."""
    from yubikit.piv import PivSession

    print("=" * 70)
    print("DEMO 3: Read custom PIV object (0x5f0000)")
    print("=" * 70)

    # Select device
    if serial is not None:
        result = select_yubikey_by_serial(serial)
        if not result:
            return
        device, info = result
    else:
        devices = list_yubikeys()
        if not devices:
            print("\nNo YubiKeys found")
            return
        device, info = devices[0]

    print(f"\nReading from YubiKey {info.serial}...\n")

    # Open connection and create PIV session
    with device.open_connection(SmartCardConnection) as _conn:
        connection = cast(ScardSmartCardConnection, _conn)
        # Create PIV session (selects applet)
        piv = PivSession(_conn)  # PivSession needs the original SmartCardConnection
        print(f"PIV applet selected, version: {piv.version}")

        # Read custom object
        try:
            data = read_piv_object(connection, 0x5f0000)

            if data is None:
                print("✗ Object 0x5f0000 not found (may not be formatted)")
            else:
                print(f"✓ Read {len(data)} bytes from object 0x5f0000")
                print(f"  First 32 bytes (hex): {data[:32].hex()}")

                # Check for yblob magic
                if len(data) >= 4:
                    magic = int.from_bytes(data[:4], 'little')
                    print(f"  Magic number: {hex(magic)}")
                    if magic == 0xF2ED5F0B:
                        print("  ✓ Valid yblob magic!")
        except Exception as e:
            print(f"✗ Error: {e}")

    print()


def demo_4_write_read_roundtrip(serial: int | None = None) -> None:
    """Demo 4: Write and read custom PIV object."""
    from yubikit.piv import PivSession

    print("=" * 70)
    print("DEMO 4: Write and read custom PIV object (roundtrip)")
    print("=" * 70)

    # Select device
    if serial is not None:
        result = select_yubikey_by_serial(serial)
        if not result:
            return
        device, info = result
    else:
        devices = list_yubikeys()
        if not devices:
            print("\nNo YubiKeys found")
            return
        device, info = devices[0]

    print(f"\nTesting on YubiKey {info.serial}...\n")

    # Test data with yblob magic
    test_data = (
        b'\x0b\x5f\xed\xf2'  # Magic: 0xF2ED5F0B (little-endian)
        b'TEST_DATA_FROM_YKMAN_MOCKUP_'
        b'\x00' * 100  # Padding
    )

    print(f"Test data: {len(test_data)} bytes")
    print(f"  First 32 bytes: {test_data[:32].hex()}")
    print()

    # Open connection
    with device.open_connection(SmartCardConnection) as _conn:
        connection = cast(ScardSmartCardConnection, _conn)
        # Create PIV session
        piv = PivSession(_conn)  # PivSession needs the original SmartCardConnection
        print(f"PIV applet selected, version: {piv.version}\n")

        # Write object
        try:
            print("Writing to object 0x5f0001...")
            write_piv_object(connection, 0x5f0001, test_data)
            print("✓ Write successful\n")
        except Exception as e:
            print(f"✗ Write failed: {e}\n")
            return

        # Read back
        try:
            print("Reading back from object 0x5f0001...")
            read_data = read_piv_object(connection, 0x5f0001)

            if read_data is None:
                print("✗ Read failed: object not found")
                return

            print(f"✓ Read {len(read_data)} bytes\n")

            # Verify
            if read_data == test_data:
                print("✓✓ VERIFICATION SUCCESS: Data matches!")
            else:
                print("✗ VERIFICATION FAILED: Data mismatch")
                print(f"  Expected: {test_data[:32].hex()}")
                print(f"  Got:      {read_data[:32].hex()}")

        except Exception as e:
            print(f"✗ Read failed: {e}")

    print()


def demo_5_comparison() -> None:
    """Demo 5: Compare old vs new approaches."""
    print("=" * 70)
    print("DEMO 5: Comparison - Current yb vs ykman API")
    print("=" * 70)

    print("\n[CURRENT APPROACH - subprocess + PC/SC reader names]")
    print("-" * 70)
    print("# List readers")
    print("readers = piv.list_readers()")
    print("→ ['Yubico YubiKey OTP+FIDO+CCID 00 00']")
    print()
    print("# User must specify reader name")
    print("yb --reader 'Yubico YubiKey OTP+FIDO+CCID 00 00' fetch myblob")
    print()
    print("# Read object (via subprocess)")
    print("subprocess.run(['yubico-piv-tool',")
    print("                '-r', reader_name,")
    print("                '-a', 'read-object',")
    print("                '-i', '0x5f0000'], ...)")

    print("\n\n[NEW APPROACH - ykman API + serial numbers]")
    print("-" * 70)
    print("# List devices with serials")
    print("devices = list_yubikeys()")
    print("→ [(device, DeviceInfo(serial=32283437, version=5.7.1, ...))]")
    print()
    print("# User specifies serial number")
    print("yb --serial 32283437 fetch myblob")
    print()
    print("# Read object (native Python)")
    print("device, info = select_yubikey_by_serial(serial)")
    print("with device.open_connection(SmartCardConnection) as conn:")
    print("    piv = PivSession(conn)")
    print("    data = read_piv_object(conn, 0x5f0000)")

    print("\n\n[KEY BENEFITS]")
    print("-" * 70)
    print("✓ Serial numbers are stable (don't change with USB config)")
    print("✓ Serial numbers are brief (8 digits vs long reader names)")
    print("✓ Serial numbers printed on device case (physical verification)")
    print("✓ No subprocess overhead (native Python API)")
    print("✓ Better error handling (exceptions vs exit codes)")
    print("✓ Type safety (DeviceInfo objects vs string parsing)")
    print("✓ Maintained by Yubico (official API)")

    print("\n[COMPATIBILITY NOTES]")
    print("-" * 70)
    print("✓ Custom PIV objects (0x5f0000-0x5f000f) work via raw APDUs")
    print("✓ PKCS#11 operations still work (pkcs11-tool for ECDH)")
    print("✓ Can keep --reader flag for backward compatibility")
    print("⚠ ykman already in default.nix (no new dependencies)")

    print()


def main() -> int:
    """Run all demos."""
    print("\n")
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 68 + "║")
    print("║" + "ykman Python API Mock-up - Working Demo".center(68) + "║")
    print("║" + "YubiKey Multi-Device Selection via Serial Numbers".center(68) + "║")
    print("║" + " " * 68 + "║")
    print("╚" + "═" * 68 + "╝")
    print()

    try:
        # Demo 1: List all devices
        devices = demo_1_list_devices()

        if not devices:
            print("\nNo YubiKeys found. Please connect a YubiKey to continue.")
            return 1

        # Get serial of first device
        first_serial = devices[0][1].serial
        assert first_serial is not None

        # Demo 2: Select by serial
        demo_2_select_by_serial(first_serial)

        # Demo 3: Read custom object
        demo_3_read_custom_object(first_serial)

        # Demo 4: Write/read roundtrip
        demo_4_write_read_roundtrip(first_serial)

        # Demo 5: Comparison
        demo_5_comparison()

        print("=" * 70)
        print("All demos completed successfully!")
        print("=" * 70)
        print()

        return 0

    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        return 130
    except Exception as e:
        print(f"\n\nERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
