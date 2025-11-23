#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

"""
Simple test to verify LED flashing on YubiKey.
"""

import sys
import time
import threading
from typing import Protocol, cast


class PcscConnection(Protocol):
    """Protocol for pyscard connection object."""

    def transmit(self, apdu: list[int]) -> tuple[list[int], int, int]:
        """Send APDU and receive response."""
        ...


class ScardSmartCardConnection(Protocol):
    """Protocol for ykman.pcsc.ScardSmartCardConnection."""

    connection: PcscConnection


def test_led_flash(serial: int, duration: int = 10):
    """
    Test LED flashing for a specific YubiKey.

    Args:
        serial: YubiKey serial number
        duration: How long to flash in seconds
    """
    from ykman.device import list_all_devices
    from yubikit.core.smartcard import SmartCardConnection

    print(f"Looking for YubiKey with serial {serial}...")

    devices = list_all_devices()
    device_obj = None
    for device, info in devices:
        print(f"Found device: serial={info.serial}, version={info.version}")
        if info.serial == serial:
            device_obj = device
            print(f"✓ Matched target serial {serial}")
            break

    if device_obj is None:
        print(f"✗ Device {serial} not found")
        return False

    print(f"\nFlashing LED for {duration} seconds...")
    print("WATCH THE YUBIKEY NOW!")
    print()

    start_time = time.time()
    flash_count = 0

    # PIV application AID: A0 00 00 03 08
    piv_aid = [0xA0, 0x00, 0x00, 0x03, 0x08]

    # Test 1: Just opening connection (might cause LED flash by itself)
    print("Test 1: Opening/closing connection repeatedly...")
    for i in range(10):
        try:
            with device_obj.open_connection(SmartCardConnection) as _conn:
                pass  # Just open and close
            flash_count += 1
            print(f"Open/close #{flash_count}", end='\r')
            time.sleep(0.3)
        except Exception as e:
            print(f"\nError: {e}")

    print(f"\n\nTest 1 complete. Did you see LED flashing? (y/n): ", end='')

    # Test 2: With APDU commands
    print("\n\nTest 2: Sending APDU commands...")
    flash_count = 0

    while time.time() - start_time < duration:
        try:
            with device_obj.open_connection(SmartCardConnection) as _conn:
                conn = cast(ScardSmartCardConnection, _conn)

                # Try just GET VERSION without selecting PIV
                get_version = [0x00, 0xF7, 0x00, 0x00]
                try:
                    response, sw1, sw2 = conn.connection.transmit(get_version)
                    flash_count += 1
                    print(f"Flash #{flash_count}: SW={sw1:02X}{sw2:02X}", end='\r')
                except Exception as apdu_err:
                    print(f"\nAPDU error: {apdu_err}")

                time.sleep(0.3)
        except Exception as e:
            print(f"\nConnection error: {e}")
            time.sleep(0.1)

    print(f"\n\nTotal flashes: {flash_count}")
    print("Did you see the LED flashing? (it should blink green)")
    return True

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python test_led_flash.py <serial_number>")
        sys.exit(1)

    serial = int(sys.argv[1])
    test_led_flash(serial, duration=10)
