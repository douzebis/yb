#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

"""
Debug version - shows all errors instead of catching them
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


def flash_yubikey_debug(serial: int, duration: int = 10):
    """Flash with full error reporting."""
    from ykman.device import list_all_devices
    from yubikit.core.smartcard import SmartCardConnection

    print(f"Looking for YubiKey {serial}...")
    devices = list_all_devices()
    device_obj = None
    for device, info in devices:
        print(f"  Found: serial={info.serial}, version={info.version}")
        if info.serial == serial:
            device_obj = device
            print(f"  ✓ Matched!")
            break

    if device_obj is None:
        print(f"ERROR: Device {serial} not found")
        return

    print(f"\nStarting flash loop for {duration} seconds...")
    print("WATCH THE YUBIKEY!")
    print()

    start_time = time.time()
    flash_count = 0
    error_count = 0

    while time.time() - start_time < duration:
        try:
            with device_obj.open_connection(SmartCardConnection) as _conn:
                conn = cast(ScardSmartCardConnection, _conn)
                print(f"Connection opened, type={type(_conn)}")

                # Try SELECT PIV application instead
                # PIV AID: A0 00 00 03 08
                piv_aid = [0xA0, 0x00, 0x00, 0x03, 0x08]
                apdu = [0x00, 0xA4, 0x04, 0x00, len(piv_aid)] + piv_aid
                print(f"Sending SELECT PIV: {' '.join(f'{b:02X}' for b in apdu)}")

                response, sw1, sw2 = conn.connection.transmit(apdu)

                print(f"Response: SW={sw1:02X}{sw2:02X}, data_len={len(response)}")

                flash_count += 1

        except Exception as e:
            error_count += 1
            print(f"ERROR #{error_count}: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()

        time.sleep(0.5)

    print(f"\n\nSummary:")
    print(f"  Successful flashes: {flash_count}")
    print(f"  Errors: {error_count}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python test_flash_debug.py <serial_number>")
        sys.exit(1)

    serial = int(sys.argv[1])
    flash_yubikey_debug(serial, duration=5)
