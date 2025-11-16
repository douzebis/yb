#!/usr/bin/env python3
"""
Final test of LED flashing with SELECT PIV command
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


def test_flash_with_select_piv(serial: int, duration: int = 10):
    """Test LED flashing using SELECT PIV command."""
    from ykman.device import list_all_devices
    from yubikit.core.smartcard import SmartCardConnection

    print(f"Testing LED flash for YubiKey {serial}")
    print(f"Using SELECT PIV command (the corrected version)")
    print()

    devices = list_all_devices()
    device_obj = None
    for device, info in devices:
        if info.serial == serial:
            device_obj = device
            print(f"Found YubiKey: serial={info.serial}, version={info.version}")
            break

    if device_obj is None:
        print(f"ERROR: YubiKey {serial} not found")
        return

    print(f"\nFlashing for {duration} seconds...")
    print("*** WATCH THE YUBIKEY LED NOW ***")
    print()

    start_time = time.time()
    flash_count = 0
    error_count = 0

    # PIV application AID
    piv_aid = [0xA0, 0x00, 0x00, 0x03, 0x08]

    while time.time() - start_time < duration:
        try:
            with device_obj.open_connection(SmartCardConnection) as _conn:
                conn = cast(ScardSmartCardConnection, _conn)

                # SELECT PIV application
                apdu = [0x00, 0xA4, 0x04, 0x00, len(piv_aid)] + piv_aid
                response, sw1, sw2 = conn.connection.transmit(apdu)

                if sw1 == 0x90 and sw2 == 0x00:
                    flash_count += 1
                    print(f"Flash #{flash_count} - LED should be blinking!", end='\r')
                else:
                    error_count += 1
                    print(f"\nWarning: Unexpected response SW={sw1:02X}{sw2:02X}")

                # Wait before next flash
                time.sleep(0.3)

        except Exception as e:
            error_count += 1
            print(f"\nError: {e}")
            time.sleep(0.1)

    print(f"\n\n{'='*60}")
    print(f"Test complete!")
    print(f"  Successful commands: {flash_count}")
    print(f"  Errors: {error_count}")
    print(f"{'='*60}")
    print()
    print("Did the YubiKey LED flash green during the test?")
    print("(Each connection should cause a brief LED activity)")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python test_final_flash.py <serial_number>")
        sys.exit(1)

    serial = int(sys.argv[1])
    test_flash_with_select_piv(serial, duration=10)
