#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

"""
Definitive YubiKey LED blinking test.

This script will make the YubiKey LED blink in a very obvious way.
"""

from __future__ import annotations

import sys
import time
from typing import Protocol, Tuple, cast


class PcscConnection(Protocol):
    """Protocol for pyscard connection object (accessed via conn.connection)."""
    def transmit(self, apdu: list[int]) -> Tuple[list[int], int, int]:
        """Send APDU and receive response."""
        ...


class ScardSmartCardConnection(Protocol):
    """Protocol for ykman.pcsc.ScardSmartCardConnection."""
    connection: PcscConnection

    def send_and_receive(self, apdu: bytes) -> Tuple[bytes, int]:
        """Send APDU and receive response (yubikit API)."""
        ...


def blink_test_via_config_read() -> bool:
    """Read config repeatedly to trigger LED blinking."""
    from ykman.device import list_all_devices
    from yubikit.core.smartcard import SmartCardConnection

    print("=" * 70)
    print("YubiKey LED Blinking Test - Configuration Reads")
    print("=" * 70)

    devices = list(list_all_devices())
    if not devices:
        print("✗ No YubiKeys found")
        return False

    device, info = devices[0]
    print(f"\nUsing YubiKey serial: {info.serial}")
    print()
    print("=" * 70)
    print("** WATCH YOUR YUBIKEY LED CAREFULLY **")
    print("** The LED should blink during the following operations **")
    print("=" * 70)
    print()

    try:
        # Read config multiple times rapidly
        print("Performing 10 rapid configuration reads...")
        print("(Each read should cause a brief LED flash)")
        print()

        for i in range(10):
            with device.open_connection(SmartCardConnection) as _conn:
                conn = cast(ScardSmartCardConnection, _conn)
                # Read version and serial - these are quick ops that trigger LED
                # GET VERSION
                apdu = [0x00, 0xF7, 0x00, 0x00]
                response, sw1, sw2 = conn.connection.transmit(apdu)

                if i % 2 == 0:
                    print(f"  Read {i+1}/10 - LED should have flashed", end='\r')

            time.sleep(0.2)  # Small delay between reads

        print()
        print()
        print("✓ Completed 10 reads")
        print()

        return True

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def blink_test_via_piv_operations() -> bool:
    """Multiple PIV operations to trigger LED."""
    from ykman.device import list_all_devices
    from yubikit.core.smartcard import SmartCardConnection
    from yubikit.piv import PivSession

    print("=" * 70)
    print("YubiKey LED Blinking Test - PIV Operations")
    print("=" * 70)

    devices = list(list_all_devices())
    if not devices:
        print("✗ No YubiKeys found")
        return False

    device, info = devices[0]
    print(f"\nUsing YubiKey serial: {info.serial}")
    print()
    print("=" * 70)
    print("** WATCH YOUR YUBIKEY LED CAREFULLY **")
    print("** The LED should blink repeatedly **")
    print("=" * 70)
    print()

    try:
        print("Performing 10 PIV session operations...")
        print("(Each session creation + read should cause LED activity)")
        print()

        for i in range(10):
            with device.open_connection(SmartCardConnection) as conn:
                piv = PivSession(conn)

                # Read PIN attempts (quick operation)
                piv.get_pin_attempts()

                # Try to read discovery object
                from yubikit.piv import OBJECT_ID
                try:
                    piv.get_object(OBJECT_ID.DISCOVERY)
                except Exception:
                    pass

                if i % 2 == 0:
                    print(f"  Operation {i+1}/10 - LED should be active", end='\r')

            time.sleep(0.15)  # Small delay

        print()
        print()
        print("✓ Completed 10 operations")
        print()

        return True

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def main() -> int:
    """Run LED blinking tests."""
    print("\n")
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 68 + "║")
    print("║" + "YubiKey LED Blinking Verification".center(68) + "║")
    print("║" + " " * 68 + "║")
    print("╚" + "═" * 68 + "╝")
    print()

    print("This test will perform multiple rapid operations on your YubiKey.")
    print("The LED should blink visibly during these operations.")
    print()

    input("Press ENTER to start the test (make sure you can see the YubiKey)...")
    print()

    try:
        # Test 1: Config reads
        result1 = blink_test_via_config_read()

        print()
        input("Press ENTER for the second test...")
        print()

        # Test 2: PIV operations
        result2 = blink_test_via_piv_operations()

        print()
        print("=" * 70)
        print("RESULTS")
        print("=" * 70)
        print()

        if result1 and result2:
            print("✓ All tests completed successfully")
            print()
            print("If you saw LED activity, this confirms:")
            print("  1. ykman can select the correct YubiKey device")
            print("  2. We have end-to-end connectivity to the PIV application")
            print("  3. The device responds to our commands")
        else:
            print("⚠ Some tests failed (but device may still have blinked)")

        print()
        print("=" * 70)

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
