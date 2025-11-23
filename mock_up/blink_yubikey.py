#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

"""
Simple YubiKey LED blinking demonstration.

Run this script and watch your YubiKey LED.
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


def main() -> int:
    from ykman.device import list_all_devices
    from yubikit.core.smartcard import SmartCardConnection

    print("\n" + "=" * 70)
    print("YubiKey LED Blinking Demonstration")
    print("=" * 70)
    print()

    devices = list(list_all_devices())
    if not devices:
        print("✗ No YubiKeys found")
        return 1

    device, info = devices[0]

    print(f"Using YubiKey serial: {info.serial}")
    print()
    print("=" * 70)
    print("** WATCH YOUR YUBIKEY - IT SHOULD BLINK NOW **")
    print("=" * 70)
    print()

    input("Press ENTER when you're ready to watch the LED blink...")

    print()
    print("Performing 20 rapid operations...")
    print("(Watch the LED closely)")
    print()

    try:
        for i in range(20):
            with device.open_connection(SmartCardConnection) as _conn:
                conn = cast(ScardSmartCardConnection, _conn)
                # Quick version read - causes LED flash
                apdu = [0x00, 0xF7, 0x00, 0x00]
                response, sw1, sw2 = conn.connection.transmit(apdu)

            # Progress indicator
            if (i + 1) % 5 == 0:
                print(f"  {i+1}/20 operations complete")

            time.sleep(0.15)

        print()
        print("=" * 70)
        print("✓ Done! Did you see the LED blinking?")
        print("=" * 70)
        print()

        return 0

    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
