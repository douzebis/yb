#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

"""
Test the actual flash function from yubikey_selector.py
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


def flash_yubikey_continuously(serial: int, stop_event: threading.Event) -> None:
    """
    Flash the LED of the YubiKey with the given serial number continuously.
    This is copied directly from yubikey_selector.py.

    Continues flashing until stop_event is set.
    """
    try:
        from ykman.device import list_all_devices
        from yubikit.core.smartcard import SmartCardConnection

        devices = list_all_devices()
        device_obj = None
        for device, info in devices:
            if info.serial == serial:
                device_obj = device
                break

        if device_obj is None:
            return

        # Flash continuously until stopped
        while not stop_event.is_set():
            try:
                with device_obj.open_connection(SmartCardConnection) as _conn:
                    conn = cast(ScardSmartCardConnection, _conn)
                    # GET VERSION command - quick and causes LED flash
                    apdu = [0x00, 0xF7, 0x00, 0x00]
                    conn.connection.transmit(apdu)

                # Wait a bit before next flash (avoid excessive polling)
                # Check stop_event more frequently for responsiveness
                for _ in range(3):  # 3 x 100ms = 300ms between flashes
                    if stop_event.is_set():
                        break
                    time.sleep(0.1)
            except Exception:
                # Ignore errors and continue flashing
                if not stop_event.is_set():
                    time.sleep(0.1)
    except Exception:
        # Silently ignore errors during flashing
        pass

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python test_selector_flash.py <serial_number>")
        sys.exit(1)

    serial = int(sys.argv[1])

    print(f"Testing LED flash for YubiKey {serial}")
    print("This uses the EXACT same function as yubikey_selector.py")
    print()
    print("Flashing for 10 seconds...")
    print("WATCH THE YUBIKEY NOW!")
    print()

    stop_event = threading.Event()
    flash_thread = threading.Thread(
        target=flash_yubikey_continuously,
        args=(serial, stop_event),
        daemon=True
    )
    flash_thread.start()

    # Let it flash for 10 seconds
    time.sleep(10)

    # Stop flashing
    stop_event.set()
    flash_thread.join(timeout=1)

    print("\n\nDid you see the LED flashing? (it should blink green)")
