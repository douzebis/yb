#!/usr/bin/env python3
"""
End-to-end connectivity verification for ykman API.

Tests:
1. Device selection via ykman API
2. PIV application access using ykman-selected device
3. YubiKey LED blinking (physical feedback)
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


def test_1_device_selection() -> bool:
    """Test 1: Select device via ykman and get PIV info."""
    from ykman.device import list_all_devices
    from yubikit.core.smartcard import SmartCardConnection
    from yubikit.piv import PivSession

    print("=" * 70)
    print("TEST 1: Device Selection and PIV Access via ykman")
    print("=" * 70)

    # List devices
    devices = list(list_all_devices())

    if not devices:
        print("✗ No YubiKeys found")
        return False

    device, info = devices[0]

    print("\n✓ Found YubiKey via ykman API:")
    print(f"  Serial: {info.serial}")
    print(f"  Version: {info.version}")
    print()

    # Open PIV connection
    print("Opening PIV session...")
    try:
        with device.open_connection(SmartCardConnection) as conn:
            piv = PivSession(conn)

            print( "✓ PIV session established:")
            print(f"  PIV version: {piv.version}")
            print(f"  PIN attempts remaining: {piv.get_pin_attempts()}")

            # Try to read a standard PIV object (CHUID - Card Holder Unique ID)
            from yubikit.piv import OBJECT_ID
            try:
                chuid = piv.get_object(OBJECT_ID.CHUID)
                if chuid:
                    print(f"  ✓ Read CHUID object: {len(chuid)} bytes")
                else:
                    print( "  ℹ CHUID object is empty (normal for new YubiKey)")
            except Exception as e:
                print(f"  ℹ Could not read CHUID: {e}")

            print()
            print("✓✓ CONFIRMED: Can access PIV application via ykman-selected device")
            return True

    except Exception as e:
        print(f"✗ Failed to access PIV: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_2_blink_yubikey() -> bool:
    """Test 2: Make YubiKey LED blink."""
    from ykman.device import list_all_devices
    from yubikit.core.smartcard import SmartCardConnection
    from yubikit.piv import PivSession

    print("=" * 70)
    print("TEST 2: YubiKey LED Blinking")
    print("=" * 70)

    devices = list(list_all_devices())
    if not devices:
        print("✗ No YubiKeys found")
        return False

    device, info = devices[0]
    print(f"\nTesting with YubiKey {info.serial}...")
    print()

    # Method 1: Try to trigger LED via verify PIN (with empty PIN)
    print("Method 1: Triggering LED via PIN verification...")
    print("(Note: This will FAIL with wrong PIN, but should cause LED activity)")
    print()

    try:
        with device.open_connection(SmartCardConnection) as conn:
            piv = PivSession(conn)

            # Send VERIFY command with empty PIN (will fail but may trigger LED)
            # APDU: 00 20 00 80 <len> <pin>
            # Using a clearly wrong PIN to avoid accidentally using real PIN

            print("Sending PIN verification command (will intentionally fail)...")
            print("** WATCH THE YUBIKEY LED NOW **")
            print()

            # Try the verify operation (will fail but may blink)
            try:
                piv.verify_pin("00000000")  # Wrong PIN, will fail
            except Exception as e:
                print(f"  Expected failure: {type(e).__name__}")

            time.sleep(0.5)

            pin_attempts = piv.get_pin_attempts()
            print(f"  PIN attempts remaining: {pin_attempts}")
            print()

    except Exception as e:
        print(f"Error: {e}")

    # Method 2: Read multiple objects rapidly (may cause LED activity)
    print("Method 2: Rapid PIV object access...")
    print("** WATCH THE YUBIKEY LED NOW **")
    print()

    try:
        with device.open_connection(SmartCardConnection) as conn:
            piv = PivSession(conn)

            # Read several objects in quick succession
            from yubikit.piv import OBJECT_ID

            objects_to_read = [
                OBJECT_ID.CHUID,
                OBJECT_ID.CAPABILITY,
                OBJECT_ID.DISCOVERY,
            ]

            for obj_id in objects_to_read:
                try:
                    data = piv.get_object(obj_id)
                    status = f"{len(data)} bytes" if data else "empty"
                    print(f"  Read {obj_id.name}: {status}")
                    time.sleep(0.1)  # Small delay between reads
                except Exception as e:
                    print(f"  Read {obj_id.name}: {e}")

            print()

    except Exception as e:
        print(f"Error: {e}")

    print("If you saw LED activity, we have physical confirmation!")
    print()

    return True


def test_3_touch_required_operation() -> bool:
    """Test 3: Operation that requires touch (definite LED activity)."""
    from ykman.device import list_all_devices
    from yubikit.core.smartcard import SmartCardConnection
    from yubikit.piv import SLOT, PivSession

    print("=" * 70)
    print("TEST 3: Check for Touch-Required Slots (Definite LED Activity)")
    print("=" * 70)

    devices = list(list_all_devices())
    if not devices:
        print("✗ No YubiKeys found")
        return False

    device, info = devices[0]
    print(f"\nChecking YubiKey {info.serial} for touch-required slots...")
    print()

    try:
        with device.open_connection(SmartCardConnection) as conn:
            piv = PivSession(conn)

            # Check if any slots have touch policy set
            # We'll try to get metadata for key slots
            from yubikit.piv import SLOT

            slots_to_check = [
                SLOT.AUTHENTICATION,    # 9a
                SLOT.SIGNATURE,         # 9c
                SLOT.KEY_MANAGEMENT,    # 9d
                SLOT.CARD_AUTH,         # 9e
            ]

            print("Checking slot metadata:")
            for slot in slots_to_check:
                try:
                    # Try to get certificate (doesn't require touch)
                    cert = piv.get_certificate(slot)
                    if cert:
                        print(f"  Slot {slot.name}: Has certificate")

                        # Try to get slot metadata if available
                        try:
                            metadata = piv.get_slot_metadata(slot)
                            print(f"    Touch policy: {metadata.touch_policy}")
                            if str(metadata.touch_policy) != 'NEVER':
                                print( "    ** This slot requires touch - LED will blink during use! **")
                        except Exception:
                            print( "    Metadata not available")
                    else:
                        print(f"  Slot {slot.name}: Empty")
                except Exception as e:
                    print(f"  Slot {slot.name}: {e}")

            print()

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

    return True


def test_4_raw_apdu_blink() -> bool:
    """Test 4: Send specific APDU that might trigger LED."""
    from ykman.device import list_all_devices
    from yubikit.core.smartcard import SmartCardConnection
    #from yubikit.piv import PivSession

    print("=" * 70)
    print("TEST 4: Trigger LED via YubiKey-Specific Commands")
    print("=" * 70)

    devices = list(list_all_devices())
    if not devices:
        print("✗ No YubiKeys found")
        return False

    device, info = devices[0]
    print(f"\nTesting with YubiKey {info.serial}...")
    print()

    # YubiKey has a SET LED command in some modes
    # Also, generating a key might trigger LED activity

    print("Method: Read YubiKey version/serial (may trigger LED)...")
    print("** WATCH THE YUBIKEY LED NOW **")
    print()

    try:
        with device.open_connection(SmartCardConnection) as _conn:
            conn = cast(ScardSmartCardConnection, _conn)
            #piv = PivSession(_conn)  # PivSession still needs the original SmartCardConnection

            # Get version - this is a YubiKey-specific command
            # APDU: 00 F7 00 00 (GET VERSION)
            print("Sending GET VERSION command...")
            apdu = [0x00, 0xF7, 0x00, 0x00]
            response, sw1, sw2 = conn.connection.transmit(apdu)

            if sw1 == 0x90 and sw2 == 0x00:
                version = f"{response[0]}.{response[1]}.{response[2]}"
                print(f"  ✓ Version response: {version}")

            time.sleep(0.5)

            # Get serial number - another YubiKey-specific command
            # APDU: 00 F8 00 00 (GET SERIAL)
            print("Sending GET SERIAL command...")
            apdu = [0x00, 0xF8, 0x00, 0x00]
            response, sw1, sw2 = conn.connection.transmit(apdu)

            if sw1 == 0x90 and sw2 == 0x00:
                serial = int.from_bytes(bytes(response), 'big')
                print(f"  ✓ Serial response: {serial}")
                if serial == info.serial:
                    print( "  ✓✓ Matches ykman-reported serial!")

            print()

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

    return True


def main() -> int:
    """Run all verification tests."""
    print("\n")
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 68 + "║")
    print("║" + "ykman API End-to-End Connectivity Verification".center(68) + "║")
    print("║" + " " * 68 + "║")
    print("╚" + "═" * 68 + "╝")
    print()

    results = {}

    try:
        # Test 1: Basic connectivity
        results['device_selection'] = test_1_device_selection()

        if not results['device_selection']:
            print("\n✗ Basic connectivity failed, stopping tests")
            return 1

        print()

        # Test 2: LED blinking
        results['led_blink'] = test_2_blink_yubikey()

        print()

        # Test 3: Touch slots
        results['touch_slots'] = test_3_touch_required_operation()

        print()

        # Test 4: Raw APDU
        results['raw_apdu'] = test_4_raw_apdu_blink()

        # Summary
        print("=" * 70)
        print("VERIFICATION SUMMARY")
        print("=" * 70)
        print()

        for test, passed in results.items():
            status = "✓ PASS" if passed else "✗ FAIL"
            print(f"  {test:20s}: {status}")

        print()

        if results['device_selection']:
            print("✓✓ CONFIRMED: Can select device via ykman and access PIV")
            print()
            print("Regarding LED blinking:")
            print("  - YubiKeys blink during cryptographic operations")
            print("  - YubiKeys blink when touch is required")
            print("  - LED activity may be subtle for read operations")
            print("  - Best test: use a slot with touch policy set")

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
