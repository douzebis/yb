#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

"""
Test FIDO2 touch detection without credential provisioning.

This investigates whether we can use FIDO2 get_assertion to detect
user touch without requiring any pre-provisioned credentials or leaving
any state on the YubiKey.
"""

from __future__ import annotations

import hashlib
import sys
from typing import Any
from collections.abc import Mapping

from fido2.ctap2 import Ctap2
from fido2.hid import CtapHidDevice


def get_yubikey_fido_device(serial: int | None = None) -> CtapHidDevice | None:
    """
    Get FIDO HID device, optionally matching a specific YubiKey serial.

    Note: Serial matching is not straightforward with FIDO HID.
    For now, just returns the first device if serial is None.
    """
    devices = list(CtapHidDevice.list_devices())
    if not devices:
        return None

    if serial is None:
        # Return first device
        return devices[0]

    # TODO: Match by serial - requires getting serial from FIDO device
    # CTAP2 info doesn't include serial number directly
    # For now, just return first device
    print( "Warning: Serial matching not implemented, using first FIDO device")
    return devices[0]


def test_touch_detection_no_credential(serial: int | None = None) -> None:
    """
    Test if we can detect touch without requiring credentials.

    Strategy: Call get_assertion with a dummy rp_id and empty allow_list.
    Expected: Operation should fail (no credential), but might still wait for touch.
    """
    print(f"\n{'='*70}")
    print( "Test 1: get_assertion with empty allow_list")
    print(f"{'='*70}\n")

    device = get_yubikey_fido_device(serial)
    if device is None:
        print("No FIDO device found")
        return

    try:
        ctap2 = Ctap2(device)

        print("Device info:")
        print(f"  AAGUID: {ctap2.info.aaguid.hex()}")
        print(f"  Versions: {ctap2.info.versions}")
        print(f"  Options: {ctap2.info.options}")
        print()

        # Create a dummy client data hash
        client_data_hash = hashlib.sha256(b"test-touch-detection").digest()

        # Try get_assertion with dummy rp_id and empty allow_list
        print("Attempting get_assertion with empty allow_list...")
        print("Touch your YubiKey if prompted...")
        try:
            response = ctap2.get_assertion(
                rp_id="example.com",  # Dummy RP ID
                client_data_hash=client_data_hash,
                allow_list=[],  # Empty - no credentials specified
            )
            print(f"Response received: {response}")
        except Exception as e:
            print(f"Error (expected): {type(e).__name__}: {e}")
            print()
            print("Analysis: Empty allow_list causes immediate error.")
            print("Does NOT wait for user touch - unusable for detection.")

    except Exception as e:
        print(f"Connection error: {e}")
    finally:
        if device:
            device.close()


def test_touch_detection_dummy_credential(serial: int | None = None) -> None:
    """
    Test if we can detect touch with a non-existent dummy credential.

    Strategy: Call get_assertion with a dummy credential ID that doesn't exist.
    Expected: Might wait for touch, then fail with "no credential found".
    """
    print(f"\n{'='*70}")
    print( "Test 2: get_assertion with non-existent credential")
    print(f"{'='*70}\n")

    device = get_yubikey_fido_device(serial)
    if device is None:
        print("No FIDO device found")
        return

    try:
        ctap2 = Ctap2(device)

        # Create a dummy client data hash
        client_data_hash = hashlib.sha256(b"test-touch-detection").digest()

        # Create a dummy credential descriptor
        dummy_cred_id = b"x" * 32  # Dummy 32-byte credential ID

        allow_list: list[Mapping[str, Any]] = [
            {
                "type": "public-key",
                "id": dummy_cred_id,
            }
        ]

        print("Attempting get_assertion with dummy credential...")
        print("** WATCH YOUR YUBIKEY - Touch it if it starts blinking **")
        print()

        try:
            response = ctap2.get_assertion(
                rp_id="example.com",  # Dummy RP ID
                client_data_hash=client_data_hash,
                allow_list=allow_list,  # Non-existent credential
            )
            print(f"✓ Response received (unexpected): {response}")
        except Exception as e:
            print(f"✗ Error (expected): {type(e).__name__}: {e}")
            print()
            if "timeout" in str(e).lower() or "keepalive" in str(e).lower():
                print("Analysis: Operation WAITED for user touch!")
                print("This means we CAN use FIDO2 for touch detection.")
            elif "no credentials" in str(e).lower():
                print("Analysis: Error indicates no matching credential.")
                print("Check if operation waited for touch (did LED blink?).")
            else:
                print("Analysis: Error occurred, check if LED blinked.")

    except Exception as e:
        print(f"Connection error: {e}")
    finally:
        if device:
            device.close()


def test_selection_check_no_up(serial: int | None = None) -> None:
    """
    Test if we can use FIDO2 selection command without user presence.

    Strategy: Try authenticatorSelection command which doesn't require touch.
    This is defined in CTAP 2.1 spec section 6.6.
    """
    print(f"\n{'='*70}")
    print( "Test 3: authenticatorSelection (CTAP 2.1)")
    print(f"{'='*70}\n")

    device = get_yubikey_fido_device(serial)
    if device is None:
        print("No FIDO device found")
        return

    try:
        print("Attempting authenticatorSelection (no UP required)...")

        try:
            # CTAP 2.1 command 0x0B - authenticatorSelection
            # This is meant to help identify which authenticator to use
            # Should NOT require user presence
            result = device.call(0x0B, b"")
            print(f"✓ Selection command succeeded: {result}")
            print()
            print("Analysis: This command works but doesn't detect touch.")
            print("It's for device identification, not user presence verification.")
        except Exception as e:
            print(f"✗ Error: {type(e).__name__}: {e}")
            print()
            print("Analysis: Command not supported or failed.")

    except Exception as e:
        print(f"Connection error: {e}")
    finally:
        if device:
            device.close()


def main() -> int:
    """Main entry point."""
    # Check for FIDO devices
    fido_devices = list(CtapHidDevice.list_devices())
    if not fido_devices:
        print("No FIDO devices found.")
        return 1

    print(f"\nFound {len(fido_devices)} FIDO device(s)")
    print("\nTesting FIDO2 touch detection")

    # Test 1: Empty allow_list
    test_touch_detection_no_credential()

    input("\nPress ENTER to continue to Test 2...")

    # Test 2: Non-existent credential
    test_touch_detection_dummy_credential()

    input("\nPress ENTER to continue to Test 3...")

    # Test 3: authenticatorSelection
    test_selection_check_no_up()

    print(f"\n{'='*70}")
    print("Testing complete")
    print(f"{'='*70}\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
