#!/usr/bin/env python3
"""
Diagnose FIDO HID access issues.

Checks permissions, device enumeration, and compares with PIV access.
"""

from __future__ import annotations

import sys


def check_fido_hid_devices() -> None:
    """Check if FIDO HID devices can be enumerated."""
    print("=" * 70)
    print("Test 1: FIDO HID Device Enumeration")
    print("=" * 70)
    print()

    try:
        from fido2.hid import CtapHidDevice

        print("Attempting to list FIDO HID devices...")
        devices = list(CtapHidDevice.list_devices())

        print(f"Found {len(devices)} FIDO HID device(s)")
        print()

        for i, device in enumerate(devices):
            print(f"Device {i}:")
            print(f"  Descriptor: {device.descriptor}")
            print(f"  Product: {device.descriptor.product_name if hasattr(device.descriptor, 'product_name') else 'N/A'}")
            print(f"  Path: {device.descriptor.path if hasattr(device.descriptor, 'path') else 'N/A'}")
            print()

        if not devices:
            print("⚠ No FIDO HID devices found!")
            print()
            print("Possible causes:")
            print("  1. Permission issue - HID devices require special permissions")
            print("  2. udev rules not configured")
            print("  3. User not in 'plugdev' or similar group")
            print("  4. Running without proper access to /dev/hidraw*")
            print()
            print("Try running with sudo to test if it's a permission issue:")
            print("  sudo python mock_up/diagnose_fido_access.py")

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()


def check_piv_smartcard_devices() -> None:
    """Check PIV smartcard device enumeration for comparison."""
    print()
    print("=" * 70)
    print("Test 2: PIV SmartCard Device Enumeration (for comparison)")
    print("=" * 70)
    print()

    try:
        from ykman.device import list_all_devices

        print("Attempting to list YubiKey devices via ykman (PIV/SmartCard)...")
        devices = list(list_all_devices())

        print(f"Found {len(devices)} YubiKey device(s)")
        print()

        for i, (device, info) in enumerate(devices):
            print(f"Device {i}:")
            print(f"  Serial: {info.serial}")
            print(f"  Version: {info.version}")
            print(f"  Form factor: {info.form_factor}")
            print(f"  Fingerprint (reader name): {device.fingerprint}")

            # Try to access USB information
            if hasattr(device, '_device'):
                print(f"  Internal device: {getattr(device, '_device')}")
            if hasattr(device, '__dict__'):
                print(f"  Device attributes: {[k for k in device.__dict__.keys() if not k.startswith('_')]}")

            print()

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()


def check_raw_hid_access() -> None:
    """Check raw HID device access."""
    print()
    print("=" * 70)
    print("Test 3: Raw HID Device Access")
    print("=" * 70)
    print()

    import os
    import glob

    print("Checking /dev/hidraw* devices...")
    hidraw_devices = glob.glob("/dev/hidraw*")

    print(f"Found {len(hidraw_devices)} hidraw device(s)")
    print()

    for hidraw in sorted(hidraw_devices):
        stat = os.stat(hidraw)
        readable = os.access(hidraw, os.R_OK)
        writable = os.access(hidraw, os.W_OK)

        print(f"{hidraw}:")
        print(f"  Mode: {oct(stat.st_mode)}")
        print(f"  Owner: UID {stat.st_uid}, GID {stat.st_gid}")
        print(f"  Readable: {readable}")
        print(f"  Writable: {writable}")

        # Try to read device info
        try:
            # Read from sysfs
            device_num = hidraw.replace("/dev/hidraw", "")
            sysfs_path = f"/sys/class/hidraw/hidraw{device_num}/device"

            if os.path.exists(sysfs_path):
                # Try to get vendor/product
                uevent_path = f"{sysfs_path}/uevent"
                if os.path.exists(uevent_path):
                    with open(uevent_path, 'r') as f:
                        uevent = f.read()
                        for line in uevent.split('\n'):
                            if 'HID_NAME' in line or 'PRODUCT' in line:
                                print(f"  {line}")
        except Exception as e:
            print(f"  Error reading sysfs: {e}")

        print()

    if hidraw_devices and not any(os.access(h, os.R_OK | os.W_OK) for h in hidraw_devices):
        print("⚠ HID devices exist but you don't have read/write access!")
        print()
        print("Solution options:")
        print("  1. Run with sudo (for testing only)")
        print("  2. Add udev rules for YubiKey FIDO access")
        print("  3. Add user to appropriate group (plugdev, etc.)")


def main() -> int:
    """Main entry point."""
    print()
    print("FIDO Access Diagnostics")
    print()

    # Test 1: FIDO HID enumeration
    check_fido_hid_devices()

    # Test 2: PIV enumeration (for comparison)
    check_piv_smartcard_devices()

    # Test 3: Raw HID access
    check_raw_hid_access()

    print()
    print("=" * 70)
    print("Diagnostics complete")
    print("=" * 70)
    print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
