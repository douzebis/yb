#!/usr/bin/env python3
"""
Investigate USB device path correlation between PIV and FIDO interfaces.

This explores whether we can map YubiKey PIV serial numbers to FIDO HID
devices by correlating their USB device paths.
"""

from __future__ import annotations

import sys


def extract_usb_info_from_piv() -> list[dict]:
    """Extract USB information from PIV/SmartCard devices."""
    print("=" * 70)
    print("PIV Device USB Information")
    print("=" * 70)
    print()

    piv_devices = []

    try:
        from ykman.device import list_all_devices

        devices = list(list_all_devices())
        print(f"Found {len(devices)} YubiKey device(s) via PIV/SmartCard")
        print()

        for i, (device, info) in enumerate(devices):
            print(f"Device {i}: Serial {info.serial}")
            print(f"  Fingerprint (reader): {device.fingerprint}")
            print(f"  Version: {info.version}")

            device_info = {
                "serial": info.serial,
                "version": str(info.version),
                "fingerprint": device.fingerprint,
            }

            # Try to extract USB path from device object
            # Different approaches depending on ykman implementation

            # Approach 1: Check _device attribute (internal)
            if hasattr(device, '_device'):
                device_device = getattr(device, '_device')
                print(f"  _device: {device_device}")
                print(f"  _device type: {type(device_device)}")
                device_info["_device"] = str(device_device)

                # Check if _device has path/location info
                if hasattr(device_device, '__dict__'):
                    print(f"  _device attributes: {list(device_device.__dict__.keys())}")

            # Approach 2: Check for transport-related attributes
            for attr in ['transport', 'path', 'location', 'port', 'bus', 'address']:
                if hasattr(device, attr):
                    val = getattr(device, attr)
                    print(f"  {attr}: {val}")
                    device_info[attr] = str(val)

            # Approach 3: Check device descriptor
            if hasattr(device, 'descriptor'):
                device_descriptor = getattr(device, 'descriptor')
                print(f"  descriptor: {device_descriptor}")
                device_info["descriptor"] = str(device_descriptor)

            # Approach 4: Try to get pid
            if hasattr(device, 'pid'):
                print(f"  pid: {device.pid}")
                device_info["pid"] = device.pid

            # Approach 5: Check all attributes
            all_attrs = [a for a in dir(device) if not a.startswith('_')]
            print(f"  Public attributes: {all_attrs}")

            piv_devices.append(device_info)
            print()

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

    return piv_devices


def extract_usb_info_from_fido() -> list[dict]:
    """Extract USB information from FIDO HID devices."""
    print()
    print("=" * 70)
    print("FIDO HID Device USB Information")
    print("=" * 70)
    print()

    fido_devices = []

    try:
        from fido2.hid import CtapHidDevice

        devices = list(CtapHidDevice.list_devices())
        print(f"Found {len(devices)} FIDO HID device(s)")
        print()

        if not devices:
            print("⚠ No FIDO HID devices found - permission issue?")
            print("  Try running with sudo or fix udev rules")
            return fido_devices

        for i, device in enumerate(devices):
            print(f"Device {i}:")

            device_info = {}

            # Descriptor information
            if hasattr(device, 'descriptor'):
                desc = device.descriptor
                print(f"  descriptor: {desc}")

                for attr in ['path', 'product_name', 'serial_number', 'vendor_id',
                             'product_id', 'usage_page', 'usage']:
                    if hasattr(desc, attr):
                        val = getattr(desc, attr)
                        print(f"  descriptor.{attr}: {val}")
                        device_info[attr] = val

            # Check for USB path/location
            for attr in ['path', 'location', 'port', 'bus', 'address', 'device_path']:
                if hasattr(device, attr):
                    val = getattr(device, attr)
                    print(f"  {attr}: {val}")
                    device_info[attr] = val

            # Check all public attributes
            all_attrs = [a for a in dir(device) if not a.startswith('_')]
            print(f"  Public attributes: {all_attrs}")

            # Try CTAP2 to get more info
            try:
                from fido2.ctap2 import Ctap2
                ctap2 = Ctap2(device)
                print(f"  CTAP2 info.aaguid: {ctap2.info.aaguid.hex()}")
                print(f"  CTAP2 info.versions: {ctap2.info.versions}")

                # Check if CTAP2 has any device/serial info
                if hasattr(ctap2.info, 'options'):
                    print(f"  CTAP2 info.options: {ctap2.info.options}")

                device_info["aaguid"] = ctap2.info.aaguid.hex()
            except Exception as e:
                print(f"  CTAP2 error: {e}")

            fido_devices.append(device_info)
            print()

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

    return fido_devices


def analyze_correlation(piv_devices: list[dict], fido_devices: list[dict]) -> None:
    """Analyze potential correlations between PIV and FIDO devices."""
    print()
    print("=" * 70)
    print("Correlation Analysis")
    print("=" * 70)
    print()

    if not piv_devices:
        print("No PIV devices to analyze")
        return

    if not fido_devices:
        print("No FIDO devices to analyze")
        print("Cannot perform correlation without FIDO access")
        return

    print(f"PIV devices: {len(piv_devices)}")
    print(f"FIDO devices: {len(fido_devices)}")
    print()

    # Strategy 1: Path comparison
    print("Strategy 1: USB Path Comparison")
    print("-" * 40)

    for piv in piv_devices:
        piv_path = piv.get('path') or piv.get('device_path')
        if piv_path:
            print(f"PIV Serial {piv['serial']}: path = {piv_path}")

            # Try to match with FIDO devices
            for fido in fido_devices:
                fido_path = fido.get('path') or fido.get('device_path')
                if fido_path and piv_path in str(fido_path):
                    print(f"  ✓ Potential match: FIDO path = {fido_path}")
        else:
            print(f"PIV Serial {piv['serial']}: No path information")

    print()

    # Strategy 2: Vendor/Product ID comparison
    print("Strategy 2: Vendor/Product ID Comparison")
    print("-" * 40)

    # Extract Vendor/Product IDs if available
    for i, fido in enumerate(fido_devices):
        vid = fido.get('vendor_id')
        pid = fido.get('product_id')
        if vid and pid:
            print(f"FIDO device {i}: VID={hex(vid) if isinstance(vid, int) else vid}, PID={hex(pid) if isinstance(pid, int) else pid}")

    print()

    # Strategy 3: Enumeration order
    print("Strategy 3: Enumeration Order Correlation")
    print("-" * 40)
    print("Assumption: PIV and FIDO enumerate in same order")

    if len(piv_devices) == len(fido_devices):
        print(f"✓ Same count ({len(piv_devices)}) - enumeration order might correlate")
        print()
        for i in range(len(piv_devices)):
            piv = piv_devices[i]
            fido = fido_devices[i]
            print(f"  Index {i}: PIV Serial {piv['serial']} ← may map to → FIDO {fido.get('path', 'no path')}")
    else:
        print(f"✗ Different counts (PIV: {len(piv_devices)}, FIDO: {len(fido_devices)})")
        print("  Enumeration order correlation unreliable")

    print()


def recommendations() -> None:
    """Print recommendations based on findings."""
    print()
    print("=" * 70)
    print("Recommendations")
    print("=" * 70)
    print()

    print("If USB path correlation is found:")
    print("  ✓ Can reliably map PIV serial to FIDO device")
    print("  ✓ Touch-based selection is feasible")
    print()

    print("If no USB path correlation:")
    print("  ✗ Cannot reliably map PIV to FIDO")
    print("  ✗ Touch-based selection not practical for multi-device")
    print("  ✓ Arrow-key navigation remains good UX")
    print()

    print("Additional considerations:")
    print("  • FIDO HID requires different permissions than PIV")
    print("  • May need udev rules or sudo for FIDO access")
    print("  • Enumeration order is platform-dependent and unreliable")
    print("  • AAGUID is YubiKey-wide, not unique per device")
    print()


def main() -> int:
    """Main entry point."""
    print()
    print("USB Device Path Correlation Investigation")
    print()

    # Extract PIV device info
    piv_devices = extract_usb_info_from_piv()

    # Extract FIDO device info
    fido_devices = extract_usb_info_from_fido()

    # Analyze correlation
    analyze_correlation(piv_devices, fido_devices)

    # Print recommendations
    recommendations()

    print("=" * 70)
    print("Investigation complete")
    print("=" * 70)
    print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
