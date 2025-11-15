#!/usr/bin/env python3
"""
Critical bridging test: ykman device selection → yubico-piv-tool reader name.

This verifies that we can:
1. Select a YubiKey by serial number using ykman
2. Get the PC/SC reader name for that device
3. Use that reader name with existing yb code (yubico-piv-tool)
"""

from __future__ import annotations

import subprocess
import sys


def get_readers_via_yubico_piv_tool() -> list[str]:
    """Get reader names via current yb approach (yubico-piv-tool)."""
    try:
        result = subprocess.run(
            ['yubico-piv-tool', '--action', 'list-readers'],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        readers = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return readers
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to list readers: {e.stderr.strip()}") from e


def get_serial_for_reader(reader: str) -> int | None:
    """Get serial number for a reader using yubico-piv-tool."""
    try:
        result = subprocess.run(
            ['yubico-piv-tool', '-r', reader, '-a', 'status'],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        # Parse output for serial number
        for line in result.stdout.splitlines():
            if 'Serial Number:' in line:
                serial_str = line.split('Serial Number:')[1].strip()
                return int(serial_str)

        return None

    except subprocess.CalledProcessError:
        return None


def get_devices_via_ykman() -> list[tuple[object, int, str]]:
    """Get devices via ykman API with serial numbers."""
    from ykman.device import list_all_devices

    devices = list(list_all_devices())
    result = []

    for device, info in devices:
        result.append((device, info.serial, str(info.version)))

    return result


def find_reader_for_serial(target_serial: int, readers: list[str]) -> str | None:
    """Find the reader name that corresponds to a serial number."""
    for reader in readers:
        serial = get_serial_for_reader(reader)
        if serial == target_serial:
            return reader
    return None


def test_bridge() -> bool:
    """Test the bridge between ykman and yubico-piv-tool."""
    print("=" * 70)
    print("BRIDGING TEST: ykman → yubico-piv-tool")
    print("=" * 70)
    print()

    # Step 1: Get devices via ykman
    print("Step 1: Enumerate devices via ykman API")
    print("-" * 70)

    ykman_devices = get_devices_via_ykman()

    if not ykman_devices:
        print("✗ No devices found via ykman")
        return False

    print(f"✓ Found {len(ykman_devices)} device(s) via ykman:")
    for device, serial, version in ykman_devices:
        print(f"  - Serial: {serial}, Version: {version}")

    print()

    # Step 2: Get readers via yubico-piv-tool
    print("Step 2: List readers via yubico-piv-tool")
    print("-" * 70)

    readers = get_readers_via_yubico_piv_tool()

    if not readers:
        print("✗ No readers found via yubico-piv-tool")
        return False

    print(f"✓ Found {len(readers)} reader(s) via yubico-piv-tool:")
    for reader in readers:
        print(f"  - {reader}")

    print()

    # Step 3: Map each ykman device to its reader name
    print("Step 3: Map ykman devices to reader names")
    print("-" * 70)

    mapping = {}
    for device, serial, version in ykman_devices:
        print(f"\nLooking for reader corresponding to serial {serial}...")

        reader = find_reader_for_serial(serial, readers)

        if reader:
            print(f"  ✓ Found: {reader}")
            mapping[serial] = reader

            # Verify by reading serial via reader
            verified_serial = get_serial_for_reader(reader)
            if verified_serial == serial:
                print("  ✓✓ Verified: reader serial matches ykman serial")
            else:
                print(f"  ✗ Mismatch: reader reports serial {verified_serial}")
        else:
            print("  ✗ No matching reader found")

    print()

    # Step 4: Summary
    print("=" * 70)
    print("BRIDGE VERIFICATION RESULTS")
    print("=" * 70)
    print()

    if len(mapping) == len(ykman_devices):
        print("✓✓ SUCCESS: All ykman devices mapped to reader names")
        print()
        print("Mapping:")
        for serial, reader in mapping.items():
            print(f"  Serial {serial} → '{reader}'")

        print()
        print("This confirms we can:")
        print("  1. Select device by serial via ykman")
        print("  2. Get corresponding reader name")
        print("  3. Use that reader with existing yb code")
        print()

        # Step 5: Can we get reader name directly from ykman?
        print("=" * 70)
        print("BONUS: Check if ykman provides reader name directly")
        print("=" * 70)
        print()

        from ykman.device import list_all_devices

        devices = list(list_all_devices())
        for device, info in devices:
            print(f"Device serial {info.serial}:")
            print(f"  device object: {device}")
            print(f"  device type: {type(device)}")

            # Check for reader-related attributes
            if hasattr(device, 'fingerprint'):
                print(f"  fingerprint: {device.fingerprint}")

            if hasattr(device, '_readers'):
                # Using getattr() to access the private attribute by string name
                print(f"  _readers: {getattr(device, '_readers')}")

        print()

        return True
    else:
        print(f"✗ PARTIAL: Only {len(mapping)}/{len(ykman_devices)} devices mapped")
        return False


def main() -> int:
    """Run the bridging test."""
    print("\n")
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 68 + "║")
    print("║" + "ykman ↔ yubico-piv-tool Bridging Test".center(68) + "║")
    print("║" + " " * 68 + "║")
    print("╚" + "═" * 68 + "╝")
    print()

    try:
        success = test_bridge()

        print()
        print("=" * 70)

        if success:
            print("✓ BRIDGE VERIFIED: ykman and yubico-piv-tool can be used together")
        else:
            print("⚠ BRIDGE INCOMPLETE: Some gaps in mapping")

        print("=" * 70)
        print()

        return 0 if success else 1

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
