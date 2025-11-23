#!/usr/bin/env python

# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

"""Test script for PIN-protected management key mode."""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from yb.piv import EmulatedPiv
from yb.auxiliaries import (
    detect_pin_protected_mode,
    get_pin_protected_management_key,
    check_for_default_credentials,
)

def test_pin_protected_mode():
    """Test PIN-protected mode detection and key retrieval."""
    print("=" * 70)
    print("Testing PIN-Protected Management Key Mode")
    print("=" * 70)

    # Test 1: Create EmulatedPiv without PIN-protected mode
    print("\n[Test 1] EmulatedPiv without PIN-protected mode")
    print("-" * 70)
    piv = EmulatedPiv()
    reader = piv.add_device(serial=12345678, version="5.7.1", pin_protected=False)

    is_protected, is_derived = detect_pin_protected_mode(reader, piv)
    print(f"PIN-protected mode: {is_protected}")
    print(f"PIN-derived mode: {is_derived}")
    assert is_protected == False, "Should not detect PIN-protected mode"
    assert is_derived == False, "Should not detect PIN-derived mode"
    print("✓ Test 1 passed")

    # Test 2: Check for default credentials (should find defaults)
    print("\n[Test 2] Check default credentials (without PIN-protected mode)")
    print("-" * 70)
    try:
        check_for_default_credentials(reader, piv, allow_defaults=False)
        print("✗ Test 2 failed - should have raised exception for default credentials")
        sys.exit(1)
    except Exception as e:
        if "default credentials" in str(e):
            print(f"✓ Test 2 passed - correctly detected default credentials")
        else:
            print(f"✗ Test 2 failed - unexpected error: {e}")
            sys.exit(1)

    # Test 3: Create EmulatedPiv WITH PIN-protected mode
    print("\n[Test 3] EmulatedPiv with PIN-protected mode")
    print("-" * 70)
    piv2 = EmulatedPiv()
    reader2 = piv2.add_device(serial=87654321, version="5.7.1", pin_protected=True)

    is_protected, is_derived = detect_pin_protected_mode(reader2, piv2)
    print(f"PIN-protected mode: {is_protected}")
    print(f"PIN-derived mode: {is_derived}")
    assert is_protected == True, "Should detect PIN-protected mode"
    assert is_derived == False, "Should not detect PIN-derived mode"
    print("✓ Test 3 passed")

    # Test 4: Check for default credentials (should NOT find defaults)
    print("\n[Test 4] Check default credentials (with PIN-protected mode)")
    print("-" * 70)
    try:
        check_for_default_credentials(reader2, piv2, allow_defaults=False)
        print("✓ Test 4 passed - no default credentials found")
    except Exception as e:
        print(f"✗ Test 4 failed - should not find default credentials: {e}")
        sys.exit(1)

    # Test 5: Retrieve management key from PRINTED object
    print("\n[Test 5] Retrieve management key from PRINTED object")
    print("-" * 70)
    try:
        # EmulatedPiv doesn't require actual PIN verification, but we pass None
        mgmt_key = get_pin_protected_management_key(reader2, piv2, pin=None)
        expected_key = '0102030405060708090a0b0c0d0e0f101112131415161718'
        print(f"Retrieved key: {mgmt_key}")
        print(f"Expected key:  {expected_key}")
        assert mgmt_key == expected_key, f"Key mismatch: got {mgmt_key}, expected {expected_key}"
        print("✓ Test 5 passed")
    except Exception as e:
        print(f"✗ Test 5 failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    # Test 6: Verify ADMIN DATA structure
    print("\n[Test 6] Verify ADMIN DATA structure")
    print("-" * 70)
    try:
        admin_data = piv2.read_object(reader2, 0x5FFF00)
        print(f"ADMIN DATA: {admin_data.hex()}")
        print(f"  Length: {len(admin_data)} bytes")

        from yb.auxiliaries import parse_admin_data
        parsed = parse_admin_data(admin_data)
        print(f"  Parsed: {parsed}")
        assert parsed['mgmt_key_stored'] == True, "mgmt_key_stored should be True"
        assert parsed['pin_derived'] == False, "pin_derived should be False"
        print("✓ Test 6 passed")
    except Exception as e:
        print(f"✗ Test 6 failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    # Test 7: Verify PRINTED object structure
    print("\n[Test 7] Verify PRINTED object structure")
    print("-" * 70)
    try:
        printed_data = piv2.read_object(reader2, 0x5FC109)
        print(f"PRINTED DATA: {printed_data.hex()}")
        print(f"  Length: {len(printed_data)} bytes")
        print("✓ Test 7 passed")
    except Exception as e:
        print(f"✗ Test 7 failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    print("\n" + "=" * 70)
    print("All tests passed! ✓")
    print("=" * 70)

if __name__ == "__main__":
    test_pin_protected_mode()
