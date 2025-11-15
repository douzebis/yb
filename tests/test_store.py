#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

"""
Simple regression test for Store using EmulatedPiv.

This test verifies that the Store can be created, formatted, and used
with the EmulatedPiv implementation without requiring physical hardware.
"""

from __future__ import annotations

import sys
import time

# Add src to path
sys.path.insert(0, '/home/experiment/code/yb/src')

from yb.piv import EmulatedPiv
from yb.store import Store, Object
from yb.constants import (
    YBLOB_MAGIC,
    OBJECT_ID_ZERO,
)


def test_basic_store_operations() -> None:
    """Test basic Store operations: format, write, read."""

    print("=" * 70)
    print("Test: Basic Store Operations with EmulatedPiv")
    print("=" * 70)
    print()

    # Create emulated PIV and add a device
    print("1. Creating EmulatedPiv and adding device...")
    piv = EmulatedPiv()
    serial = 12345678
    reader = piv.add_device(serial=serial, version="5.7.1")
    print(f"   ✓ Added device: serial={serial}, reader={reader}")
    print()

    # Verify device enumeration
    print("2. Verifying device enumeration...")
    devices = piv.list_devices()
    assert len(devices) == 1, f"Expected 1 device, got {len(devices)}"
    dev_serial, dev_version, dev_reader = devices[0]
    assert dev_serial == serial, f"Serial mismatch: {dev_serial} != {serial}"
    assert dev_reader == reader, f"Reader mismatch: {dev_reader} != {reader}"
    print(f"   ✓ Device enumeration correct: {devices}")
    print()

    # Format the store
    print("3. Formatting store...")
    object_size = 512
    object_count = 10
    key_slot = 0x9a

    store = Store(
        reader=reader,
        yblob_magic=YBLOB_MAGIC,
        object_size_in_store=object_size,
        object_count_in_store=object_count,
        store_encryption_key_slot=key_slot,
        piv=piv,
    )

    # Create empty objects
    for index in range(object_count):
        obj = Object(
            store=store,
            object_index_in_store=index,
            object_age=0,
        )
        store.commit_object(obj)

    # Sync to device
    store.sync()
    print(f"   ✓ Store formatted: {object_count} objects of {object_size} bytes each")
    print()

    # Verify objects were written to emulated device
    print("4. Verifying objects were written...")
    for index in range(object_count):
        object_id = OBJECT_ID_ZERO + index
        data = piv.read_object(reader, object_id)
        assert len(data) == object_size, f"Object {index} size mismatch"
    print(f"   ✓ All {object_count} objects written correctly")
    print()

    # Load store from device
    print("5. Loading store from device...")
    loaded_store = Store.from_piv_device(reader, piv)
    assert loaded_store.yblob_magic == YBLOB_MAGIC
    assert loaded_store.object_size_in_store == object_size
    assert loaded_store.object_count_in_store == object_count
    assert len(loaded_store.objects) == object_count
    print("   ✓ Store loaded successfully")
    print()

    # Verify all objects are empty (age == 0)
    print("6. Verifying all objects are initially empty...")
    for obj in loaded_store.objects:
        assert obj.object_age == 0, f"Object {obj.object_index_in_store} has age {obj.object_age}, expected 0"
    print(f"   ✓ All {object_count} objects are empty as expected")
    print()

    # Create a simple blob
    print("7. Creating a test blob...")
    blob_name = "test-data"
    blob_payload = b"Hello, YubiKey!"
    blob_time = int(time.time())

    # Create head object for the blob
    head_obj = Object(
        store=loaded_store,
        object_index_in_store=0,
        object_age=1,
        chunk_pos_in_blob=0,
        next_chunk_index_in_store=0,  # Self-reference means last chunk
        blob_modification_time=blob_time,
        blob_size=len(blob_payload),
        blob_encryption_key_slot=0,  # Not encrypted
        blob_unencrypted_size=len(blob_payload),
        blob_name=blob_name,
        chunk_payload=blob_payload,
    )
    loaded_store.objects[0] = head_obj
    loaded_store.sync()
    print(f"   ✓ Created blob '{blob_name}' with {len(blob_payload)} bytes")
    print()

    # Reload and verify the blob
    print("8. Reloading store and verifying blob...")
    reloaded_store = Store.from_piv_device(reader, piv)
    reloaded_store.sanitize()

    # Find the blob
    blobs = [
        obj for obj in reloaded_store.objects
        if obj.object_age != 0 and obj.chunk_pos_in_blob == 0
    ]
    assert len(blobs) == 1, f"Expected 1 blob, got {len(blobs)}"

    blob = blobs[0]
    assert blob.blob_name == blob_name, f"Name mismatch: {blob.blob_name} != {blob_name}"
    assert blob.blob_size == len(blob_payload), f"Size mismatch: {blob.blob_size} != {len(blob_payload)}"

    # Verify payload (trim padding)
    actual_payload = blob.chunk_payload[:blob.blob_size]
    assert actual_payload == blob_payload, f"Payload mismatch: {actual_payload!r} != {blob_payload!r}"
    print(f"   ✓ Blob verified: name='{blob.blob_name}', size={blob.blob_size}, payload={actual_payload!r}")
    print()

    print("=" * 70)
    print("✓ All tests passed!")
    print("=" * 70)
    print()


def test_multiple_devices() -> None:
    """Test EmulatedPiv with multiple devices."""

    print("=" * 70)
    print("Test: Multiple Devices")
    print("=" * 70)
    print()

    print("1. Creating EmulatedPiv with 3 devices...")
    piv = EmulatedPiv()

    devices_to_add = [
        (11111111, "5.4.3"),
        (22222222, "5.7.1"),
        (33333333, "5.7.2"),
    ]

    for serial, version in devices_to_add:
        reader = piv.add_device(serial=serial, version=version)
        print(f"   ✓ Added: serial={serial}, version={version}, reader={reader}")
    print()

    print("2. Verifying device enumeration...")
    devices = piv.list_devices()
    assert len(devices) == 3, f"Expected 3 devices, got {len(devices)}"
    print(f"   ✓ Found {len(devices)} devices:")
    for serial, version, reader in devices:
        print(f"     - Serial {serial}: {version} ({reader})")
    print()

    print("3. Testing get_reader_for_serial...")
    for serial, version in devices_to_add:
        reader = piv.get_reader_for_serial(serial)
        assert reader == f"Emulated YubiKey {serial}"
        print(f"   ✓ Serial {serial} -> {reader}")
    print()

    print("4. Testing error case: non-existent serial...")
    try:
        piv.get_reader_for_serial(99999999)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        print(f"   ✓ Correctly raised ValueError: {e}")
    print()

    print("=" * 70)
    print("✓ All tests passed!")
    print("=" * 70)
    print()


def main() -> int:
    """Run all tests."""
    print()
    print("Store Regression Tests")
    print()

    try:
        test_basic_store_operations()
        test_multiple_devices()

        print()
        print("=" * 70)
        print("SUCCESS: All tests passed!")
        print("=" * 70)
        print()
        return 0

    except AssertionError as e:
        print()
        print("=" * 70)
        print(f"FAILURE: {e}")
        print("=" * 70)
        print()
        import traceback
        traceback.print_exc()
        return 1

    except Exception as e:
        print()
        print("=" * 70)
        print(f"ERROR: {e}")
        print("=" * 70)
        print()
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
