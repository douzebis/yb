#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

"""
Comprehensive regression test for Store with 2000+ random operations.

This test verifies Store correctness by:
1. Running 2000+ pseudo-random operations (store, fetch, remove, list)
2. Maintaining a "toy filesystem" (dict) as ground truth
3. Verifying Store state matches expected state after all operations
4. Testing recovery from simulated ejection events

The test uses a fixed random seed for reproducibility.
"""

from __future__ import annotations

import sys
import time

# Add src to path
sys.path.insert(0, '/home/experiment/code/yb/src')

from yb import orchestrator
from yb.constants import YBLOB_MAGIC
from yb.piv import EjectionError, EmulatedPiv
from yb.store import Object, Store
from yb.test_helpers import OpType, Operation, OperationGenerator, ToyFilesystem


# === COMPREHENSIVE TEST =======================================================

def test_comprehensive_operations(
    operation_count: int = 200,
    seed: int = 42,
    verbose: bool = False
) -> None:
    """
    Run comprehensive test with many random operations (no ejections).

    Args:
        operation_count: Number of operations to perform
        seed: Random seed for reproducibility
        verbose: Print detailed operation log
    """
    print("=" * 70)
    print(f"Comprehensive Test: {operation_count} Random Operations (No Ejections)")
    print("=" * 70)
    print()

    # Setup
    print("1. Setting up test environment...")
    piv = EmulatedPiv()  # No ejections
    serial = 88888888
    reader = piv.add_device(serial=serial, version="5.7.1")
    print(f"   ✓ Created emulated device: serial={serial}")

    # Format store - need more objects for multi-chunk blobs
    object_size = 512
    object_count = 100  # More objects for multi-chunk support

    store = Store(
        reader=reader,
        yblob_magic=YBLOB_MAGIC,
        object_size_in_store=object_size,
        object_count_in_store=object_count,
        store_encryption_key_slot=0x9a,
        piv=piv,
    )

    for index in range(object_count):
        obj = Object(
            store=store,
            object_index_in_store=index,
            object_age=0,
        )
        store.commit_object(obj)

    store.sync()
    print(f"   ✓ Formatted store: {object_count} objects × {object_size} bytes")
    print()

    # Create ground truth
    toy_fs = ToyFilesystem()

    # Generate operations
    print(f"2. Generating {operation_count} random operations (seed={seed})...")
    generator = OperationGenerator(seed=seed, max_capacity=object_count)
    operations = generator.generate(operation_count)

    op_counts = {
        OpType.STORE: sum(1 for op in operations if op.op_type == OpType.STORE),
        OpType.FETCH: sum(1 for op in operations if op.op_type == OpType.FETCH),
        OpType.REMOVE: sum(1 for op in operations if op.op_type == OpType.REMOVE),
        OpType.LIST: sum(1 for op in operations if op.op_type == OpType.LIST),
    }
    print( "   ✓ Generated operations:")
    for op_type, count in op_counts.items():
        print(f"     - {op_type.value.upper()}: {count}")
    print()

    # Execute operations
    print( "3. Executing operations...")
    errors = []
    current_time = int(time.time())
    progress_interval = max(1, operation_count // 20)  # Show progress every 5%

    for i, op in enumerate(operations):
        if not verbose and i > 0 and i % progress_interval == 0:
            print(f"   Progress: {i}/{operation_count} ({100*i//operation_count}%)")

        try:
            if op.op_type == OpType.STORE:
                # Store operation using orchestrator
                # Note: orchestrator handles encryption, but we're testing unencrypted only
                success = orchestrator.store_blob(
                    reader=reader,
                    piv=piv,
                    name=op.name,
                    payload=op.payload,
                    encrypted=False,
                    management_key=None,
                )

                if success:
                    toy_fs.store(op.name, op.payload, current_time)
                    current_time += 1

                    if verbose:
                        print(f"   [{i+1}] STORE({op.name!r}, {len(op.payload)} bytes) - OK")
                elif verbose:
                    print(f"   [{i+1}] STORE({op.name!r}, {len(op.payload)} bytes) - FULL")
                # If not successful, both Store and ToyFS unchanged (operation skipped)

            elif op.op_type == OpType.FETCH:
                # Fetch from both and compare
                expected = toy_fs.fetch(op.name)
                actual_payload = orchestrator.fetch_blob(
                    reader=reader,
                    piv=piv,
                    name=op.name,
                    pin=None,  # No encryption in test
                )

                if expected is None:
                    if actual_payload is not None:
                        errors.append(f"Op {i+1} FETCH({op.name!r}): Expected None, got {len(actual_payload)} bytes")
                else:
                    expected_payload = expected[0]
                    if actual_payload != expected_payload:
                        errors.append(
                            f"Op {i+1} FETCH({op.name!r}): Payload mismatch\n"
                            f"  Expected: {len(expected_payload)} bytes\n"
                            f"  Actual:   {len(actual_payload) if actual_payload else 'None'} bytes"
                        )

                if verbose:
                    status = "OK" if expected is None and actual_payload is None or \
                                     (expected is not None and actual_payload == expected[0]) else "MISMATCH"
                    print(f"   [{i+1}] FETCH({op.name!r}) - {status}")

            elif op.op_type == OpType.REMOVE:
                # Remove from both and compare
                expected_removed = toy_fs.remove(op.name)
                actual_removed = orchestrator.remove_blob(
                    reader=reader,
                    piv=piv,
                    name=op.name,
                    management_key=None,
                )

                if expected_removed != actual_removed:
                    errors.append(
                        f"Op {i+1} REMOVE({op.name!r}): Expected {expected_removed}, got {actual_removed}"
                    )

                if verbose:
                    status = "OK" if expected_removed == actual_removed else "MISMATCH"
                    print(f"   [{i+1}] REMOVE({op.name!r}) - {status}")

            elif op.op_type == OpType.LIST:
                # List from both and compare
                expected_names = toy_fs.list()
                actual_blobs = orchestrator.list_blobs(reader=reader, piv=piv)
                actual_names = [name for name, _, _, _, _ in actual_blobs]

                if expected_names != actual_names:
                    errors.append(
                        f"Op {i+1} LIST: Mismatch\n"
                        f"  Expected: {expected_names}\n"
                        f"  Actual:   {actual_names}"
                    )

                if verbose:
                    status = "OK" if expected_names == actual_names else "MISMATCH"
                    print(f"   [{i+1}] LIST - {status}")

        except Exception as e:
            errors.append(f"Op {i+1} {op}: Unexpected exception: {e}")
            if verbose:
                print(f"   [{i+1}] {op} - EXCEPTION: {e}")

    print(f"   ✓ Completed {operation_count} operations")
    print()

    # Print results
    print("=" * 70)
    if errors:
        print(f"✗ TEST FAILED with {len(errors)} error(s):")
        print("=" * 70)
        for error in errors[:10]:  # Show first 10 errors
            print(f"  {error}")
        if len(errors) > 10:
            print(f"  ... and {len(errors) - 10} more errors")
    else:
        print("✓ TEST PASSED - All operations matched expected behavior!")
    print("=" * 70)

    assert not errors, f"Test failed with {len(errors)} errors"


# === EJECTION TEST ============================================================

def test_with_ejection_simulation(
    operation_count: int = 2000,
    ejection_probability: float = 0.2,
    seed: int = 42,
    verbose: bool = False
) -> None:
    """
    Run comprehensive test with simulated ejection events.

    When ejection occurs during a write operation:
    - The operation may partially complete
    - We reconnect and compare state with BOTH old and new expected values
    - Either is acceptable (operation may have been aborted or completed)

    Args:
        operation_count: Number of operations to perform
        ejection_probability: Probability of ejection during each write (0.0-1.0)
        seed: Random seed for reproducibility
        verbose: Print detailed operation log
    """
    print("=" * 70)
    print(f"Ejection Test: {operation_count} Operations with {ejection_probability*100}% Ejection Rate")
    print("=" * 70)
    print()

    # Setup with ejection simulation
    print("1. Setting up test environment with ejection simulation...")
    piv = EmulatedPiv(ejection_probability=0.0, seed=seed + 1)  # No ejections during setup
    serial = 88888888
    reader = piv.add_device(serial=serial, version="5.7.1")

    # Format store
    object_size = 512
    object_count = 100

    store = Store(
        reader=reader,
        yblob_magic=YBLOB_MAGIC,
        object_size_in_store=object_size,
        object_count_in_store=object_count,
        store_encryption_key_slot=0x9a,
        piv=piv,
    )

    for index in range(object_count):
        obj = Object(
            store=store,
            object_index_in_store=index,
            object_age=0,
        )
        store.commit_object(obj)

    store.sync()
    print(f"   ✓ Formatted store: {object_count} objects × {object_size} bytes")

    # Now enable ejection simulation for actual test operations
    piv.ejection_probability = ejection_probability
    print(f"   ✓ Enabled ejection simulation: {ejection_probability*100}% probability")
    print()

    # Create ground truth - track TWO possible states
    toy_fs_before = ToyFilesystem()  # State before operation
    toy_fs_after = ToyFilesystem()   # State if operation succeeds

    # Generate operations
    print(f"2. Generating {operation_count} random operations (seed={seed})...")
    generator = OperationGenerator(seed=seed, max_capacity=object_count)
    operations = generator.generate(operation_count)

    op_counts = {
        OpType.STORE: sum(1 for op in operations if op.op_type == OpType.STORE),
        OpType.FETCH: sum(1 for op in operations if op.op_type == OpType.FETCH),
        OpType.REMOVE: sum(1 for op in operations if op.op_type == OpType.REMOVE),
        OpType.LIST: sum(1 for op in operations if op.op_type == OpType.LIST),
    }
    print( "   ✓ Generated operations:")
    for op_type, count in op_counts.items():
        print(f"     - {op_type.value.upper()}: {count}")
    print()

    # Execute operations
    print( "3. Executing operations with ejection handling...")
    errors = []
    current_time = int(time.time())
    progress_interval = max(1, operation_count // 20)
    ejection_count = 0

    for i, op in enumerate(operations):
        if not verbose and i > 0 and i % progress_interval == 0:
            print(f"   Progress: {i}/{operation_count} ({100*i//operation_count}%), Ejections: {ejection_count}")

        # Save state before operation
        toy_fs_before = ToyFilesystem()
        toy_fs_before.files = toy_fs_after.files.copy()

        # Predict what "after" state would be if operation succeeds
        toy_fs_predicted_after = ToyFilesystem()
        toy_fs_predicted_after.files = toy_fs_after.files.copy()

        if op.op_type == OpType.STORE:
            # Predicted: blob will be added/updated
            toy_fs_predicted_after.store(op.name, op.payload, current_time)
        elif op.op_type == OpType.REMOVE:
            # Predicted: blob will be removed if it exists
            toy_fs_predicted_after.remove(op.name)

        try:
            if op.op_type == OpType.STORE:
                # Attempt store operation
                success = orchestrator.store_blob(
                    reader=reader,
                    piv=piv,
                    name=op.name,
                    payload=op.payload,
                    encrypted=False,
                    management_key=None,
                )

                if success:
                    toy_fs_after = toy_fs_predicted_after
                    current_time += 1

                    if verbose:
                        print(f"   [{i+1}] STORE({op.name!r}, {len(op.payload)} bytes) - OK")
                # If not successful (full), toy_fs_after stays unchanged

            elif op.op_type == OpType.REMOVE:
                # Attempt remove operation
                success = orchestrator.remove_blob(
                    reader=reader,
                    piv=piv,
                    name=op.name,
                    management_key=None,
                )

                if success:
                    toy_fs_after = toy_fs_predicted_after

                if verbose:
                    print(f"   [{i+1}] REMOVE({op.name!r}) - {'REMOVED' if success else 'NOT_FOUND'}")

            elif op.op_type == OpType.FETCH:
                # Fetch (read-only, no ejection risk)
                expected = toy_fs_after.fetch(op.name)
                actual_payload = orchestrator.fetch_blob(
                    reader=reader,
                    piv=piv,
                    name=op.name,
                    pin=None,
                )

                # Verify fetch result
                if expected is None:
                    if actual_payload is not None:
                        errors.append(f"Op {i+1} FETCH({op.name!r}): Expected None, got payload")
                else:
                    if actual_payload != expected[0]:
                        errors.append(f"Op {i+1} FETCH({op.name!r}): Payload mismatch")

                if verbose:
                    status = "OK" if (expected is None and actual_payload is None) or \
                                     (expected and actual_payload == expected[0]) else "MISMATCH"
                    print(f"   [{i+1}] FETCH({op.name!r}) - {status}")

            elif op.op_type == OpType.LIST:
                # List (read-only, no ejection risk)
                expected_names = toy_fs_after.list()
                actual_blobs = orchestrator.list_blobs(reader=reader, piv=piv)
                actual_names = [name for name, _, _, _, _ in actual_blobs]

                if expected_names != actual_names:
                    errors.append(
                        f"Op {i+1} LIST: Expected {expected_names}, got {actual_names}"
                    )

                if verbose:
                    status = "OK" if expected_names == actual_names else "MISMATCH"
                    print(f"   [{i+1}] LIST - {status}")

        except EjectionError as e:
            # Ejection occurred during write!
            ejection_count += 1
            if verbose:
                print(f"   [{i+1}] {op} - EJECTED ({e})")

            # Reconnect device
            piv.reconnect()

            # Verify state is either before OR predicted_after (partial write acceptable)
            actual_blobs = orchestrator.list_blobs(reader=reader, piv=piv)
            actual_names = set(name for name, _, _, _, _ in actual_blobs)
            expected_before = set(toy_fs_before.list())
            expected_after = set(toy_fs_predicted_after.list())

            # For STORE operations that updated existing blobs, also check payload
            payload_matches_after = True
            if op.op_type == OpType.STORE and actual_names == expected_after:
                # Verify payload is correct by fetching the blob
                actual_payload = orchestrator.fetch_blob(
                    reader=reader,
                    piv=piv,
                    name=op.name,
                    pin=None,
                )
                fetched = toy_fs_predicted_after.fetch(op.name)
                expected_payload = b'' if fetched is None else fetched[0]
                payload_matches_after = (actual_payload == expected_payload)

            if actual_names == expected_after and payload_matches_after:
                # Operation completed despite ejection - use predicted after state
                toy_fs_after = toy_fs_predicted_after
                if op.op_type == OpType.STORE:
                    current_time += 1
            elif actual_names == expected_before:
                # Operation rolled back - keep before state (toy_fs_after unchanged)
                pass
            else:
                # State doesn't match either before or after
                errors.append(
                    f"Op {i+1} {op} EJECTED: State mismatch\n"
                    f"  Expected (before): {sorted(expected_before)}\n"
                    f"  Expected (after):  {sorted(expected_after)}\n"
                    f"  Actual:            {sorted(actual_names)}"
                )

        except Exception as e:
            errors.append(f"Op {i+1} {op}: Unexpected exception: {e}")
            if verbose:
                print(f"   [{i+1}] {op} - EXCEPTION: {e}")

    print(f"   ✓ Completed {operation_count} operations with {ejection_count} ejections")
    print()

    # Print results
    print("=" * 70)
    if errors:
        print(f"✗ TEST FAILED with {len(errors)} error(s):")
        print("=" * 70)
        for error in errors[:10]:
            print(f"  {error}")
        if len(errors) > 10:
            print(f"  ... and {len(errors) - 10} more errors")
    else:
        print( "✓ TEST PASSED - All operations handled correctly!")
        print(f"  Total ejections: {ejection_count}")
        print(f"  Ejection rate: {100*ejection_count/operation_count:.2f}%")
    print("=" * 70)

    assert not errors, f"Test failed with {len(errors)} errors"
