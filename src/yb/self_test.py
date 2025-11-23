#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

"""
Self-test functionality for yb.

Performs end-to-end CLI testing on a real YubiKey by executing a series of
pseudo-random operations via subprocess calls to the yb CLI itself.
"""

from __future__ import annotations

import getpass
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field

from yb.test_helpers import OperationGenerator, OpType, ToyFilesystem

# === SUBPROCESS EXECUTOR ======================================================

class SubprocessExecutor:
    """Execute yb commands via subprocess and verify results."""

    def __init__(self, serial: int, pin: str, mgmt_key: str | None = None, debug: bool = False):
        self.serial = serial
        self.pin = pin
        self.mgmt_key = mgmt_key
        self.debug = debug

    def _build_base_cmd(self) -> list[str]:
        """Build base command with device selection and PIN."""
        cmd = [
            'yb',
            '--serial', str(self.serial),
            '--pin', self.pin,
        ]
        if self.mgmt_key:
            cmd += ['--key', self.mgmt_key]
        if self.debug:
            cmd += ['--debug']
        return cmd

    def _run_subprocess(self, cmd: list[str], input_data: bytes | None = None, timeout: int = 30) -> subprocess.CompletedProcess:
        """
        Run subprocess with debug output.

        Args:
            cmd: Command to run
            input_data: Optional input data (for stdin)
            timeout: Timeout in seconds

        Returns:
            CompletedProcess object
        """
        if self.debug:
            # Show command with actual credentials for debugging
            print(f"[DEBUG] Subprocess command: {' '.join(cmd)}", file=sys.stderr)
            if input_data:
                print(f"[DEBUG] Subprocess stdin: {len(input_data)} bytes", file=sys.stderr)

        result = subprocess.run(
            cmd,
            input=input_data,
            capture_output=True,
            timeout=timeout
        )

        if self.debug:
            print(f"[DEBUG] Subprocess exit status: {result.returncode}", file=sys.stderr)
            if result.stdout:
                print(f"[DEBUG] Subprocess stdout ({len(result.stdout)} bytes):", file=sys.stderr)
                print(result.stdout.decode('utf-8', errors='replace'), file=sys.stderr)
            if result.stderr:
                print(f"[DEBUG] Subprocess stderr ({len(result.stderr)} bytes):", file=sys.stderr)
                print(result.stderr.decode('utf-8', errors='replace'), file=sys.stderr)

        return result

    def format(self, object_count: int = 16, generate_key: bool = True) -> tuple[bool, int, float]:
        """
        Execute: yb format [--generate] [--object-count N]

        Returns:
            (success, exit_code, duration_seconds)
        """
        cmd = self._build_base_cmd() + ['format']
        if generate_key:
            cmd.append('--generate')
        cmd += ['--object-count', str(object_count)]

        start = time.time()
        result = self._run_subprocess(cmd, timeout=60)
        duration = time.time() - start

        return result.returncode == 0, result.returncode, duration

    def store_blob(self, name: str, payload: bytes, encrypted: bool = True) -> tuple[bool, int, str]:
        """
        Execute: yb store [--encrypted|--unencrypted] NAME < payload

        Returns:
            (success, exit_code, stderr)
        """
        cmd = self._build_base_cmd() + ['store']
        cmd += ['--encrypted' if encrypted else '--unencrypted']
        cmd += [name]

        result = self._run_subprocess(cmd, input_data=payload)
        stderr = result.stderr.decode('utf-8', errors='replace').strip() if result.stderr else ""
        return result.returncode == 0, result.returncode, stderr

    def fetch_blob(self, name: str) -> tuple[bytes | None, int]:
        """
        Execute: yb fetch NAME

        Returns:
            (payload, exit_code) - payload is None on failure
        """
        cmd = self._build_base_cmd() + ['fetch', name]
        result = self._run_subprocess(cmd)
        if result.returncode != 0:
            return None, result.returncode
        return result.stdout, 0

    def remove_blob(self, name: str) -> tuple[bool, int]:
        """
        Execute: yb rm NAME

        Returns:
            (success, exit_code)
        """
        cmd = self._build_base_cmd() + ['rm', name]
        result = self._run_subprocess(cmd)
        return result.returncode == 0, result.returncode

    def list_blobs(self) -> tuple[list[str], int]:
        """
        Execute: yb ls, parse output for blob names

        Returns:
            (blob_names, exit_code)
        """
        cmd = self._build_base_cmd() + ['ls']
        result = self._run_subprocess(cmd)

        if result.returncode != 0:
            return [], result.returncode

        # Parse output: "- 1  100  2025-11-16 ...  blobname"
        names = []
        stdout_text = result.stdout.decode('utf-8', errors='replace')
        for line in stdout_text.splitlines():
            if line.strip():
                parts = line.split()
                if len(parts) >= 5:
                    names.append(parts[-1])  # Last column is name
        return names, 0


# === TEST STATISTICS ==========================================================

@dataclass
class TestStats:
    """Track test execution statistics."""

    total_operations: int = 0
    passed_operations: int = 0
    failed_operations: int = 0

    store_count: int = 0
    store_passed: int = 0
    fetch_count: int = 0
    fetch_passed: int = 0
    remove_count: int = 0
    remove_passed: int = 0
    list_count: int = 0
    list_passed: int = 0

    failures: list[str] = field(default_factory=list)
    interrupted: bool = False

    def record_operation(self, op_type: OpType, success: bool, error_msg: str = "") -> None:
        """Record the result of an operation."""
        self.total_operations += 1

        if op_type == OpType.STORE:
            self.store_count += 1
            if success:
                self.store_passed += 1
        elif op_type == OpType.FETCH:
            self.fetch_count += 1
            if success:
                self.fetch_passed += 1
        elif op_type == OpType.REMOVE:
            self.remove_count += 1
            if success:
                self.remove_passed += 1
        elif op_type == OpType.LIST:
            self.list_count += 1
            if success:
                self.list_passed += 1

        if success:
            self.passed_operations += 1
        else:
            self.failed_operations += 1
            if error_msg:
                self.failures.append(error_msg)

    def all_passed(self) -> bool:
        """Check if all operations passed."""
        return self.failed_operations == 0 and not self.interrupted

    def mark_interrupted(self) -> None:
        """Mark the test as interrupted by user."""
        self.interrupted = True


# === HELPER FUNCTIONS =========================================================

def request_pin() -> str:
    """Request PIN from user interactively."""
    try:
        pin = getpass.getpass("YubiKey PIN: ")
        if not pin:
            raise ValueError("PIN cannot be empty")
        return pin
    except (EOFError, KeyboardInterrupt):
        print("\nPIN entry cancelled", file=sys.stderr)
        sys.exit(1)


def request_management_key() -> str:
    """Request management key from user interactively."""
    try:
        key = getpass.getpass("Management key (48 hex chars, or Enter for default): ")
        if not key:
            # Use default YubiKey management key
            return "010203040506070801020304050607080102030405060708"
        # Basic validation
        key = key.replace(' ', '').replace('-', '').lower()
        if len(key) != 48:
            raise ValueError(f"Management key must be 48 hex characters, got {len(key)}")
        return key
    except (EOFError, KeyboardInterrupt):
        print("\nManagement key entry cancelled", file=sys.stderr)
        sys.exit(1)


def flash_yubikey_continuously(serial: int, stop_event: threading.Event, debug: bool = False) -> None:
    """
    Flash the LED of the YubiKey with the given serial number continuously.

    Continues flashing until stop_event is set.
    """
    try:
        from typing import Protocol, cast

        from ykman.device import list_all_devices
        from yubikit.core.smartcard import SmartCardConnection

        class PcscConnection(Protocol):
            """Protocol for pyscard connection object."""
            def transmit(self, apdu: list[int]) -> tuple[list[int], int, int]:
                ...

        class ScardSmartCardConnection(Protocol):
            """Protocol for ykman.pcsc.ScardSmartCardConnection."""
            connection: PcscConnection

        if debug:
            print(f"[DEBUG] LED flash thread started for serial {serial}", file=sys.stderr)

        devices = list_all_devices()
        device_obj = None
        for device, info in devices:
            if info.serial == serial:
                device_obj = device
                if debug:
                    print(f"[DEBUG] LED flash: found device with serial {serial}", file=sys.stderr)
                break

        if device_obj is None:
            if debug:
                print(f"[DEBUG] LED flash: device {serial} not found", file=sys.stderr)
            return

        # Flash continuously until stopped
        flash_count = 0
        while not stop_event.is_set():
            try:
                with device_obj.open_connection(SmartCardConnection) as _conn:
                    conn = cast(ScardSmartCardConnection, _conn)
                    # SELECT PIV application - causes LED flash
                    # PIV AID: A0 00 00 03 08
                    piv_aid = [0xA0, 0x00, 0x00, 0x03, 0x08]
                    apdu = [0x00, 0xA4, 0x04, 0x00, len(piv_aid)] + piv_aid
                    conn.connection.transmit(apdu)

                flash_count += 1
                if debug and flash_count % 10 == 0:
                    print(f"[DEBUG] LED flash count: {flash_count}", file=sys.stderr)

                # Wait a bit before next flash (avoid excessive polling)
                # Check stop_event more frequently for responsiveness
                for _ in range(3):  # 3 x 100ms = 300ms between flashes
                    if stop_event.is_set():
                        break
                    time.sleep(0.1)
            except Exception as e:
                if debug:
                    print(f"[DEBUG] LED flash error: {e}", file=sys.stderr)
                # Ignore errors and continue flashing
                if not stop_event.is_set():
                    time.sleep(0.1)

        if debug:
            print(f"[DEBUG] LED flash thread stopped (total flashes: {flash_count})", file=sys.stderr)

    except Exception as e:
        if debug:
            print(f"[DEBUG] LED flash thread failed to start: {e}", file=sys.stderr)
        # Silently ignore errors during flashing
        pass


def confirm_destructive_test(serial: int, num_operations: int = 200, flash: bool = True, debug: bool = False) -> bool:
    """
    Prompt user for confirmation before destructive test.

    Args:
        serial: YubiKey serial number
        num_operations: Number of test operations to perform
        flash: If True, flash YubiKey LED continuously during prompt
        debug: Enable debug output

    Returns:
        True if user confirmed with 'yes'
    """
    print()
    print("=" * 70)
    print("WARNING: DESTRUCTIVE OPERATION")
    print("=" * 70)
    print()
    print( "YubiKey to test:")
    print(f"  Serial: {serial}")
    print()
    print("This self-test will:")
    print("  1. FORMAT the YubiKey (destroys all existing blob data)")
    print(f"  2. Perform {num_operations} store/fetch/remove operations (encrypted + unencrypted)")
    print("  3. Stop on first error (if any)")
    print("  4. Test with 16 objects and blobs up to 16 KB")
    print()
    print("ALL EXISTING BLOB DATA WILL BE PERMANENTLY LOST!")
    print()

    # Start continuous LED flashing to help user identify correct device
    flash_thread = None
    stop_flash_event = None

    if flash:
        print("YubiKey LED is flashing to help you identify the correct device...")
        print()
        stop_flash_event = threading.Event()
        flash_thread = threading.Thread(
            target=flash_yubikey_continuously,
            args=(serial, stop_flash_event, debug),
            daemon=True,
        )
        flash_thread.start()

    try:
        response = input("Type 'yes' to proceed with self-test: ")
        print()
        result = response.strip().lower() == 'yes'
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled by user")
        result = False
    finally:
        # Stop flashing
        if stop_flash_event is not None:
            stop_flash_event.set()
        if flash_thread is not None and flash_thread.is_alive():
            flash_thread.join(timeout=0.5)

    return result


def format_yubikey(
    serial: int,
    pin: str,
    mgmt_key: str,
    object_count: int = 16,
    debug: bool = False
) -> tuple[bool, float]:
    """
    Format YubiKey for blob storage.

    Returns:
        (success, duration_seconds)
    """
    print("Formatting YubiKey...")
    executor = SubprocessExecutor(serial, pin, mgmt_key, debug=debug)
    success, exit_code, duration = executor.format(
        object_count=object_count,
        generate_key=True
    )

    if success:
        print(f"Format complete ({duration:.1f} seconds)")
    else:
        print(f"ERROR: Format failed with exit code {exit_code}", file=sys.stderr)

    return success, duration


def run_test_operations(
    serial: int,
    pin: str,
    mgmt_key: str,
    num_operations: int = 200,
    debug: bool = False
) -> TestStats:
    """
    Run test operations and verify results.

    Returns:
        TestStats object with results
    """
    print(f"Running {num_operations} test operations...")
    print()

    # Initialize executor and ground truth
    executor = SubprocessExecutor(serial, pin, mgmt_key, debug=debug)
    toy_fs = ToyFilesystem()
    stats = TestStats()

    # Generate operations with 50% encryption ratio
    generator = OperationGenerator(seed=42, max_capacity=15)
    operations = generator.generate(count=num_operations, encryption_ratio=0.5)

    # Execute operations
    try:
        for i, op in enumerate(operations):
            # Show progress for each operation (one-liner)
            remaining = num_operations - (i + 1)
            op_desc = f"{op.op_type.value.upper()}"
            if op.op_type in (OpType.STORE, OpType.FETCH, OpType.REMOVE):
                op_desc += f"({op.name})"

            if not debug:
                # Non-debug: concise one-liner with countdown
                print(f"[{i+1}/{num_operations}, {remaining} remaining] {op_desc}...", end='', flush=True)
            else:
                # Debug: show operation details
                if (i + 1) % 10 == 0:
                    print(f"[DEBUG] Progress: {i+1}/{num_operations} operations ({remaining} remaining)", file=sys.stderr)

            success = False
            error_msg = ""
            mtime = i  # Use operation index as modification time

            try:
                if op.op_type == OpType.STORE:
                    # Store operation - update toy store first (optimistically)
                    was_updating = op.name in toy_fs.files  # Track if this is an update
                    old_value = toy_fs.files.get(op.name)  # Save old value in case we need to restore
                    toy_fs.store(op.name, op.payload, mtime)

                    # Try to store in YubiKey
                    yb_success, exit_code, stderr = executor.store_blob(op.name, op.payload, op.encrypted)

                    # Check if this is a "Store is full" error
                    is_full_error = "Store is full" in stderr if stderr else False

                    if yb_success:
                        # Store succeeded - toy store already updated
                        success = True
                    elif is_full_error:
                        # Store is full - undo the toy store update
                        if was_updating:
                            assert old_value is not None
                            toy_fs.files[op.name] = old_value  # Restore old value
                        else:
                            del toy_fs.files[op.name]  # Remove the optimistic add
                        success = True  # "Full" is valid behavior, not a failure
                    else:
                        # Real error - undo the toy store update
                        if was_updating:
                            assert old_value is not None
                            toy_fs.files[op.name] = old_value
                        else:
                            del toy_fs.files[op.name]
                        success = False
                        error_msg = f"Op #{i+1} STORE({op.name}): exit code {exit_code}"
                        if stderr:
                            error_lines = stderr.strip().split('\n')
                            if error_lines:
                                error_msg += f" - {error_lines[-1]}"

                elif op.op_type == OpType.FETCH:
                    # Fetch operation
                    payload, exit_code = executor.fetch_blob(op.name)
                    expected = toy_fs.fetch(op.name)

                    if expected is None:
                        # Blob shouldn't exist
                        success = (payload is None)
                        if not success:
                            len_payload = 0 if payload is None else len(payload)
                            error_msg = f"Op #{i+1} FETCH({op.name}): expected not found, but got {len_payload} bytes"
                    else:
                        # Blob should exist
                        if payload is None:
                            success = False
                            error_msg = f"Op #{i+1} FETCH({op.name}): expected {len(expected[0])} bytes, got None (exit {exit_code})"
                        else:
                            success = (payload == expected[0])
                            if not success:
                                error_msg = f"Op #{i+1} FETCH({op.name}): payload mismatch (expected {len(expected[0])} bytes, got {len(payload)} bytes)"

                elif op.op_type == OpType.REMOVE:
                    # Remove operation
                    rm_success, exit_code = executor.remove_blob(op.name)
                    expected_existed = toy_fs.remove(op.name)

                    # Success means: operation returned expected result
                    # If blob existed, removal should succeed
                    # If blob didn't exist, removal should fail
                    success = (rm_success == expected_existed)
                    if not success:
                        error_msg = f"Op #{i+1} REMOVE({op.name}): expected {'success' if expected_existed else 'failure'}, got {'success' if rm_success else 'failure'} (exit {exit_code})"

                elif op.op_type == OpType.LIST:
                    # List operation
                    actual_names, exit_code = executor.list_blobs()
                    expected_names = toy_fs.list()

                    success = (exit_code == 0 and actual_names == expected_names)
                    if not success:
                        if exit_code != 0:
                            error_msg = f"Op #{i+1} LIST: exit code {exit_code}"
                        else:
                            error_msg = f"Op #{i+1} LIST: expected {expected_names}, got {actual_names}"

            except subprocess.TimeoutExpired:
                error_msg = f"Op #{i+1} {op.op_type.value.upper()}: timeout"
            except Exception as e:
                error_msg = f"Op #{i+1} {op.op_type.value.upper()}: {type(e).__name__}: {e}"

            # Record result
            stats.record_operation(op.op_type, success, error_msg)

            # Show result
            if not debug:
                if success:
                    print(" OK")
                else:
                    print( " FAIL")
                    print(f"  Error: {error_msg}", file=sys.stderr)
                    # Stop on first true error - state is now unknown
                    print(f"\nStopping at first error (operation {i+1}/{num_operations})", file=sys.stderr)
                    print("State after error is unknown - cannot continue testing reliably", file=sys.stderr)
                    break

    except KeyboardInterrupt:
        print("\n\nTest interrupted by user", file=sys.stderr)
        stats.mark_interrupted()

    print()
    return stats


def cleanup_yubikey(serial: int, pin: str, mgmt_key: str, debug: bool = False) -> None:
    """Remove all blobs from the YubiKey (only called on success)."""
    print("Cleaning up YubiKey...")

    executor = SubprocessExecutor(serial, pin, mgmt_key, debug=debug)

    # List all blobs
    blobs, exit_code = executor.list_blobs()
    if exit_code != 0:
        print("Warning: Failed to list blobs during cleanup", file=sys.stderr)
        return

    if not blobs:
        print("Store is already empty")
        return

    # Remove each blob
    failed = []
    for name in blobs:
        success, exit_code = executor.remove_blob(name)
        if not success:
            failed.append((name, exit_code))

    if failed:
        print(f"Warning: Failed to remove {len(failed)} blob(s):", file=sys.stderr)
        for name, code in failed[:5]:  # Show first 5 failures
            print(f"  - {name} (exit {code})", file=sys.stderr)
    else:
        print("Store successfully emptied")


def print_report(stats: TestStats, total_duration: float) -> None:
    """Print final test report."""
    print("=" * 70)
    print("YB SELF-TEST REPORT")
    print("=" * 70)
    print()

    print("Test Configuration:")
    print(f"  Operations: {stats.total_operations}")
    print(f"  Duration: {total_duration:.1f} seconds")
    print()

    print("Operation Results:")
    if stats.store_count > 0:
        print(f"  STORE:  {stats.store_count} operations, {stats.store_passed} passed, {stats.store_count - stats.store_passed} failed")
    if stats.fetch_count > 0:
        print(f"  FETCH:  {stats.fetch_count} operations, {stats.fetch_passed} passed, {stats.fetch_count - stats.fetch_passed} failed")
    if stats.remove_count > 0:
        print(f"  REMOVE: {stats.remove_count} operations, {stats.remove_passed} passed, {stats.remove_count - stats.remove_passed} failed")
    if stats.list_count > 0:
        print(f"  LIST:   {stats.list_count} operations, {stats.list_passed} passed, {stats.list_count - stats.list_passed} failed")
    print()
    print(f"  TOTAL: {stats.total_operations} operations, {stats.passed_operations} passed, {stats.failed_operations} failed")
    print()

    if stats.interrupted:
        print("Result: ✗ TEST INTERRUPTED")
    elif stats.all_passed():
        print("Result: ✓ ALL TESTS PASSED")
    else:
        print("Result: ✗ TESTS FAILED")

        if stats.failures:
            print()
            print("Failed Operations:")
            for i, failure in enumerate(stats.failures[:10], 1):  # Show first 10 failures
                print(f"  {i}. {failure}")
            if len(stats.failures) > 10:
                print(f"  ... and {len(stats.failures) - 10} more failures")

    print()
    print("=" * 70)


# === MAIN SELF-TEST FUNCTION ==================================================

def run_self_test(
    serial: int,
    pin: str | None,
    mgmt_key: str | None,
    num_operations: int = 200,
    debug: bool = False
) -> int:
    """
    Run comprehensive self-test on the specified YubiKey.

    Args:
        serial: YubiKey serial number (required)
        pin: YubiKey PIN (prompted if None)
        mgmt_key: Management key (prompted if None)
        num_operations: Number of test operations to perform (default: 200)
        debug: Enable debug output

    Returns:
        0 on success, 1 on failure
    """
    # 1. Request PIN/key if not provided
    if pin is None:
        pin = request_pin()
    if mgmt_key is None:
        mgmt_key = request_management_key()

    # 2. Confirm with user (flashes YubiKey LED)
    if not confirm_destructive_test(serial, num_operations=num_operations, flash=True, debug=debug):
        print("Self-test cancelled by user")
        return 1

    # 3. Format YubiKey (timed, 16 objects)
    start_time = time.time()
    format_success, format_duration = format_yubikey(serial, pin, mgmt_key, object_count=16, debug=debug)
    if not format_success:
        print("ERROR: Failed to format YubiKey")
        return 1

    # 4. Run test operations (timed, encrypted + unencrypted)
    stats = run_test_operations(serial, pin, mgmt_key, num_operations=num_operations, debug=debug)
    total_time = time.time() - start_time

    # 5. Cleanup (only on success)
    if stats.all_passed():
        cleanup_yubikey(serial, pin, mgmt_key, debug=debug)
    else:
        print("\nNOTE: YubiKey state preserved for debugging")
        print(f"      Run 'yb --serial {serial} ls' to inspect")
        print(f"      Run 'yb --serial {serial} fsck' for details")

    # 6. Report
    print_report(stats, total_time)

    return 0 if stats.all_passed() else 1
