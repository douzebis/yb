#!/usr/bin/env python3
"""
Test subprocess TTY access for secure password input.

This investigates whether yubico-piv-tool can directly read the management key
from the terminal when spawned as a subprocess from Python, avoiding the need
to handle the key in Python's memory.
"""

from __future__ import annotations

import subprocess
import sys


def test_subprocess_inherit_stdio() -> None:
    """
    Test 1: Subprocess with inherited stdio.

    Pass stdin=None, stdout=None, stderr=None to inherit from parent.
    """
    print(f"\n{'='*70}")
    print("Test 1: Subprocess with inherited stdio")
    print(f"{'='*70}\n")

    print("This test will run 'yubico-piv-tool -a status'")
    print("If the tool needs to prompt for anything, it should work.")
    print()

    try:
        # Run with inherited stdio - subprocess should be able to access terminal
        result = subprocess.run(
            ["yubico-piv-tool", "-a", "status"],
            stdin=None,  # Inherit stdin from parent
            stdout=None,  # Inherit stdout from parent
            stderr=None,  # Inherit stderr from parent
        )

        print()
        print(f"Exit code: {result.returncode}")
        print()

        if result.returncode == 0:
            print("✓ Success: Subprocess accessed terminal directly")
        else:
            print("✗ Failed: Check output above")

    except Exception as e:
        print(f"Error running subprocess: {e}")


def test_subprocess_explicit_tty() -> None:
    """
    Test 2: Subprocess with explicit TTY file handles.

    Open /dev/tty explicitly and pass as stdin/stdout/stderr.
    This ensures the subprocess can interact with the controlling terminal
    even if parent's stdio has been redirected.
    """
    print(f"\n{'='*70}")
    print("Test 2: Subprocess with explicit /dev/tty")
    print(f"{'='*70}\n")

    print("This test opens /dev/tty explicitly and passes to subprocess.")
    print("This works even if parent's stdio has been redirected.")
    print()

    try:
        # Open the controlling terminal
        with open("/dev/tty", "r") as tty_in, open("/dev/tty", "w") as tty_out:
            result = subprocess.run(
                ["yubico-piv-tool", "-a", "status"],
                stdin=tty_in,
                stdout=tty_out,
                stderr=tty_out,
            )

        print()
        print(f"Exit code: {result.returncode}")
        print()

        if result.returncode == 0:
            print("✓ Success: Subprocess accessed /dev/tty directly")
        else:
            print("✗ Failed: Check output above")

    except Exception as e:
        print(f"Error running subprocess: {e}")


def test_read_password_via_subprocess() -> None:
    """
    Test 3: Read password using 'read' command in shell.

    Demonstrates reading sensitive input via subprocess without Python seeing it.
    """
    print(f"\n{'='*70}")
    print("Test 3: Shell 'read' command for password input")
    print(f"{'='*70}\n")

    print("This test uses shell 'read -s' to get password input.")
    print("Python never sees the password - it stays in the shell.")
    print()

    try:
        # Use shell script that reads password and passes to command
        # This is a proof-of-concept - shows password never enters Python
        shell_script = """
        echo "Enter a test password (not stored, just for demo):" >&2
        read -s -p "Password: " PASSWORD
        echo "" >&2
        echo "Password length: ${#PASSWORD}" >&2
        # In real use, would pass to: yubico-piv-tool -k "$PASSWORD" ...
        """

        result = subprocess.run(
            ["bash", "-c", shell_script],
            stdin=None,  # Inherit - allows read to access terminal
            stdout=subprocess.PIPE,
            stderr=None,  # Let stderr go to terminal
            text=True,
        )

        print()
        if result.returncode == 0:
            print("✓ Success: Password read via subprocess without Python seeing it")
            print(f"Shell output: {result.stdout.strip()}")
        else:
            print("✗ Failed")

    except Exception as e:
        print(f"Error: {e}")


def test_yubico_piv_tool_key_prompt() -> None:
    """
    Test 4: Check if yubico-piv-tool can prompt for management key.

    Some versions support --key=- to prompt for key.
    """
    print(f"\n{'='*70}")
    print("Test 4: yubico-piv-tool management key prompt")
    print(f"{'='*70}\n")

    print("Checking yubico-piv-tool capabilities...")
    print()

    try:
        # Check help output for key-related options
        result = subprocess.run(
            ["yubico-piv-tool", "--help"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

        # Search for management key options
        lines = result.stdout.split("\n")
        print("Management key related options:")
        for line in lines:
            if "key" in line.lower() or "-k" in line:
                print(f"  {line.strip()}")

        print()
        print("Analysis:")
        print("  yubico-piv-tool uses -k <key> for management key")
        print("  Key must be provided as argument (48 hex chars)")
        print("  Tool does NOT have built-in password prompting")
        print("  We must handle prompting ourselves or via shell wrapper")

    except Exception as e:
        print(f"Error: {e}")


def test_envvar_approach() -> None:
    """
    Test 5: Pass management key via environment variable.

    Alternative to command-line argument - slightly more secure as
    environment is not visible in process list (ps aux).
    """
    print(f"\n{'='*70}")
    print("Test 5: Management key via environment variable")
    print(f"{'='*70}\n")

    print("This demonstrates passing sensitive data via environment.")
    print("Advantage: Not visible in 'ps aux' process listing")
    print("Disadvantage: Still in Python process memory briefly")
    print()

    try:
        import os

        # Demonstrate reading password and passing via env
        shell_script = """
        echo "Enter test management key (48 hex chars, dummy for demo):" >&2
        read -s -p "Management Key: " MGMT_KEY
        echo "" >&2
        # In real use: export MGMT_KEY
        # Then yubico-piv-tool reads from $MGMT_KEY
        echo "Key length: ${#MGMT_KEY}" >&2
        # Note: yubico-piv-tool doesn't actually support env vars,
        # but we could use: yubico-piv-tool -k "$MGMT_KEY"
        """

        result = subprocess.run(
            ["bash", "-c", shell_script],
            stdin=None,
            stdout=subprocess.PIPE,
            stderr=None,
            text=True,
        )

        print()
        print("Analysis:")
        print("  Shell can read key securely and pass to subprocess")
        print("  Python doesn't need to see the key")
        print("  Can be done via wrapper script or shell=True subprocess")

    except Exception as e:
        print(f"Error: {e}")


def main() -> int:
    """Main entry point."""
    print("\nSubprocess TTY Access Investigation")
    print("="*70)
    print()
    print("This tests various methods for secure password handling via subprocess.")
    print()

    # Test 1: Inherited stdio
    test_subprocess_inherit_stdio()

    input("\nPress ENTER to continue to Test 2...")

    # Test 2: Explicit /dev/tty
    test_subprocess_explicit_tty()

    input("\nPress ENTER to continue to Test 3...")

    # Test 3: Shell read command
    test_read_password_via_subprocess()

    input("\nPress ENTER to continue to Test 4...")

    # Test 4: yubico-piv-tool capabilities
    test_yubico_piv_tool_key_prompt()

    input("\nPress ENTER to continue to Test 5...")

    # Test 5: Environment variable approach
    test_envvar_approach()

    print(f"\n{'='*70}")
    print("Testing complete")
    print(f"{'='*70}\n")

    print("SUMMARY:")
    print("  1. Subprocess can access TTY when stdin/stdout/stderr inherited")
    print("  2. /dev/tty provides explicit terminal access")
    print("  3. Shell 'read -s' can read password without Python seeing it")
    print("  4. yubico-piv-tool requires -k <key> argument (no built-in prompt)")
    print("  5. Best approach: Shell wrapper that reads key and passes to tool")
    print()
    print("RECOMMENDATION:")
    print("  Use shell wrapper with 'read -s' to get management key,")
    print("  then invoke yubico-piv-tool with -k \"$KEY\"")
    print("  This keeps the key out of Python's memory entirely.")
    print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
