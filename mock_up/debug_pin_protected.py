#!/usr/bin/env python3
"""Debug script to check PIN-protected management key retrieval"""

import sys
sys.path.insert(0, 'src')

from ykman.device import list_all_devices
from yubikit.core.smartcard import SmartCardConnection
from yubikit.piv import PivSession

# Get PIN from user
pin = input("Enter PIN: ")

# Find device
devices = list_all_devices()
if not devices:
    print("No YubiKeys found")
    sys.exit(1)

device, info = devices[0]
print(f"Using YubiKey {info.serial} (version {info.version})")

# Open connection and retrieve management key
with device.open_connection(SmartCardConnection) as conn:
    piv = PivSession(conn)
    
    # Verify PIN
    try:
        piv.verify_pin(pin)
        print("✓ PIN verified successfully")
    except Exception as e:
        print(f"✗ PIN verification failed: {e}")
        sys.exit(1)
    
    # Read PRINTED object
    try:
        printed_data = piv.get_object(0x5FC109)
        print(f"✓ PRINTED object read ({len(printed_data)} bytes)")
        print(f"  Raw hex: {printed_data.hex()}")
    except Exception as e:
        print(f"✗ Failed to read PRINTED object: {e}")
        sys.exit(1)
    
    # Parse TLV
    if printed_data[0] != 0x88:
        print(f"✗ Invalid outer tag: expected 0x88, got 0x{printed_data[0]:02x}")
        sys.exit(1)
    
    print(f"✓ Outer tag: 0x{printed_data[0]:02x}")
    
    outer_len = printed_data[1]
    print(f"✓ Outer length: {outer_len}")
    
    inner_data = printed_data[2:2 + outer_len]
    print(f"  Inner data: {inner_data.hex()}")
    
    if inner_data[0] != 0x89:
        print(f"✗ Invalid inner tag: expected 0x89, got 0x{inner_data[0]:02x}")
        sys.exit(1)
    
    print(f"✓ Inner tag: 0x{inner_data[0]:02x} (AES key)")
    
    key_len = inner_data[1]
    print(f"✓ Key length: {key_len}")
    
    key_bytes = inner_data[2:2 + key_len]
    print(f"✓ Key extracted ({len(key_bytes)} bytes)")
    print(f"  Key hex: {key_bytes.hex()}")
    
    management_key_hex = key_bytes.hex()
    print(f"\n✓ Management key: {management_key_hex}")
    print(f"  Length: {len(management_key_hex)} characters")

print("\nNow testing with yubico-piv-tool...")
import subprocess

# Get reader name
reader = device.fingerprint
print(f"Reader: {reader}")

# Try a simple command with the key
cmd = [
    'yubico-piv-tool',
    '--reader', str(reader),
    f'--key={management_key_hex}',
    '--action', 'status',
]

print(f"\nCommand: {' '.join(cmd)}")

try:
    result = subprocess.run(
        cmd,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    print("✓ yubico-piv-tool authentication successful!")
    print(result.stdout.decode())
except subprocess.CalledProcessError as e:
    print(f"✗ yubico-piv-tool failed:")
    print(f"  stdout: {e.stdout.decode()}")
    print(f"  stderr: {e.stderr.decode()}")
