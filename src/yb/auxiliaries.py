# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

from __future__ import annotations
import sys
from datetime import datetime
from typing import Hashable, TYPE_CHECKING
import click

if TYPE_CHECKING:
    from yb.piv import PivInterface

def format_timestamp(ts: int) -> str:
    dt = datetime.fromtimestamp(ts)  # convert to local datetime
    return dt.strftime('%c')  # locale-appropriate datetime string


def verify_device_if_needed(ctx):
    """
    Verify device PIN for write operations (unless -x flag was specified).

    This should be called by write commands (format, store, remove) at the
    beginning of their execution to confirm user identity before making changes.

    Read-only commands (ls, fetch, fsck) should NOT call this.

    Args:
        ctx: Click context containing 'piv', 'reader', 'pin', and 'no_verify' in ctx.obj

    Raises:
        click.ClickException: If PIN verification fails
    """
    if ctx.obj.get('no_verify', False):
        return  # -x flag was specified, skip verification

    reader = ctx.obj['reader']
    piv = ctx.obj['piv']
    pin = ctx.obj.get('pin')

    if pin is None:
        print('Confirm by entering your PIN...', file=sys.stderr)

    if not piv.verify_reader(reader, 0x9a, pin=pin):
        raise click.ClickException('Could not verify the PIN.')


class StringTooLargeError(ValueError):
    pass


def parse_tlv(data: bytes) -> dict[int, bytes]:
    """
    Parse DER-encoded TLV data into dictionary.

    Args:
        data: Raw TLV bytes from APDU response

    Returns:
        Dictionary mapping tag (int) to value (bytes)

    Raises:
        ValueError: If TLV data is malformed
    """
    result = {}
    offset = 0

    while offset < len(data):
        if offset >= len(data):
            break

        # Parse tag
        tag = data[offset]
        offset += 1

        if offset >= len(data):
            raise ValueError(f"Truncated TLV data: tag {tag:#04x} has no length byte")

        # Parse length (supports single-byte and multi-byte lengths)
        length = data[offset]
        offset += 1

        if length & 0x80:  # Multi-byte length
            num_bytes = length & 0x7F
            if num_bytes == 0:
                raise ValueError(f"Invalid length encoding at offset {offset-1}")
            if offset + num_bytes > len(data):
                raise ValueError( "Truncated TLV data: length field extends beyond data")
            length = int.from_bytes(data[offset:offset+num_bytes], 'big')
            offset += num_bytes

        # Extract value
        if offset + length > len(data):
            raise ValueError(
                f"Truncated TLV data: tag {tag:#04x} expects {length} bytes "
                f"but only {len(data) - offset} available"
            )
        value = data[offset:offset+length]
        offset += length

        result[tag] = value

    return result


# Constants for GET_METADATA command
INS_GET_METADATA = 0xF7
SLOT_PIN = 0x80
SLOT_PUK = 0x81
SLOT_CARD_MANAGEMENT = 0x9B
TAG_METADATA_IS_DEFAULT = 0x05


def get_pin_metadata(reader: Hashable, piv: PivInterface) -> tuple[bool, int, int]:
    """
    Get PIN metadata including default status and retry counts.

    Uses GET_METADATA command (firmware 5.3+) which does NOT consume retry attempts.

    Args:
        reader: PC/SC reader name
        piv: PIV interface

    Returns:
        Tuple of (is_default, total_retries, remaining_retries)

    Raises:
        RuntimeError: If firmware <5.3 or command fails
    """
    try:
        response = piv.send_apdu(reader, 0x00, INS_GET_METADATA, 0x00, SLOT_PIN)
        tlv_data = parse_tlv(response)

        is_default = (tlv_data.get(TAG_METADATA_IS_DEFAULT, b'\x00') == b'\x01')

        # Tag 0x06 contains retry counts
        retry_data = tlv_data.get(0x06, b'\x00\x00')
        total_retries = retry_data[0] if len(retry_data) > 0 else 0
        remaining_retries = retry_data[1] if len(retry_data) > 1 else 0

        return (is_default, total_retries, remaining_retries)
    except Exception as e:
        raise RuntimeError(f"Failed to get PIN metadata (firmware <5.3?): {e}") from e


def get_puk_metadata(reader: Hashable, piv: PivInterface) -> tuple[bool, int, int]:
    """
    Get PUK metadata including default status and retry counts.

    Uses GET_METADATA command (firmware 5.3+) which does NOT consume retry attempts.

    Args:
        reader: PC/SC reader name
        piv: PIV interface

    Returns:
        Tuple of (is_default, total_retries, remaining_retries)

    Raises:
        RuntimeError: If firmware <5.3 or command fails
    """
    try:
        response = piv.send_apdu(reader, 0x00, INS_GET_METADATA, 0x00, SLOT_PUK)
        tlv_data = parse_tlv(response)

        is_default = (tlv_data.get(TAG_METADATA_IS_DEFAULT, b'\x00') == b'\x01')
        retry_data = tlv_data.get(0x06, b'\x00\x00')
        total_retries = retry_data[0] if len(retry_data) > 0 else 0
        remaining_retries = retry_data[1] if len(retry_data) > 1 else 0

        return (is_default, total_retries, remaining_retries)
    except Exception as e:
        raise RuntimeError(f"Failed to get PUK metadata (firmware <5.3?): {e}") from e


def get_management_key_metadata(reader: Hashable, piv: PivInterface) -> bool:
    """
    Get management key default status.

    Uses GET_METADATA command (firmware 5.3+) which does NOT consume retry attempts.

    Args:
        reader: PC/SC reader name
        piv: PIV interface

    Returns:
        True if using default management key, False otherwise

    Raises:
        RuntimeError: If firmware <5.3 or command fails
    """
    try:
        response = piv.send_apdu(reader, 0x00, INS_GET_METADATA, 0x00, SLOT_CARD_MANAGEMENT)
        tlv_data = parse_tlv(response)

        is_default = (tlv_data.get(TAG_METADATA_IS_DEFAULT, b'\x00') == b'\x01')
        return is_default
    except Exception as e:
        raise RuntimeError(f"Failed to get management key metadata (firmware <5.3?): {e}") from e


def check_for_default_credentials(
    reader: Hashable,
    piv: PivInterface,
    allow_defaults: bool = False
) -> None:
    """
    Check if YubiKey uses default PIN, PUK, or Management Key.

    Uses GET_METADATA command (firmware 5.3+) which does NOT consume retry attempts.
    This check is performed early in the CLI to prevent users from accidentally
    using insecure default credentials.

    Args:
        reader: PC/SC reader name
        piv: PIV interface
        allow_defaults: Allow operation even with default credentials (default: False)

    Raises:
        click.ClickException: If defaults detected and not allowed

    Note:
        On firmware <5.3, displays warning but continues (cannot detect safely).
    """
    defaults_found = []

    # Try to detect defaults (safe on firmware 5.3+)
    try:
        # Check PIN
        pin_is_default, _, pin_remaining = get_pin_metadata(reader, piv)
        if pin_is_default:
            defaults_found.append(f"PIN (default: 123456, {pin_remaining} attempts remaining)")

        # Check PUK
        puk_is_default, _, puk_remaining = get_puk_metadata(reader, piv)
        if puk_is_default:
            defaults_found.append(f"PUK (default: 12345678, {puk_remaining} attempts remaining)")

        # Check Management Key
        mgmt_key_is_default = get_management_key_metadata(reader, piv)
        if mgmt_key_is_default:
            defaults_found.append("Management Key (default: 010203...)")

    except RuntimeError as e:
        # Firmware <5.3 or other error
        print(
            f"WARNING: Cannot verify default credentials (firmware <5.3?): {e}",
            file=sys.stderr
        )
        print(
            "Continuing anyway. For security, ensure your YubiKey uses non-default credentials.",
            file=sys.stderr
        )
        return

    # If defaults found and not allowed, error out
    if defaults_found and not allow_defaults:
        defaults_list = '\n  - '.join([''] + defaults_found)
        raise click.ClickException(
            f"YubiKey is using default credentials (INSECURE):{defaults_list}\n\n"
            "This is a security risk. Please change your YubiKey credentials:\n"
            "  - Change PIN: ykman piv access change-pin\n"
            "  - Change PUK: ykman piv access change-puk\n"
            "  - Change Management Key (recommended with PIN-protected mode):\n"
            "    ykman piv access change-management-key --generate --protect\n\n"
            "To proceed anyway (NOT RECOMMENDED), use --allow-defaults flag."
        )

    # If defaults found but allowed, warn
    if defaults_found and allow_defaults:
        defaults_list = '\n  - '.join([''] + defaults_found)
        print(
            f"WARNING: YubiKey is using default credentials:{defaults_list}",
            file=sys.stderr
        )
        print("Continuing with --allow-defaults flag (INSECURE)", file=sys.stderr)


# Constants for PIV objects
OBJECT_ADMIN_DATA = 0x5FFF00
OBJECT_PRINTED = 0x5FC109


def parse_admin_data(data: bytes) -> dict:
    """
    Parse PIV ADMIN DATA object (0x5FFF00).

    The ADMIN DATA object contains metadata about the PIV applet configuration,
    including whether the management key is stored in PIN-protected mode.

    The object can have two formats:
    - Direct TLV tags: 80 L1 [...] 81 01 <bitfield> 82 L2 <salt> 83 L3 <timestamp>
    - With wrapper: 53 len [Direct TLV tags]

    Args:
        data: Raw ADMIN DATA object bytes

    Returns:
        Dictionary with parsed fields:
        - 'puk_blocked': bool - Whether PUK is blocked
        - 'mgmt_key_stored': bool - Whether mgmt key is stored in PRINTED object
        - 'pin_derived': bool - Whether PIN-derived mode is active (deprecated/insecure)
        - 'salt': bytes or None - Salt for PIN-derived mode (if present)
        - 'timestamp': int or None - PIN last updated timestamp (if present)

    Raises:
        ValueError: If ADMIN DATA is malformed
    """
    result = {
        'puk_blocked': False,
        'mgmt_key_stored': False,
        'pin_derived': False,
        'salt': None,
        'timestamp': None,
    }

    if not data:
        return result

    # Check if there's a 0x53 wrapper
    if data[0] == 0x53:
        # Parse the wrapper TLV to get inner data
        wrapper_tlv = parse_tlv(data)
        inner_data = wrapper_tlv.get(0x53, b'')
    else:
        # No wrapper, data is already the inner TLV structure
        inner_data = data

    if not inner_data:
        return result

    # Parse TLV structure
    tlv_data = parse_tlv(inner_data)

    # Tag 0x80: Contains nested TLV with management key configuration
    if 0x80 in tlv_data:
        # Tag 0x80 contains the nested structure
        nested_data = tlv_data[0x80]
        if nested_data:
            nested_tlv = parse_tlv(nested_data)

            # Tag 0x81: Bit field for management key storage
            if 0x81 in nested_tlv:
                bitfield = nested_tlv[0x81]
                if len(bitfield) >= 1:
                    # Bit 0x01: Management key stored in PRINTED (3DES key)
                    # Bit 0x02: Management key stored in PRINTED (AES key)
                    # Bit 0x04: Management key is PIN-derived (deprecated/insecure)
                    # For PIN-protected mode: check for 0x01 OR 0x02
                    result['mgmt_key_stored'] = bool(bitfield[0] & 0x03)  # 0x01 or 0x02
                    result['pin_derived'] = bool(bitfield[0] & 0x04)  # Deprecated mode

            # Tag 0x82: Salt for PIN-derived mode (deprecated, insecure)
            if 0x82 in nested_tlv:
                result['salt'] = nested_tlv[0x82]
                result['pin_derived'] = True  # Presence of salt confirms PIN-derived mode

            # Tag 0x83: Timestamp (optional)
            if 0x83 in nested_tlv:
                timestamp_bytes = nested_tlv[0x83]
                if len(timestamp_bytes) >= 4:
                    result['timestamp'] = int.from_bytes(timestamp_bytes[:4], 'big')
    else:
        # Fallback: try parsing tags directly (older format)
        # Tag 0x81: Bit field
        if 0x81 in tlv_data:
            bitfield = tlv_data[0x81]
            if len(bitfield) >= 1:
                result['mgmt_key_stored'] = bool(bitfield[0] & 0x03)  # 0x01 or 0x02
                result['pin_derived'] = bool(bitfield[0] & 0x04)  # Deprecated mode

        # Tag 0x82: Salt for PIN-derived mode (deprecated, insecure)
        if 0x82 in tlv_data:
            result['salt'] = tlv_data[0x82]
            result['pin_derived'] = True

        # Tag 0x83: Timestamp (optional)
        if 0x83 in tlv_data:
            timestamp_bytes = tlv_data[0x83]
            if len(timestamp_bytes) >= 4:
                result['timestamp'] = int.from_bytes(timestamp_bytes[:4], 'big')

    return result


def detect_pin_protected_mode(reader: Hashable, piv: PivInterface) -> tuple[bool, bool]:
    """
    Detect if YubiKey has PIN-protected management key enabled.

    This function checks the ADMIN DATA object to determine if the YubiKey
    is configured to store the management key in the PRINTED object,
    protected by the PIN.

    Args:
        reader: PC/SC reader name
        piv: PIV interface

    Returns:
        Tuple of (is_pin_protected, is_pin_derived):
        - is_pin_protected: True if PIN-protected mode is active
        - is_pin_derived: True if deprecated PIN-derived mode is active

    Note:
        Returns (False, False) if ADMIN DATA cannot be read or is missing.
        PIN-derived mode is deprecated and insecure - it should be rejected.
    """
    try:
        # Read ADMIN DATA object
        admin_data = piv.read_object(reader, OBJECT_ADMIN_DATA)

        # Parse the ADMIN DATA
        parsed = parse_admin_data(admin_data)

        return (parsed['mgmt_key_stored'], parsed['pin_derived'])

    except RuntimeError:
        # ADMIN DATA not readable or doesn't exist
        # This is normal for YubiKeys not using PIN-protected mode
        return (False, False)
    except ValueError as e:
        # Malformed ADMIN DATA - log warning but don't fail
        print(
            f"WARNING: Could not parse ADMIN DATA: {e}",
            file=sys.stderr
        )
        return (False, False)


def get_pin_protected_management_key(
    reader: Hashable,
    piv: PivInterface,
    pin: str | None = None
) -> str:
    """
    Retrieve the management key from PIN-protected storage.

    When a YubiKey is configured with PIN-protected management key mode using
    `ykman piv access change-management-key --generate --protect`, the management
    key is stored in the PRINTED object (0x5FC109), encrypted and accessible only
    after PIN verification.

    This function reads the PRINTED object and extracts the management key.

    Args:
        reader: PC/SC reader name
        piv: PIV interface
        pin: YubiKey PIN (will prompt if None)

    Returns:
        Management key as 48-character hex string (AES192)

    Raises:
        RuntimeError: If PIN verification fails or key retrieval fails
        ImportError: If ykman library is not available
    """
    try:
        from ykman.device import list_all_devices
        from yubikit.core.smartcard import SmartCardConnection
        from yubikit.piv import PivSession
    except ImportError as e:
        raise ImportError(
            "ykman library required for PIN-protected management key mode.\n"
            "Install with: pip install yubikey-manager"
        ) from e

    # Prompt for PIN if not provided
    if pin is None:
        import getpass
        print('PIN required for PIN-protected management key mode...', file=sys.stderr)
        pin = getpass.getpass('Enter PIN: ')

    # Find device and open connection
    devices = list_all_devices()
    target_device = None
    for device, info in devices:
        # Match by reader name
        if str(reader) in str(device.fingerprint):
            target_device = device
            break

    if not target_device:
        # If exact match fails, use first device (single YubiKey scenario)
        if devices:
            target_device, _ = devices[0]

    if not target_device:
        raise RuntimeError(f"YubiKey not found for reader: {reader}")

    # Open connection and retrieve management key
    try:
        with target_device.open_connection(SmartCardConnection) as conn:
            piv_session = PivSession(conn)

            # Verify PIN
            piv_session.verify_pin(pin)

            # Read PRINTED object to get management key
            printed_data = piv_session.get_object(0x5FC109)

            # Parse TLV: 88 <len> [ 89 <len> <key-bytes> ]
            if printed_data[0] != 0x88:
                raise RuntimeError(
                    f"PRINTED object has invalid format: "
                    f"expected tag 0x88, got 0x{printed_data[0]:02x}"
                )

            outer_len = printed_data[1]
            inner_data = printed_data[2:2 + outer_len]

            if inner_data[0] != 0x89:  # AES key tag
                raise RuntimeError(
                    f"Management key not found in PRINTED object: "
                    f"expected tag 0x89, got 0x{inner_data[0]:02x}"
                )

            key_len = inner_data[1]
            key_bytes = inner_data[2:2 + key_len]

            # Convert to hex string
            management_key_hex = key_bytes.hex()

            if len(management_key_hex) != 48:
                raise RuntimeError(
                    f"Invalid management key length: {len(management_key_hex)} "
                    f"(expected 48 for AES192)"
                )

            return management_key_hex

    except Exception as e:
        raise RuntimeError(
            f"Failed to retrieve PIN-protected management key: {e}"
        ) from e


def get_management_key_for_write(ctx) -> str | None:
    """
    Get the management key for write operations, handling PIN-protected mode.

    This helper function should be called by write commands (store, rm, format)
    to retrieve the management key. It handles three cases:

    1. User provided explicit --key: use that key
    2. YubiKey is in PIN-protected mode: retrieve key from PRINTED object
    3. Neither: return None (use default management key)

    Args:
        ctx: Click context containing reader, piv, management_key, pin, and pin_protected_mode

    Returns:
        Management key as hex string, or None to use default

    Raises:
        click.ClickException: If PIN-protected mode retrieval fails
    """
    management_key = ctx.obj.get('management_key')

    # Case 1: User provided explicit --key
    if management_key is not None:
        return management_key

    # Case 2: PIN-protected mode
    if ctx.obj.get('pin_protected_mode', False):
        reader = ctx.obj['reader']
        piv = ctx.obj['piv']
        pin = ctx.obj.get('pin')

        try:
            management_key = get_pin_protected_management_key(
                reader=reader,
                piv=piv,
                pin=pin
            )
            return management_key
        except RuntimeError as e:
            raise click.ClickException(
                f"Failed to retrieve PIN-protected management key: {e}"
            ) from e

    # Case 3: No explicit key, not PIN-protected - use default
    return None
