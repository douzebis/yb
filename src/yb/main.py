#!/usr/bin/env python

# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

import os
import sys
from typing import Hashable

import click
import yaml
from click.shell_completion import CompletionItem

from yb.cli_fsck import cli_fsck
from yb.cli_format import cli_format
from yb.cli_fetch import cli_fetch
from yb.cli_list import cli_list
from yb.cli_remove import cli_remove
from yb.cli_self_test import cli_self_test
from yb.cli_store import cli_store
from yb.piv import HardwarePiv

PIV_OBJECT_ID = "0x5f0001"
# PKCS11_LIB = "/nix/store/0makfrhmjm2b7w3abp0j77b62nkxv9d9-yubico-piv-tool-2.6.1/lib/libykcs11.so"
PKCS11_LIB = "libykcs11.so"

# === Helper Functions =========================================================


def complete_serial(ctx, param, incomplete):
    """Shell completion for --serial option.

    Returns a list of serial numbers from connected YubiKeys.
    """
    try:
        piv = HardwarePiv()
        devices = piv.list_devices()

        # Normalize incomplete to empty string if None
        if incomplete is None:
            incomplete = ""

        # Filter devices and create completion items
        completions = []
        for serial, version, _ in devices:
            # Skip devices without serial numbers
            if serial is None:
                continue

            # Convert to string for comparison
            serial_str = str(serial)

            # Match against incomplete input (empty string matches all)
            if incomplete == "" or serial_str.startswith(incomplete):
                completions.append(
                    CompletionItem(
                        serial_str,
                        help=f"YubiKey {version}"
                    )
                )

        return completions

    except Exception as e:
        # If anything goes wrong (no ykman, no devices, etc.), return empty list
        # Debug: log to stderr
        import sys
        print(f"DEBUG: complete_serial error: {e}", file=sys.stderr)
        return []


def validate_management_key(key: str) -> str:
    """Validate and normalize management key.

    Args:
        key: Hex string of management key

    Returns:
        Normalized hex string (lowercase, no spaces)

    Raises:
        click.ClickException: If key is invalid
    """
    # Remove spaces and dashes for user convenience
    key = key.replace(' ', '').replace('-', '').lower()

    # Check if it's valid hex
    try:
        bytes.fromhex(key)
    except ValueError:
        raise click.ClickException(
            'Management key must be a hex string (0-9, a-f)'
        )

    # Check length (24 bytes = 48 hex chars for 3DES)
    if len(key) != 48:
        raise click.ClickException(
            f'Management key must be 48 hex characters (24 bytes), got {len(key)}'
        )

    return key


# === Main CLI =================================================================


@click.group(
    help='''
        Securely store, retrieve, and manage small binary blobs using a YubiKey.

        The yb tool uses the YubiKey's PIV application to store encrypted or
        unencrypted binary data across a set of custom PIV data objects. Each
        blob is stored under a user-defined name, and commands are provided to
        create, list, retrieve, delete, and inspect these blobs.

        If multiple YubiKeys are connected, you must use --serial or --reader
        to select one, otherwise yb will complain, for example:

        \b
          Error: Multiple YubiKeys are connected:
          - Serial 12345678 (YubiKey 5.7.1)
          - Serial 87654321 (YubiKey 5.4.3)

        - Use --serial to select by serial number (printed on the YubiKey case):
          yb --serial 12345678 list

        - Use --reader for legacy PC/SC reader name selection:
          yb --reader "Yubico YubiKey OTP+FIDO+CCID 00 00" list

        - When --reader or --serial is set, yb will flash the selected YubiKey
          and prompt for a PIN to verify identity. This is skipped with -x flag.
          
        yb uses hybrid encryption to protect stored data:
          
          - An ephemeral ECC P-256 key is generated per store operation.
          - ECDH is performed with a persistent key stored on the YubiKey.
          - A shared secret is derived using HKDF-SHA256 to create an AES-256 key.
          - Data is encrypted with AES-CBC and PKCS#7 padding.
          - Encrypted blobs are stored in the YubiKey's PIV application.
    '''
)
@click.option(
    '-s', '--serial',
    type=int,
    required=False,
    shell_complete=complete_serial,
    help='YubiKey serial number (printed on device case)'
)
@click.option(
    '-r', '--reader',
    type=str,
    required=False,
    help='PC/SC reader name (legacy, use --serial instead)'
)
@click.option(
    '-k', '--key',
    type=str,
    default=None,
    help='Management key as 48-char hex string, or "-" to prompt. '
         'Not needed if YubiKey uses PIN-protected management key mode.'
)
@click.option(
    '--pin',
    type=str,
    default=None,
    help='YubiKey PIN (for non-interactive encrypted operations)'
)
@click.option(
    '--debug',
    is_flag=True,
    default=False,
    hidden=True,
    help='Enable debug instrumentation (hidden flag for troubleshooting)'
)
@click.option(
    '--allow-defaults',
    is_flag=True,
    default=False,
    help='Allow operations even with default PIN/PUK/Management Key (INSECURE)'
)
@click.pass_context
def cli(
    ctx,
    serial: int | None,
    reader: Hashable | None,
    key: str | None,
    pin: str | None,
    debug: bool,
    allow_defaults: bool,
) -> None:
    """CLI tool for managing cryptographic operations."""

    # Create PIV interface for hardware operations
    piv = HardwarePiv()

    # Validate options
    if serial is not None and reader is not None:
        raise click.ClickException(
            'Cannot specify both --serial and --reader. Use one or the other.'
        )

    chosen_reader: Hashable

    # Select reader by serial number
    if serial is not None:
        try:
            chosen_reader = piv.get_reader_for_serial(serial)
        except ValueError as e:
            raise click.ClickException(str(e)) from e
        except RuntimeError as e:
            raise click.ClickException(str(e)) from e

    # Select reader by PC/SC name (legacy)
    elif reader is not None:
        chosen_reader = reader

    # Auto-select if only one device, refuse if multiple
    else:
        try:
            devices = piv.list_devices()

            if len(devices) == 0:
                raise click.ClickException('No YubiKeys found.')
            elif len(devices) == 1:
                # Auto-select single device
                serial_num, version, chosen_reader = devices[0]
                print(
                    f'Using YubiKey {serial_num} (version {version})',
                    file=sys.stderr
                )
            else:
                # Multiple devices detected
                # Try interactive selection if stdin is a TTY
                if sys.stdin.isatty() and sys.stdout.isatty():
                    try:
                        from yb.yubikey_selector import select_yubikey_interactively

                        print('Multiple YubiKeys detected. Starting interactive selector...',
                              file=sys.stderr)
                        selected_serial = select_yubikey_interactively(devices)

                        if selected_serial is None:
                            raise click.ClickException('Selection cancelled.')

                        # Get reader for selected serial
                        chosen_reader = piv.get_reader_for_serial(selected_serial)
                        print(
                            f'\nSelected YubiKey {selected_serial}',
                            file=sys.stderr
                        )

                    except ImportError:
                        # prompt_toolkit not available - fall back to error
                        device_list = [
                            f'  - Serial {s} (YubiKey {v})'
                            for s, v, _ in devices
                        ]
                        raise click.ClickException(
                            'Multiple YubiKeys are connected:\n'
                            + '\n'.join(device_list) + '\n\n'
                            'Use --serial to select one, for example:\n'
                            f'  yb --serial {devices[0][0]} <command>\n\n'
                            'Or install prompt_toolkit for interactive selection:\n'
                            '  pip install prompt_toolkit'
                        )
                    except Exception as e:
                        # Interactive selector failed - fall back to error
                        device_list = [
                            f'  - Serial {s} (YubiKey {v})'
                            for s, v, _ in devices
                        ]
                        raise click.ClickException(
                            f'Interactive selector failed: {e}\n\n'
                            'Multiple YubiKeys are connected:\n'
                            + '\n'.join(device_list) + '\n\n'
                            'Use --serial to select one, for example:\n'
                            f'  yb --serial {devices[0][0]} <command>'
                        )
                else:
                    # Not interactive (piped input/output) - require explicit selection
                    device_list = [
                        f'  - Serial {s} (YubiKey {v})'
                        for s, v, _ in devices
                    ]
                    raise click.ClickException(
                        'Multiple YubiKeys are connected:\n'
                        + '\n'.join(device_list) + '\n\n'
                        'Use --serial to select one, for example:\n'
                        f'  yb --serial {devices[0][0]} <command>'
                    )

        except RuntimeError:
            # Fallback to legacy list_readers() if ykman not available
            readers = piv.list_readers()
            if len(readers) == 0:
                raise click.ClickException('No PIV reader is connected.')
            elif len(readers) == 1:
                # Auto-select single reader
                chosen_reader = readers[0]
            else:
                # Multiple readers - require explicit selection
                raise click.ClickException(
                    'Multiple PIV readers are connected:\n'
                    f'{yaml.dump(readers)}'
                    '\n'
                    'Use the --reader option to select one.'
                )

    # Check for default credentials (unless YB_SKIP_DEFAULT_CHECK is set)
    if not os.environ.get('YB_SKIP_DEFAULT_CHECK'):
        from yb.auxiliaries import check_for_default_credentials
        check_for_default_credentials(
            reader=chosen_reader,
            piv=piv,
            allow_defaults=allow_defaults
        )

    # Detect PIN-protected management key mode
    pin_protected = False
    pin_derived = False
    try:
        from yb.auxiliaries import detect_pin_protected_mode
        pin_protected, pin_derived = detect_pin_protected_mode(chosen_reader, piv)

        # Reject PIN-derived mode (deprecated and insecure)
        if pin_derived:
            raise click.ClickException(
                "PIN-derived management key mode detected (insecure, deprecated).\n\n"
                "This mode is no longer supported due to security concerns.\n"
                "Please reconfigure with PIN-protected mode instead:\n"
                "  ykman piv access change-management-key --generate --protect"
            )

    except click.ClickException:
        raise  # Re-raise ClickException as-is
    except Exception:
        # Detection failed, assume not PIN-protected
        pin_protected = False

    # Process management key
    management_key: str | None = None
    if key is not None:
        # User explicitly provided --key, use it (overrides PIN-protected mode)
        if key == '-':
            # Prompt for key (hidden input)
            key_input = click.prompt(
                'Management key (48 hex chars)',
                hide_input=True,
                type=str
            )
            management_key = validate_management_key(key_input)
        else:
            # Validate provided key
            management_key = validate_management_key(key)
    elif pin_protected:
        # YubiKey is PIN-protected, management key will be retrieved lazily
        # when first needed (see write commands)
        pass
    else:
        # Not PIN-protected, no --key provided: use default management key
        management_key = None

    ctx.ensure_object(dict)  # Ensure ctx.obj is a dict
    ctx.obj['reader'] = chosen_reader  # Store chosen reader in context
    ctx.obj['management_key'] = management_key  # Store management key in context
    ctx.obj['pin'] = pin  # Store PIN in context
    ctx.obj['piv'] = piv  # Store PIV interface in context
    ctx.obj['debug'] = debug  # Store --debug flag in context
    ctx.obj['allow_defaults'] = allow_defaults  # Store --allow-defaults flag in context
    ctx.obj['pin_protected_mode'] = pin_protected  # Store PIN-protected mode flag

cli.add_command(cli_fsck)
cli.add_command(cli_fetch)
cli.add_command(cli_format)
cli.add_command(cli_list)
cli.add_command(cli_remove)
cli.add_command(cli_self_test)
cli.add_command(cli_store)


if __name__ == "__main__":
    cli()
