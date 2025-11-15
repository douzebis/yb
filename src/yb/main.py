#!/usr/bin/env python

# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

import sys

import click
import yaml

from yb.cli_fsck import cli_fsck
from yb.cli_format import cli_format
from yb.cli_fetch import cli_fetch
from yb.cli_list_readers import cli_list_readers
from yb.cli_list import cli_list
from yb.cli_remove import cli_remove
from yb.cli_store import cli_store
from yb.piv import HardwarePiv

PIV_OBJECT_ID = "0x5f0001"
# PKCS11_LIB = "/nix/store/0makfrhmjm2b7w3abp0j77b62nkxv9d9-yubico-piv-tool-2.6.1/lib/libykcs11.so"
PKCS11_LIB = "libykcs11.so"

# === Helper Functions =========================================================


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
    help='YubiKey serial number (printed on device case)'
)
@click.option(
    '-r', '--reader',
    type=str,
    required=False,
    help='PC/SC reader name (legacy, use --serial instead)'
)
@click.option(
    '-x', '--no-verify',
    is_flag=True,
    help='Skip reader verification (no PIN prompt)'
)
@click.option(
    '-k', '--key',
    type=str,
    default=None,
    help='Management key as 48-char hex string, or "-" to prompt (default: YubiKey default key)'
)
@click.pass_context
def cli(
    ctx,
    serial: int | None,
    reader: str | None,
    no_verify: bool,
    key: str | None,
) -> None:
    """CLI tool for managing cryptographic operations."""

    # Create PIV interface for hardware operations
    piv = HardwarePiv()

    # Validate options
    if serial is not None and reader is not None:
        raise click.ClickException(
            'Cannot specify both --serial and --reader. Use one or the other.'
        )

    chosen_reader: str

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

    # Auto-select if only one device
    else:
        try:
            devices = piv.list_devices()

            if len(devices) == 0:
                raise click.ClickException('No YubiKeys found.')
            elif len(devices) == 1:
                serial_num, version, chosen_reader = devices[0]
                # Inform user which device was auto-selected
                print(
                    f'Auto-selected YubiKey {serial_num} (version {version})',
                    file=sys.stderr
                )
            else:
                # Multiple devices - show helpful error
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
                chosen_reader = readers[0]
            else:
                raise click.ClickException(
                    'Multiple PIV readers are connected:\n'
                    f'{yaml.dump(readers)}'
                    '\n'
                    'Use the --reader option to pick one.'
                )

    # Verify reader identity (unless --no-verify)
    if (serial is not None or reader is not None) and not no_verify:
        print('Confirm by entering your PIN...', file=sys.stderr)
        if not piv.verify_reader(chosen_reader, 0x9a):
            raise click.ClickException('Could not verify the PIN.')

    # Process management key
    management_key: str | None = None
    if key is not None:
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

    ctx.ensure_object(dict)  # Ensure ctx.obj is a dict
    ctx.obj['reader'] = chosen_reader  # Store chosen reader in context
    ctx.obj['management_key'] = management_key  # Store management key in context
    ctx.obj['piv'] = piv  # Store PIV interface in context

cli.add_command(cli_fsck)
cli.add_command(cli_fetch)
cli.add_command(cli_format)
#cli.add_command(cli_list_readers)
cli.add_command(cli_list)
cli.add_command(cli_remove)
cli.add_command(cli_store)


if __name__ == "__main__":
    cli()
