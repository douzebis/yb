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
from yb.piv import Piv

PIV_OBJECT_ID = "0x5f0001"
# PKCS11_LIB = "/nix/store/0makfrhmjm2b7w3abp0j77b62nkxv9d9-yubico-piv-tool-2.6.1/lib/libykcs11.so"
PKCS11_LIB = "libykcs11.so"

# === Main CLI =================================================================


@click.group(
    help='''
        Securely store, retrieve, and manage small binary blobs using a YubiKey.

        The yb tool uses the YubiKey's PIV application to store encrypted or
        unencrypted binary data across a set of custom PIV data objects. Each
        blob is stored under a user-defined name, and commands are provided to
        create, list, retrieve, delete, and inspect these blobs.

        If multiple PIV readers are connected, you must use --reader to select
        one, otherwise yb will complain, for example:

        \b
          Error: Multiple PIV readers are connected:
          - Yubico YubiKey OTP+FIDO+CCID 00 00
          - Yubico YubiKey OTP+FIDO+CCID 01 00
          
        - When --reader is set, yb will flash the selected YubiKey and prompt for a PIN
          to verify reader identity. This verification is skipped with the -x flag.
          
        yb uses hybrid encryption to protect stored data:
          
          - An ephemeral ECC P-256 key is generated per store operation.
          - ECDH is performed with a persistent key stored on the YubiKey.
          - A shared secret is derived using HKDF-SHA256 to create an AES-256 key.
          - Data is encrypted with AES-CBC and PKCS#7 padding.
          - Encrypted blobs are stored in the YubiKey's PIV application.
    '''
)
@click.option(
    '-r', '--reader',
    type=str,
    required=False,
    help=''
)
@click.option(
    '-x', '--no-verify',
    is_flag=True,
    help=''
)
@click.pass_context
def cli(
    ctx,
    reader: str | None,
    no_verify: bool,
) -> None:
    """CLI tool for managing cryptographic operations."""

    chosen_reader: str
    if reader:
        chosen_reader = reader
    
    else:
        readers = Piv.list_readers()
        if len(readers) == 0:
            raise click.ClickException('No PIV reader is not connected.')
        elif len(readers) == 1:
            chosen_reader = readers[0]
        else:
            raise click.ClickException(
                'Multiple PIV readers are connected:\n'
                f'{yaml.dump(readers)}'
                '\n'
                'Use the --reader option to pick one.'
            )
    if reader is not None and not no_verify:
        print('Confirm by entering your PIN...', file=sys.stderr)
        if not Piv.verify_reader(chosen_reader, 0x9a):
            raise click.ClickException('Could not verify the PIN.')

    ctx.ensure_object(dict)  # Ensure ctx.obj is a dict
    ctx.obj['reader'] = chosen_reader  # Store chosen reader in context

cli.add_command(cli_fsck)
cli.add_command(cli_fetch)
cli.add_command(cli_format)
#cli.add_command(cli_list_readers)
cli.add_command(cli_list)
cli.add_command(cli_remove)
cli.add_command(cli_store)


if __name__ == "__main__":
    cli()
