#!/usr/bin/env python

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
    help="""
CLI tool for securely storing and retrieving small binary blobs using a YubiKey.

\b
This tool uses hybrid encryption:
  - An ephemeral EC key is generated to perform ECDH with a persistent key stored on the YubiKey.
  - The resulting shared secret is used to derive an AES-256 key (HKDF-SHA256).
  - Data is encrypted/decrypted using AES-CBC with PKCS7 padding.
  - Encrypted data is stored into the YubiKey as a custom object
"""
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
cli.add_command(cli_list_readers)
cli.add_command(cli_list)
cli.add_command(cli_remove)
cli.add_command(cli_store)


if __name__ == "__main__":
    cli()
