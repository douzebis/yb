# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

import sys
import os
import click
from typing import BinaryIO

from yb import orchestrator


# === STORE ====================================================================


@click.command(
    'store',
    help='''
        Store data as a named blob in the YubiKey. By default, the data can be
        stored either encrypted or unencrypted depending on the flags below.

        If NAME is not provided, the basename of the input file (-i) is used as
        the blob name.
    ''',
)
@click.option(
    '-e/-u', '--encrypted/--unencrypted',
    is_flag=True,
    default=True,
    help='Whether to encrypt the blob before storing it.',
)
@click.option(
    '-i', '--input',
    type=click.File('rb'),
    required=False,
    help='Read the data to store from the specified file.'
         ' If omitted, data is read from standard input.'
         ' If NAME is not provided, the basename of this file is used.',
)
@click.argument(
    'name',
    type=str,
    required=False,
)
@click.pass_context
def cli_store(
        ctx,
        encrypted: bool,
        input: BinaryIO | None,
        name: str | None,
    ) -> None:
    ''''''

    from yb.auxiliaries import get_management_key_for_write

    reader: str = ctx.obj['reader']
    management_key: str | None = get_management_key_for_write(ctx)
    pin: str | None = ctx.obj.get('pin')
    piv = ctx.obj['piv']

    # Determine blob name
    if name is None:
        if input is None:
            raise click.ClickException(
                "NAME argument required when reading from stdin. "
                "Or use -i FILE to use the file's basename as the blob name."
            )
        # Extract basename from input file
        name = os.path.basename(input.name)
        if not name:
            raise click.ClickException(
                "Cannot determine blob name from input file. Please provide NAME argument."
            )

    # Read payload
    payload: bytes
    if input is None:
        payload = sys.stdin.buffer.read()
    else:
        payload = input.read()
    assert isinstance(payload, bytes)

    # Call orchestrator
    try:
        success = orchestrator.store_blob(
            reader=reader,
            piv=piv,
            name=name,
            payload=payload,
            encrypted=encrypted,
            management_key=management_key,
            pin=pin,
        )

        if not success:
            raise click.ClickException("Store is full - cannot store blob")

    except ValueError as e:
        raise click.ClickException(str(e)) from e
    except RuntimeError as e:
        raise click.ClickException(str(e)) from e
