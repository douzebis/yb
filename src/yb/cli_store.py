# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

import sys
import click
from typing import BinaryIO

from yb import orchestrator


# === STORE ====================================================================


@click.command(
    'store',
    help='''
        Store data as a named blob in the YubiKey. By default, the data can be
        stored either encrypted or unencrypted depending on the flags below.
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
         ' If omitted, data is read from standard input.',
)
@click.argument(
    'name',
    type=str,
)
@click.pass_context
def cli_store(
        ctx,
        encrypted: bool,
        input: BinaryIO | None,
        name: str,
    ) -> None:
    ''''''

    reader: str = ctx.obj['reader']
    management_key: str | None = ctx.obj.get('management_key')
    piv = ctx.obj['piv']

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
        )

        if not success:
            raise click.ClickException("Store is full - cannot store blob")

    except ValueError as e:
        raise click.ClickException(str(e)) from e
    except RuntimeError as e:
        raise click.ClickException(str(e)) from e
