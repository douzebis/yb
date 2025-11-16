# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

import sys
import click
import getpass
from typing import BinaryIO

from yb import orchestrator


# === FETCH ====================================================================


@click.command(
    'fetch',
    help='''
        Retrieve a named blob from the YubiKey.

        By default, the blob is written to standard output unless an output file
        is specified.
    ''',
)
@click.option(
    '-o', '--output',
    type=click.File('wb'),
    required=False,
    help='Write the retrieved blob to the specified file.'
         ' If omitted, output is written to standard output.',
)
@click.argument(
    'name',
    type=str,
)
@click.pass_context
def cli_fetch(ctx,
        output: BinaryIO | None,
        name: str,
    ) -> None:
    ''''''

    reader: str = ctx.obj['reader']
    piv = ctx.obj['piv']

    # Prompt for PIN if needed (check if blob is encrypted first)
    pin: str | None = None
    # For now, always prompt - orchestrator will use it only if needed
    # TODO: Could optimize by checking blob encryption status first
    try:
        pin = getpass.getpass("Please enter User PIN (press Enter if not encrypted): ")
        if pin == "":
            pin = None

    except (EOFError, getpass.GetPassWarning):
        pin = None

    # Call orchestrator
    try:
        payload = orchestrator.fetch_blob(
            reader=reader,
            piv=piv,
            name=name,
            pin=pin,
        )

        if payload is None:
            raise click.ClickException(f'Cannot find object {name}')

    except ValueError as e:
        raise click.ClickException(str(e)) from e
    except RuntimeError as e:
        raise click.ClickException(str(e)) from e

    # Write output
    if output is None:
        sys.stdout.buffer.write(payload)
    else:
        output.write(payload)
