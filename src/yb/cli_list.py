# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

import click
from datetime import datetime

from yb import orchestrator

# === LS =======================================================================

@click.command(
    'ls',
    help='''List all blobs stored in the YubiKey.

        \b
        Each entry shows the following fields:

          - Encryption status: '-' for encrypted, 'U' for unencrypted
          - Number of PIV objects used to store the blob
          - Blob size in bytes
          - Creation timestamp (YYYY-MM-DD HH:MM)
          - Blob name

        Example output:
          -  1        7  2025-06-01 13:22  sensitive-data
          U  1       10  2025-06-01 13:36  public-data''',
)
@click.pass_context
def cli_list(ctx,
    ) -> None:
    ''''''

    reader: str = ctx.obj['reader']
    piv = ctx.obj['piv']

    # Call orchestrator
    blobs = orchestrator.list_blobs(reader=reader, piv=piv)

    # Format and print each blob
    for name, size, is_encrypted, mtime, chunk_count in blobs:
        bits = '-' if is_encrypted else 'U'
        count = str(chunk_count).rjust(2)
        size_str = str(size).rjust(8)
        dt = datetime.fromtimestamp(mtime)
        date = dt.strftime("%Y-%m-%d %H:%M").ljust(16)
        print(f"{bits} {count} {size_str} {date} {name}")
