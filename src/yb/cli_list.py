# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

import click
from yb.store import Store
import textwrap

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

    store = Store.from_piv_device(reader)
    store.sanitize()

    blobs = [
        obj
        for obj in store.objects
        if obj.object_age != 0 and obj.chunk_pos_in_blob == 0
    ]
    blobs = sorted(blobs, key=lambda e: e.blob_name or "")
    for blob in blobs:
        print(blob.to_repr())
