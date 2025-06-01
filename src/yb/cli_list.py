# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

import click
from yb.store import Store

# === LS =======================================================================

@click.command(
    'ls',
    help='''
    ''',
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
