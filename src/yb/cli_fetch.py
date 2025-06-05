# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

import sys
import click
from yb.store import Store, Object
from typing import BinaryIO
from yb.crypto import Crypto
import getpass


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

    if len(name) == 0 or len(name) > 255:
        raise click.ClickException('Bad name')

    reader: str = ctx.obj['reader']

    # Load the store from the PIV device
    store = Store.from_piv_device(reader)
    store.sanitize()

    # Find the target blob
    try:
        blob: Object = next(
            obj
            for obj in store.objects
            if (obj.object_age != 0
                and obj.chunk_pos_in_blob == 0
                and obj.blob_name == name)
        )
    except StopIteration as e:
        raise click.ClickException(f'Cannot find object {name}') from e

    # Re-assemble the target blob
    chunks: list[bytes] = []
    obj = blob
    while True:
        chunks.append(obj.chunk_payload)
        if obj.next_chunk_index_in_store == obj.object_index_in_store:
            break
        obj = store.objects[obj.next_chunk_index_in_store]
    payload = b''.join(chunks)[:blob.blob_size]

    if blob.blob_encryption_key_slot:
        pin = getpass.getpass("Please enter User PIN: ")
        payload = Crypto.hybrid_decrypt(
            reader=reader,
            slot=f'{store.store_encryption_key_slot:02x}',
            encrypted_blob=payload,
            pin=pin
        )

    # Flush the result
    if output is None:
        sys.stdout.buffer.write(payload)
    else:
        output.write(payload)
