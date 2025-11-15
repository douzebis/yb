# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

import click
from yb.store import Store


# === REMOVE ===================================================================


@click.command(
    'rm',
    help='''
        Remove a named blob from the YubiKey.

        This permanently deletes the stored blob associated with the given name.
    ''',
)
@click.argument(
    'name',
    type=str,
)
@click.pass_context
def cli_remove(ctx,
        name: str,
    ) -> None:
    ''''''

    if len(name) == 0 or len(name) > 255:
        raise click.ClickException('Bad name')

    reader: str = ctx.obj['reader']
    management_key: str | None = ctx.obj.get('management_key')

    # Load the store from the PIV device
    store = Store.from_piv_device(reader)
    store.sanitize()

    # Find the target blob
    try:
        blob = next(
            obj
            for obj in store.objects
            if (obj.object_age != 0
                and obj.chunk_pos_in_blob == 0
                and obj.blob_name == name)
        )
    except StopIteration as e:
        raise click.ClickException(f'Cannot find object {name}') from e

    # Remove the target blob
    obj = blob
    while True:
        obj.reset()
        if obj.next_chunk_index_in_store == obj.object_index_in_store:
            break
        obj = store.objects[obj.next_chunk_index_in_store]

    # Flush
    store.sync(management_key)
