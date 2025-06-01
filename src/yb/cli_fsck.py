# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

import click
from yb.store import Store
import yaml


# === FSCK =====================================================================

@click.command(
    'fsck',
    help='''
    ''',
)
@click.pass_context
def cli_fsck(ctx) -> None:
    """Dumps the contents of a PIV object store."""

    reader: str = ctx.obj['reader']

    store = Store.from_piv_device(reader)
    store.sanitize()

    out = {
        'reader': store.reader,
        'yblob_magic': f'{store.yblob_magic:08x}',
        'object_size_in_store': store.object_size_in_store,
        'object_count_in_store': store.object_count_in_store,
        'store_encryption_key_slot': f'0x{store.store_encryption_key_slot:02x}',
        'store_age': store.store_age,
    }
    print(f"{yaml.dump(out, indent=2, sort_keys=False)}")
    print('---\n')

    for obj in store.objects:
        obj_as_dict = obj.dict()
        print(f"{yaml.dump(obj_as_dict, indent=2, sort_keys=False)}")
