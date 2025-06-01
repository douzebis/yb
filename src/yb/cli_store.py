# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

import sys
import click
from yb.store import Store, Object
import time
from typing import BinaryIO
from yb.crypto import Crypto


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
    '--in', 'input_file',
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
        input_file: BinaryIO | None,
        name: str,
    ) -> None:
    ''''''

    if len(name) == 0 or len(name) > 255:
        raise click.ClickException('Bad name')

    reader: str = ctx.obj['reader']

    store = Store.from_piv_device(reader)
    store.sanitize()

    blob_modification_time = int(time.time())
    payload: bytes
    if input_file is None:
        payload = sys.stdin.buffer.read()
    else:
        payload = input_file.read()
    assert isinstance(payload, bytes)
    blob_unencrypted_size = len(payload)

    if encrypted:
        pubkey = Crypto.get_public_key_from_yubikey(
            reader, f'{store.store_encryption_key_slot:02x}')
        payload = Crypto.hybrid_encrypt(payload, pubkey)

    capacity_head = store.get_payload_capacity(name)
    capacity_body = store.get_payload_capacity('')
    indexes: list[int]=[]
    pending_len = len(payload)
    index = store.get_free_object_index()
    indexes.append(index)
    pending_len -= capacity_head
    while pending_len > 0:
        index = store.get_free_object_index()
        indexes.append(index)
        pending_len -= capacity_body

    end = 0
    for chunk_pos_in_blob, index_in_store in enumerate(indexes):
        next_chunk_index_in_store: int
        if chunk_pos_in_blob == len(indexes) - 1:
            next_chunk_index_in_store = index_in_store
        else:
            next_chunk_index_in_store = indexes[chunk_pos_in_blob+1]
        size: int
        if chunk_pos_in_blob == 0:
            size = capacity_head
        else:
            size = capacity_body
        start = end
        end = start + size   
        chunk_payload = payload[start:end]
        obj: Object
        if chunk_pos_in_blob == 0:
            obj = Object(
                store=store,
                object_index_in_store=index_in_store,
                object_age=store.store_age+1,
                chunk_pos_in_blob=chunk_pos_in_blob,
                next_chunk_index_in_store=next_chunk_index_in_store,
                blob_modification_time=blob_modification_time,
                blob_size=len(payload),
                blob_encryption_key_slot=(0 if not encrypted
                                          else store.store_encryption_key_slot),
                blob_unencrypted_size=blob_unencrypted_size,
                blob_name=name,
                chunk_payload=chunk_payload,
            )
        else:
            obj = Object(
                store=store,
                object_index_in_store=index_in_store,
                object_age=store.store_age+1,
                chunk_pos_in_blob=chunk_pos_in_blob,
                next_chunk_index_in_store=next_chunk_index_in_store,
                chunk_payload=chunk_payload,
            )
        store.commit_object(obj)

    store.sync()
