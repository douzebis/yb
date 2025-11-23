# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

"""
Orchestrator module for YubiKey blob store operations.

This module contains the business logic for store operations, extracted from
CLI commands. It provides a clean interface for both CLI and testing.
"""

from __future__ import annotations

import time
from typing import Hashable, Optional

from yb.piv import PivInterface
from yb.store import Store, Object
from yb.crypto import Crypto


def store_blob(
    reader: str,
    piv: PivInterface,
    name: str,
    payload: bytes,
    encrypted: bool = False,
    management_key: str | None = None,
    pin: str | None = None,
) -> bool:
    """
    Store a blob in the YubiKey store.

    Args:
        reader: PC/SC reader name
        piv: PIV interface (hardware or emulated)
        name: Blob name (1-255 characters)
        payload: Binary data to store
        encrypted: Whether to encrypt the payload
        management_key: Optional management key for write operations
        pin: Optional PIN for PIN-protected management key mode

    Returns:
        True if successful, False if successful, False if store is full or operation failed

    Raises:
        ValueError: If name is invalid
        RuntimeError: If operation fails
    """
    if len(name) == 0 or len(name) > 255:
        raise ValueError(f"Invalid name length: {len(name)} (must be 1-255)")

    # Load store and sanitize
    store = Store.from_piv_device(reader, piv)
    store.sanitize()

    # Prepare payload
    blob_modification_time = int(time.time())
    blob_unencrypted_size = len(payload)

    if encrypted:
        pubkey = Crypto.get_public_key_from_yubikey(
            reader, f'{store.store_encryption_key_slot:02x}')
        payload = Crypto.hybrid_encrypt(payload, pubkey)

    # Calculate chunks needed
    capacity_head = store.get_payload_capacity(name)
    capacity_body = store.get_payload_capacity('')
    indexes: list[int] = []
    pending_len = len(payload)

    try:
        # Allocate first chunk (head)
        index = store.get_free_object_index()
        indexes.append(index)
        pending_len -= capacity_head

        # Allocate remaining chunks (body)
        while pending_len > 0:
            index = store.get_free_object_index()
            indexes.append(index)
            pending_len -= capacity_body
    except StopIteration:
        # Not enough free objects
        return False

    # Create chunk objects
    end = 0
    for chunk_pos_in_blob, index_in_store in enumerate(indexes):
        # Determine next chunk
        if chunk_pos_in_blob == len(indexes) - 1:
            next_chunk_index_in_store = index_in_store  # Last chunk points to itself
        else:
            next_chunk_index_in_store = indexes[chunk_pos_in_blob + 1]

        # Calculate chunk size and extract payload
        if chunk_pos_in_blob == 0:
            size = capacity_head
        else:
            size = capacity_body

        start = end
        end = start + size
        chunk_payload = payload[start:end]

        # Create object
        if chunk_pos_in_blob == 0:
            # Head chunk
            obj = Object(
                store=store,
                object_index_in_store=index_in_store,
                object_age=store.store_age + 1,
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
            # Body chunk
            obj = Object(
                store=store,
                object_index_in_store=index_in_store,
                object_age=store.store_age + 1,
                chunk_pos_in_blob=chunk_pos_in_blob,
                next_chunk_index_in_store=next_chunk_index_in_store,
                chunk_payload=chunk_payload,
            )

        store.commit_object(obj)

    # Sync to device
    store.sync(management_key, pin)
    return True


def fetch_blob(
    reader: str,
    piv: PivInterface,
    name: str,
    pin: str | None = None,
    debug: bool = False,
) -> Optional[bytes]:
    """
    Fetch a blob from the YubiKey store.

    Args:
        reader: PC/SC reader name
        piv: PIV interface (hardware or emulated)
        name: Blob name to fetch
        pin: Optional PIN for decrypting encrypted blobs

    Returns:
        Blob payload as bytes, or None if not found

    Raises:
        ValueError: If name is invalid
        RuntimeError: If blob is encrypted but no PIN provided
    """
    if len(name) == 0 or len(name) > 255:
        raise ValueError(f"Invalid name length: {len(name)} (must be 1-255)")

    # Load store and sanitize
    store = Store.from_piv_device(reader, piv)
    store.sanitize()

    # Find the target blob
    blob = None
    for obj in store.objects:
        if (obj.object_age != 0
            and obj.chunk_pos_in_blob == 0
            and obj.blob_name == name):
            blob = obj
            break

    if blob is None:
        return None

    # Re-assemble the blob from chunks
    chunks: list[bytes] = []
    obj = blob
    chunk_count = 0
    while True:
        chunks.append(obj.chunk_payload)
        chunk_count += 1
        if obj.next_chunk_index_in_store == obj.object_index_in_store:
            break
        obj = store.objects[obj.next_chunk_index_in_store]

    if debug:
        import sys
        print(f'[DEBUG] fetch_blob: blob_name = {blob.blob_name}', file=sys.stderr)
        print(f'[DEBUG] fetch_blob: blob_size (metadata) = {blob.blob_size}', file=sys.stderr)
        print(f'[DEBUG] fetch_blob: blob_unencrypted_size = {blob.blob_unencrypted_size}', file=sys.stderr)
        print(f'[DEBUG] fetch_blob: blob_encryption_key_slot = 0x{blob.blob_encryption_key_slot:02x}', file=sys.stderr)
        print(f'[DEBUG] fetch_blob: chunk_count = {chunk_count}', file=sys.stderr)
        print(f'[DEBUG] fetch_blob: total chunks data length = {sum(len(c) for c in chunks)}', file=sys.stderr)

    payload = b''.join(chunks)[:blob.blob_size]

    if debug:
        import sys
        print(f'[DEBUG] fetch_blob: payload length after slice = {len(payload)}', file=sys.stderr)
        print(f'[DEBUG] fetch_blob: is_encrypted = {blob.blob_encryption_key_slot != 0}', file=sys.stderr)

    # Decrypt if encrypted
    if blob.blob_encryption_key_slot:
        if pin is None:
            raise RuntimeError("Blob is encrypted but no PIN provided")

        # Map reader to serial for PKCS#11 token selection
        serial = piv.get_serial_for_reader(reader)

        if debug:
            import sys
            print(f'[DEBUG] fetch_blob: reader = {reader}', file=sys.stderr)
            print(f'[DEBUG] fetch_blob: serial = {serial}', file=sys.stderr)
            print(f'[DEBUG] fetch_blob: calling hybrid_decrypt with slot = {store.store_encryption_key_slot:02x}', file=sys.stderr)
        payload = Crypto.hybrid_decrypt(
            serial=serial,
            slot=f'{store.store_encryption_key_slot:02x}',
            encrypted_blob=payload,
            pin=pin,
            debug=debug
        )
        if debug:
            import sys
            print(f'[DEBUG] fetch_blob: decrypted payload length = {len(payload)}', file=sys.stderr)

    return payload


def remove_blob(
    reader: str,
    piv: PivInterface,
    name: str,
    management_key: str | None = None,
    pin: str | None = None,
) -> bool:
    """
    Remove a blob from the YubiKey store.

    Args:
        reader: PC/SC reader name
        piv: PIV interface (hardware or emulated)
        name: Blob name to remove
        management_key: Optional management key for write operations

    Returns:
        True if blob was found and removed, False if not found

    Raises:
        ValueError: If name is invalid
    """
    if len(name) == 0 or len(name) > 255:
        raise ValueError(f"Invalid name length: {len(name)} (must be 1-255)")

    # Load store and sanitize
    store = Store.from_piv_device(reader, piv)
    store.sanitize()

    # Find the target blob
    blob = None
    for obj in store.objects:
        if (obj.object_age != 0
            and obj.chunk_pos_in_blob == 0
            and obj.blob_name == name):
            blob = obj
            break

    if blob is None:
        return False

    # Remove all chunks of the blob
    obj = blob
    while True:
        next_index = obj.next_chunk_index_in_store
        obj.reset()
        if next_index == obj.object_index_in_store:
            break
        obj = store.objects[next_index]

    # Sync to device
    store.sync(management_key, pin)
    return True


def list_blobs(
    reader: Hashable,
    piv: PivInterface,
) -> list[tuple[str, int, bool, int, int]]:
    """
    List all blobs in the YubiKey store.

    Args:
        reader: PC/SC reader name
        piv: PIV interface (hardware or emulated)

    Returns:
        List of tuples (name, size, is_encrypted, modification_time, chunk_count) sorted by name
    """
    # Load store and sanitize
    store = Store.from_piv_device(reader, piv)
    store.sanitize()

    # Collect all head chunks
    blobs = [
        obj
        for obj in store.objects
        if obj.object_age != 0 and obj.chunk_pos_in_blob == 0
    ]

    # Sort by name and extract info
    blobs = sorted(blobs, key=lambda e: e.blob_name or "")

    result = []
    for blob in blobs:
        name = blob.blob_name
        size = blob.blob_unencrypted_size
        is_encrypted = blob.blob_encryption_key_slot != 0
        mtime = blob.blob_modification_time

        # Calculate chunk count by following the chain
        chunk_count = 1
        obj = blob
        while True:
            next_index = obj.next_chunk_index_in_store
            if next_index == obj.object_index_in_store:
                break
            obj = store.objects[next_index]
            chunk_count += 1

        result.append((name, size, is_encrypted, mtime, chunk_count))

    return result
