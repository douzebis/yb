# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import sys
from datetime import datetime

import click

from yb.auxiliaries import StringTooLargeError, format_timestamp
from yb.constants import (
    BLOB_ENCRYPTION_KEY_SLOT_S,
    BLOB_MODIFICATION_TIME_O,
    BLOB_MODIFICATION_TIME_S,
    BLOB_NAME_O,
    BLOB_NAME_UTF8_LEN_S,
    BLOB_SIZE_S,
    BLOB_UNENCRYPTED_SIZE_S,
    CHUNK_POS_IN_BLOB_O,
    CHUNK_POS_IN_BLOB_S,
    NEXT_CHUNK_INDEX_IN_STORE_S,
    OBJECT_AGE_S,
    OBJECT_COUNT_IN_STORE_O,
    OBJECT_COUNT_IN_STORE_S,
    OBJECT_ID_ZERO,
    OBJECT_MAX_SIZE,
    OBJECT_MIN_SIZE,
    STORE_ENCRYPTION_KEY_SLOT_O,
    STORE_ENCRYPTION_KEY_SLOT_S,
    YBLOB_MAGIC,
    YBLOB_MAGIC_O,
    YBLOB_MAGIC_S,
    ZERO,
)
from yb.piv import Piv

# === STORE ====================================================================

class Store:

    # --- STORE GET_PAYLOAD_CAPACITY -------------------------------------------

    def get_payload_capacity(
            self,
            # If name is '', request the capacity for a non-head object
            # Otherwise, request the capacity for a head_object
            name: str
        ) -> int:
        name_as_utf8 = name.encode('utf-8')
        name_utf8_len = len(name_as_utf8)
        if name_utf8_len == 0:
            return (self.object_size_in_store
                    - BLOB_MODIFICATION_TIME_O)
        elif name_utf8_len <= 255:
            return (self.object_size_in_store
                    - BLOB_NAME_O
                    - name_utf8_len)
        else:
            raise StringTooLargeError


    # --- STORE __INIT__ -------------------------------------------------------

    def __init__(
            self,
            reader: str,
            yblob_magic: int,
            object_size_in_store: int,
            object_count_in_store: int,
            store_encryption_key_slot: int,
        ):
        self.reader = reader
        self.yblob_magic = yblob_magic
        self.object_size_in_store = object_size_in_store
        self.object_count_in_store = object_count_in_store
        self.store_encryption_key_slot = store_encryption_key_slot
        self.store_age = 0
        self.objects: list[Object] = []


    # --- STORE FROM_PIV_DEVICE ------------------------------------------------

    @classmethod
    def from_piv_device(
            cls,
            reader: str,
        ) -> Store:
        raw_data = Piv.read_object(reader, OBJECT_ID_ZERO)

        # --- YBLOB_MAGIC

        start = YBLOB_MAGIC_O
        end = start + YBLOB_MAGIC_S
        yblob_magic = int.from_bytes(
            raw_data[start:end], byteorder="little")
        if yblob_magic != YBLOB_MAGIC:
            raise click.ClickException(
                f'Store has bad yblob magic: {yblob_magic:08x}')

        # --- OBJECT_SIZE_IN_STORE

        object_size_in_store = len(raw_data)
        if not OBJECT_MIN_SIZE <= object_size_in_store <= OBJECT_MAX_SIZE:
            raise click.ClickException(
                f'Store has bad object size: {object_size_in_store}')

        # --- OBJECT_COUNT_IN_STORE

        start = OBJECT_COUNT_IN_STORE_O
        end = start + OBJECT_COUNT_IN_STORE_S
        object_count_in_store = int.from_bytes(
            raw_data[start:end], byteorder="little")

        # --- STORE_ENCRYPTION_KEY_SLOT

        start = STORE_ENCRYPTION_KEY_SLOT_O
        end = start + STORE_ENCRYPTION_KEY_SLOT_S
        store_encryption_key_slot = int.from_bytes(
            raw_data[start:end], byteorder="little")
        
        store = Store(
            reader=reader,
            yblob_magic=yblob_magic,
            object_size_in_store=object_size_in_store,
            object_count_in_store=object_count_in_store,
            store_encryption_key_slot=store_encryption_key_slot,
        )

        for index in range(object_count_in_store):
            id = OBJECT_ID_ZERO + index
            if index != 0:
                raw_data = Piv.read_object(store.reader, id)
            if len(raw_data) != store.object_size_in_store:
                raise click.ClickException(
                    f'Object 0x{id:#02x} has bad object_size_in_store:'
                    f' {len(raw_data)}')
            obj = Object.from_serialization(store, index, raw_data)
            if obj.object_count_in_store != store.object_count_in_store:
                raise click.ClickException(
                    f'Object 0x{id:#02x} has bad object_count_in_store:'
                    f' {obj.object_count_in_store}')
            if store.store_age < obj.object_age:
                store.store_age = obj.object_age
            store.objects.append(obj)
        return store


    # --- STORE SANITIZE -------------------------------------------------------
    
    def sanitize(
            self,
        ) -> None:
        # --- Remove head of corrupt blobs -------------------------------------

        # A corrupt blob has any of
        # - out-of-range objects
        # - corrupt age sequence
        # - corrupt chunk-pos-in-blob sequence

        for blob in self.objects:
            age = blob.object_age
            if age == 0:
                continue
            pos_in_blob = blob.chunk_pos_in_blob
            if pos_in_blob != 0:
                continue
            if (not isinstance(blob.blob_name, str)
                or not isinstance(blob.chunk_payload, bytes)):
                blob.reset()
                continue
            object = blob
            while True:
                next_index = object.next_chunk_index_in_store
                if next_index == object.object_index_in_store:
                    break
                if (next_index is None
                    or not(0 <= next_index < self.object_count_in_store)
                    or not isinstance(object.chunk_payload, bytes)):
                    blob.reset()
                    break
                age += 1
                pos_in_blob += 1
                object = self.objects[next_index]
                if (object.object_age != age
                    or object.chunk_pos_in_blob != pos_in_blob):
                    blob.reset()
                    break

        # --- Remove older of identically named blobs --------------------------

        blobs: dict[str, Object] = dict()
        for blob in self.objects:
            age = blob.object_age
            if age == 0:
                continue
            pos_in_blob = blob.chunk_pos_in_blob
            if pos_in_blob != 0:
                continue
            name = blob.blob_name
            assert isinstance(name, str)
            if name not in blobs:
                blobs[name] = self.objects[blob.object_index_in_store]
                continue
            alt_blob = blobs[name]
            assert blob.object_age != alt_blob.object_age
            if blob.object_age < alt_blob.object_age:
                blob.reset()
            else:
                alt_blob.reset()

        # --- Remove unreachable objects ---------------------------------------

        is_reachable = [False] * self.object_count_in_store
        for blob in self.objects:
            age = blob.object_age
            if age == 0:
                continue
            pos_in_blob = blob.chunk_pos_in_blob
            if pos_in_blob != 0:
                continue
            object = blob
            while True:
                is_reachable[object.object_index_in_store] = True
                next_index = object.next_chunk_index_in_store
                assert isinstance(next_index, int)
                if next_index == object.object_index_in_store:
                    break
                object = self.objects[next_index]
        for object in self.objects:
            if (object.object_age != 0
                and not is_reachable[object.object_index_in_store]):
                object.reset()


    # --- STORE GET_FREE_OBJECT_INDEX ------------------------------------------
    
    def get_free_object_index(self) -> int:
        obj  = next(
            obj
            for obj in self.objects
            if obj.object_age == 0
        )
        obj.object_age = 1  # Marking the object as no longer free
        return obj.object_index_in_store


    # --- STORE COMMIT_OBJECT --------------------------------------------------

    def commit_object(self, obj: Object) -> None:
        if self.store_age < obj.object_age:
            self.store_age = obj.object_age
        if obj.object_index_in_store < len(self.objects):
            self.objects[obj.object_index_in_store] = obj
        elif obj.object_index_in_store == len(self.objects):
            self.objects.append(obj)
        else:
            raise RuntimeError


    # --- STORE SYNC -----------------------------------------------------------

    def sync(self) -> None:
        assert self.yblob_magic == YBLOB_MAGIC
        for obj in self.objects:
            id = OBJECT_ID_ZERO + obj.object_index_in_store
            if obj.is_dirty:
                print('.', end='', file=sys.stderr, flush=True)
                Piv.write_object(self.reader, id, obj.serialize())
        print('', file=sys.stderr)



# === OBJECT ===================================================================

class Object:

    # -- OBJECT __INIT__ -------------------------------------------------------

    def __init__(
        self,
        store: Store,
        object_index_in_store: int,
        # If 0, indicates that object is empty
        object_age: int,
         # If 0, indicates that object is the first chunk of a blob
        chunk_pos_in_blob: int | None = None,
        # If identical to object_index_in_store, this is the blob's last chunk
        next_chunk_index_in_store: int | None = None,
        # UNIX Epoch time with second precision
        blob_modification_time: int | None = None,
        blob_size: int | None = None,
        # If 0, indicates that the blob is not encrypted
        blob_encryption_key_slot: int | None = None,
        blob_unencrypted_size: int | None = None,
        blob_name: str | None = None,
        chunk_payload: bytes | None = None,
        # If True, object state in memory differs from state on PIV device
        is_dirty: bool = True,
    ):

        self.store = store

        assert isinstance(store.object_size_in_store, int)
        
        self.object_index_in_store: int = object_index_in_store
        self.is_dirty = is_dirty

        # --- YBLOB_MAGIC

        yblob_magic = store.yblob_magic
        if not 0 <= yblob_magic < 256**YBLOB_MAGIC_S:
            raise ValueError
        self.yblob_magic: int = store.yblob_magic

        # --- OBJECT_COUNT_IN_STORE

        object_count_in_store: int = store.object_count_in_store
        if not 0 <= object_count_in_store < 256**OBJECT_COUNT_IN_STORE_S:
            raise ValueError
        self.object_count_in_store: int = object_count_in_store

        # --- STORE_ENCRYPTION_KEY_SLOT

        store_encryption_key_slot: int = store.store_encryption_key_slot
        if not (0 <= store_encryption_key_slot
                < 256**STORE_ENCRYPTION_KEY_SLOT_S):
            raise ValueError
        self.store_encryption_key_slot: int = store_encryption_key_slot

        # --- OBJECT_AGE

        if not 0 <= object_age < 256**OBJECT_AGE_S:
            raise ValueError
        self.object_age: int = object_age

        # --- CHUNK_PAYLOAD

        blob_name_as_utf8 = None
        blob_name_utf8_len = 0
        if object_age == 0:
            if chunk_payload is None:
                chunk_payload = ZERO[
                    :self.store.object_size_in_store - CHUNK_POS_IN_BLOB_O]
            self.chunk_payload: bytes =chunk_payload
        else:
            capacity = store.object_size_in_store
            if chunk_pos_in_blob != 0:
                capacity -= BLOB_MODIFICATION_TIME_O
            else:
                if not isinstance(blob_name, str):
                    raise ValueError
                blob_name_as_utf8 = blob_name.encode('utf-8')
                blob_name_utf8_len = len(blob_name_as_utf8)
                if not 0 < blob_name_utf8_len < 256**BLOB_NAME_UTF8_LEN_S:
                    raise ValueError
                capacity -= BLOB_NAME_O + blob_name_utf8_len
                #self.object_payload = b'\x00' * (
                #    self.store.get_payload_capacity(blob_name)
                #    - blob_name_utf8_len - BLOB_NAME_O)
            if not isinstance(chunk_payload, bytes):
                raise ValueError
            if len(chunk_payload) > capacity:
                raise ValueError
            self.chunk_payload: bytes = chunk_payload.ljust(capacity, b'\x00')

        # We are done for empty objects
        if object_age == 0:
            return

        # --- CHUNK_POS_IN_BLOB

        if not isinstance(chunk_pos_in_blob, int):
            raise ValueError
        if not 0 <= chunk_pos_in_blob < 256**CHUNK_POS_IN_BLOB_S:
            raise ValueError
        self.chunk_pos_in_blob: int = chunk_pos_in_blob

        # --- NEXT_CHUNK_INDEX_IN_STORE

        if not isinstance(next_chunk_index_in_store, int):
            raise ValueError
        if not 0 <= next_chunk_index_in_store < 256**NEXT_CHUNK_INDEX_IN_STORE_S:
            raise ValueError
        self.next_chunk_index_in_store: int = next_chunk_index_in_store

        # We are done for non-head objects
        if chunk_pos_in_blob != 0:
            return

        # --- BLOB_MODIFICATION_TIME

        if not isinstance(blob_modification_time, int):
            raise ValueError
        if not 0 <= blob_modification_time < 256**BLOB_MODIFICATION_TIME_S:
            raise ValueError
        self.blob_modification_time: int = blob_modification_time

        # --- BLOB_SIZE

        if not isinstance(blob_size, int):
            raise ValueError
        if not 0 <= blob_size < 256**BLOB_SIZE_S:
            raise ValueError
        self.blob_size: int = blob_size

        # --- BLOB_ENCRYPTION_KEY_SLOT

        if not isinstance(blob_encryption_key_slot, int):
            raise ValueError
        if not 0 <= blob_encryption_key_slot < 256**BLOB_ENCRYPTION_KEY_SLOT_S:
            raise ValueError
        self.blob_encryption_key_slot: int = blob_encryption_key_slot

        # --- BLOB_UNENCRYPTED_SIZE

        if not isinstance(blob_unencrypted_size, int):
            raise ValueError
        if not 0 <= blob_unencrypted_size < 256**BLOB_UNENCRYPTED_SIZE_S:
            raise ValueError
        self.blob_unencrypted_size: int = blob_unencrypted_size

        # --- BLOB_NAME

        assert isinstance(blob_name, str)
        self.blob_name: str = blob_name


    # -- OBJECT RESET ----------------------------------------------------------

    def reset(self) -> None:
        self.object_age = 0
        self.chunk_payload = ZERO[
            :self.store.object_size_in_store - CHUNK_POS_IN_BLOB_O]
        self.is_dirty = True


    # -- OBJECT DICT -----------------------------------------------------------

    def dict(self) -> dict:
        out = {
            '<object_index_in_store>': self.object_index_in_store,
            '<is_dirty>': self.is_dirty,
            'yblob_magic': f'0x{self.yblob_magic:#08x}',
            'object_count_in_store': self.object_count_in_store,
            'store_encryption_key_slot': f'0x{self.store_encryption_key_slot:02x}',
            'object_age': self.object_age,
        }
        if self.object_age != 0:
            out |= {
                'chunk_pos_in_blob': self.chunk_pos_in_blob,
                'next_chunk_index_in_store': self.next_chunk_index_in_store,
            }
            if self.chunk_pos_in_blob == 0:
                assert self.blob_modification_time is not None
                out |= {
                    'blob_modification_date': format_timestamp(
                        self.blob_modification_time),
                    'payload_size': self.blob_size,
                    'blob_encryption_key_slot': f'0x{self.blob_encryption_key_slot:02x}',
                    'blob_unencrypted_size': self.blob_unencrypted_size,
                    'blob_name': self.blob_name,                    
                }
            out |= {
                'chunk_payload': (
                    repr(self.chunk_payload) if len(self.chunk_payload) < 32
                    else repr(self.chunk_payload[:32]) + "..."),
            }
        return out


    # -- OBJECT SERIALIZE ------------------------------------------------------

    def serialize(self) -> bytes:

        # --- YBLOB_MAGIC
        
        assert 0 <= self.yblob_magic < 256**YBLOB_MAGIC_S
        out = self.yblob_magic.to_bytes(
            YBLOB_MAGIC_S, byteorder="little")

        # --- OBJECT_COUNT_IN_STORE
        
        assert 0 <= self.object_count_in_store < 256**OBJECT_COUNT_IN_STORE_S
        out += self.object_count_in_store.to_bytes(OBJECT_COUNT_IN_STORE_S)

        # --- STORE_ENCRYPTION_KEY_SLOT
        
        assert (0 <= self.store_encryption_key_slot
                < 256**STORE_ENCRYPTION_KEY_SLOT_S)
        out += self.store_encryption_key_slot.to_bytes(
            STORE_ENCRYPTION_KEY_SLOT_S)

        # --- OBJECT_AGE
        
        assert 0 <= self.object_age < 256**OBJECT_AGE_S
        out += self.object_age.to_bytes(OBJECT_AGE_S, byteorder="little")

        # We are done for empty objects
        if self.object_age == 0:
            return out + self.chunk_payload

        # --- CHUNK_POS_IN_BLOB

        assert isinstance(self.chunk_pos_in_blob, int)
        assert 0 <= self.chunk_pos_in_blob < 256**CHUNK_POS_IN_BLOB_S
        out += self.chunk_pos_in_blob.to_bytes(CHUNK_POS_IN_BLOB_S)

        # --- NEXT_CHUNK_INDEX_IN_STORE

        assert isinstance(self.next_chunk_index_in_store, int)
        assert (0 <= self.next_chunk_index_in_store
                < 256**NEXT_CHUNK_INDEX_IN_STORE_S)
        out += self.next_chunk_index_in_store.to_bytes(
            NEXT_CHUNK_INDEX_IN_STORE_S)
        
        # We are done for non-head objects
        if self.chunk_pos_in_blob != 0:
            return out + self.chunk_payload

        # --- BLOB_MODIFICATION_TIME

        assert isinstance(self.blob_modification_time, int)
        assert 0 <= self.blob_modification_time < 256**BLOB_MODIFICATION_TIME_S
        out += self.blob_modification_time.to_bytes(
            BLOB_MODIFICATION_TIME_S, byteorder="little")

        # --- BLOB_SIZE

        assert isinstance(self.blob_size, int)
        assert 0 < self.blob_size < 256**BLOB_SIZE_S
        out += self.blob_size.to_bytes(BLOB_SIZE_S, byteorder="little")

        # --- BLOB_ENCRYPTION_KEY_SLOT

        assert isinstance(self.blob_encryption_key_slot, int)
        assert (0 <= self.blob_encryption_key_slot
                < 256**BLOB_ENCRYPTION_KEY_SLOT_S)
        out += self.blob_encryption_key_slot.to_bytes(
            BLOB_ENCRYPTION_KEY_SLOT_S)

        # --- BLOB_UNENCRYPTED_SIZE

        assert isinstance(self.blob_unencrypted_size, int)
        assert 0 <= self.blob_unencrypted_size < 256**BLOB_UNENCRYPTED_SIZE_S
        out += self.blob_unencrypted_size.to_bytes(
            BLOB_UNENCRYPTED_SIZE_S, byteorder="little")

        # --- BLOB_NAME_UTF8_LEN

        assert isinstance(self.blob_name, str)
        blob_name_as_utf8 = self.blob_name.encode("utf-8")
        blob_name_utf8_len = len(blob_name_as_utf8)
        assert 0 < blob_name_utf8_len < 256**BLOB_NAME_UTF8_LEN_S
        out += blob_name_utf8_len.to_bytes(
            BLOB_NAME_UTF8_LEN_S, byteorder="little")

        # --- BLOB_NAME

        out += blob_name_as_utf8
        
        # We are done
        return out + self.chunk_payload


    # -- OBJECT FROM_SERIALIZATION ---------------------------------------------
    
    @classmethod
    def from_serialization(
            cls,
            store: Store,
            object_index_in_store: int,
            serialization: bytes,
        ) -> Object:
        """
        Create an Object from raw "wire_level" bytes
        """

        id = OBJECT_ID_ZERO + object_index_in_store
        ndx = 0
        def nxt(length: int) -> bytes:
            nonlocal ndx
            if length == 0:
                length = len(serialization) - ndx
            if ndx + length > len(serialization):
                raise EOFError
            out = serialization[ndx:ndx + length]
            ndx += length
            return out

        # --- YBLOB_MAGIC

        try:
            yblob_magic = int.from_bytes(
                nxt(YBLOB_MAGIC_S), byteorder="little")
        except EOFError as e:
            raise click.ClickException(
                f'Object 0x{id:#02x} is too short') from e
        if yblob_magic != store.yblob_magic:
            raise click.ClickException(
                f'Object 0x{id:#02x} has bad magic number {yblob_magic:#08x}')

        # --- OBJECT_COUNT_IN_STORE

        try:
            object_count_in_store = int.from_bytes(
                nxt(OBJECT_COUNT_IN_STORE_S), byteorder="little")
        except EOFError as e:
            raise click.ClickException(
                f'Object 0x{id:#02x} is too short') from e
        if object_count_in_store != store.object_count_in_store:
            raise click.ClickException(
                f'Object 0x{id:#02x} has bad objects_in_store:'
                f' {object_count_in_store}')

        # --- STORE_ENCRYPTION_KEY_SLOT

        try:
            store_encryption_key_slot = int.from_bytes(
                nxt(STORE_ENCRYPTION_KEY_SLOT_S), byteorder="little")
        except EOFError as e:
            raise click.ClickException(
                f'Object 0x{id:#02x} is too short') from e
        if store_encryption_key_slot != store.store_encryption_key_slot:
            raise click.ClickException(
                f'Object 0x{id:#02x} has bad store_encryption_key_slot:'
                f' {store_encryption_key_slot:02x}')

        # --- OBJECT_AGE
        
        try:
            object_age = int.from_bytes(
                nxt(OBJECT_AGE_S), byteorder="little")
        except EOFError as e:
            raise click.ClickException(
                f'Object 0x{id:#02x} is too short') from e

        # We are done for empty objects
        if object_age == 0:
            return cls(
                store,
                object_index_in_store=object_index_in_store,
                object_age=object_age,
                chunk_payload=nxt(0),
                is_dirty=False,
            )
        
        # --- CHUNK_POS_IN_BLOB
        
        try:
            chunk_pos_in_blob = int.from_bytes(
                nxt(CHUNK_POS_IN_BLOB_S), byteorder="little")
        except EOFError as e:
            raise click.ClickException(
                f'Object 0x{id:#02x} is too short') from e

        # --- NEXT_CHUNK_INDEX_IN_STORE
    
        try:
            next_chunk_index_in_store = int.from_bytes(
                nxt(NEXT_CHUNK_INDEX_IN_STORE_S), byteorder="little")
        except EOFError as e:
            raise click.ClickException(
                f'Object 0x{id:#02x} is too short') from e

        # We are done for non-head objects
        if chunk_pos_in_blob != 0:
            return cls(
                store,
                object_index_in_store=object_index_in_store,
                object_age=object_age,
                chunk_pos_in_blob=chunk_pos_in_blob,
                next_chunk_index_in_store=next_chunk_index_in_store,
                chunk_payload=nxt(0),
                is_dirty=False,
            )

        # --- BLOB_MODIFICATION_TIME

        try:
            blob_modification_time = int.from_bytes(
                nxt(BLOB_MODIFICATION_TIME_S), byteorder="little")
        except EOFError as e:
            raise click.ClickException(
                f'Object 0x{id:#02x} is too short') from e

        # --- BLOB_SIZE

        try:
            blob_size = int.from_bytes(
                nxt(BLOB_SIZE_S), byteorder="little")
        except EOFError as e:
            raise click.ClickException(
                f'Object 0x{id:#02x} is too short') from e

        # --- BLOB_ENCRYPTION_KEY_SLOT

        try:
            blob_encryption_key_slot = int.from_bytes(
                nxt(BLOB_ENCRYPTION_KEY_SLOT_S), byteorder="little")
        except EOFError as e:
            raise click.ClickException(
                f'Object 0x{id:#02x} is too short') from e

        # --- BLOB_UNENCRYPTED_SIZE

        try:
            blob_unencrypted_size = int.from_bytes(
                nxt(BLOB_UNENCRYPTED_SIZE_S), byteorder="little")
        except EOFError as e:
            raise click.ClickException(
                f'Object 0x{id:#02x} is too short') from e

        # --- BLOB_NAME_UTF8_LEN

        try:
            blob_name_utf8_len = int.from_bytes(
                nxt(BLOB_NAME_UTF8_LEN_S), byteorder="little")
        except EOFError as e:
            raise click.ClickException(
                f'Object 0x{id:#02x} is too short') from e

        # --- BLOB_NAME

        try:
            blob_name_as_utf8 = nxt(blob_name_utf8_len)
        except EOFError as e:
            raise click.ClickException(
                f'Object 0x{id:#02x} is too short') from e
        blob_name = blob_name_as_utf8.decode('utf-8')

        # We are done
        return cls(
            store,
            object_index_in_store=object_index_in_store,
            object_age=object_age,
            chunk_pos_in_blob=chunk_pos_in_blob,
            next_chunk_index_in_store=next_chunk_index_in_store,
            blob_modification_time=blob_modification_time,
            blob_size=blob_size,
            blob_encryption_key_slot=blob_encryption_key_slot,
            blob_unencrypted_size=blob_unencrypted_size,
            blob_name=blob_name,
            chunk_payload=nxt(0),
            is_dirty=False,
        )
    
    
    def to_repr(self) -> str:
        if self.object_age == 0 or self.chunk_pos_in_blob != 0:
            return ''
        assert self.blob_unencrypted_size is not None
        assert self.blob_modification_time is not None
        assert self.blob_name is not None

        chunk_count = 1
        object = self
        while True:
            next_index = object.next_chunk_index_in_store
            if  next_index == object.object_index_in_store:
                break
            object = self.store.objects[next_index]
            chunk_count += 1
        bits = '-' if self.blob_encryption_key_slot else 'U'
        count = str(chunk_count).rjust(2)
        size = str(self.blob_unencrypted_size).rjust(8)
        dt = datetime.fromtimestamp(self.blob_modification_time)
        date = dt.strftime("%Y-%m-%d %H:%M").ljust(16)
        return f"{bits} {count} {size} {date} {self.blob_name}"
