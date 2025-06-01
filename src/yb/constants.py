# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

# Fred's Fob's magic
YBLOB_MAGIC = 0xF2ed5F0b
OBJECT_MIN_SIZE = 10
# https://docs.yubico.com/yesdk/users-manual/application-piv/cert-size.html
OBJECT_MAX_SIZE = 3_052
ZERO = b'\x00' * OBJECT_MAX_SIZE
OBJECT_ID_ZERO = 0x5f0000
MIN_OBJECT_COUNT = 1
DEFAULT_OBJECT_COUNT = 5
MAX_OBJECT_COUNT = 16
DEFAULT_X509_SUBJECT = '/CN=YBLOB ECCP256'


# === PIV OBJECT STRUCTURE =====================================================

YBLOB_MAGIC_O = 0
YBLOB_MAGIC_S = 4
OBJECT_COUNT_IN_STORE_O = YBLOB_MAGIC_O + YBLOB_MAGIC_S
OBJECT_COUNT_IN_STORE_S = 1
STORE_ENCRYPTION_KEY_SLOT_O = OBJECT_COUNT_IN_STORE_O + OBJECT_COUNT_IN_STORE_S
STORE_ENCRYPTION_KEY_SLOT_S = 1
OBJECT_AGE_O = STORE_ENCRYPTION_KEY_SLOT_O + STORE_ENCRYPTION_KEY_SLOT_S
OBJECT_AGE_S = 3
CHUNK_POS_IN_BLOB_O = OBJECT_AGE_O + OBJECT_AGE_S
CHUNK_POS_IN_BLOB_S = 1
NEXT_CHUNK_INDEX_IN_STORE_O = CHUNK_POS_IN_BLOB_O + CHUNK_POS_IN_BLOB_S
NEXT_CHUNK_INDEX_IN_STORE_S = 1
BLOB_MODIFICATION_TIME_O = (NEXT_CHUNK_INDEX_IN_STORE_O
                            + NEXT_CHUNK_INDEX_IN_STORE_S)
BLOB_MODIFICATION_TIME_S = 4
BLOB_SIZE_O = BLOB_MODIFICATION_TIME_O + BLOB_MODIFICATION_TIME_S
BLOB_SIZE_S = 3
BLOB_ENCRYPTION_KEY_SLOT_O = BLOB_SIZE_O + BLOB_SIZE_S
BLOB_ENCRYPTION_KEY_SLOT_S = 1
BLOB_UNENCRYPTED_SIZE_O = (BLOB_ENCRYPTION_KEY_SLOT_O
                           + BLOB_ENCRYPTION_KEY_SLOT_S)
BLOB_UNENCRYPTED_SIZE_S = 3
BLOB_NAME_UTF8_LEN_O = BLOB_UNENCRYPTED_SIZE_O + BLOB_UNENCRYPTED_SIZE_S
BLOB_NAME_UTF8_LEN_S = 1
BLOB_NAME_O = BLOB_NAME_UTF8_LEN_O + BLOB_NAME_UTF8_LEN_S

# --- For all objects ------------
#
# 0x00 -- yblob_magic
# 0x01 -- yblob_magic
# 0x02 -- yblob_magic
# 0x03 -- yblob_magic
# 0x04 -- object_count_in_store
# 0x05 -- store_encryption_key_slot
# 0x06 -- object_age
# 0x07 -- object_age
# 0x08 -- object_age
#
# --- for all non-empty objects --
#
# 0x09 -- chunk_pos_in_blob
# 0x0a -- next_chunk_index_in_store
#
# --- for first chunk in blob ----
#
# 0x0b -- blob_modification_time
# 0x0c -- blob_modification_time
# 0x0d -- blob_modification_time
# 0x0d -- blob_modification_time
# 0x0f -- payload_size
# 0x10 -- payload_size
# 0x11 -- payload_size
# 0x12 -- blob_encryption_key_slot
# 0x13 -- blob_unencrypted_size
# 0x14 -- blob_unencrypted_size
# 0x15 -- blob_unencrypted_size
# 0x16 -- blob_name_utf8_length
# 0x17 -- blob_name
# ...
# 0x.. -- blob_name
#
# --- for all objects again ------
#
# 0x.. -- chunk_payload
# ...
# 0x.. -- chunk_payload
# 0x.. -- padding
# ...
# 0x.. -- padding
#
# --------------------------------
