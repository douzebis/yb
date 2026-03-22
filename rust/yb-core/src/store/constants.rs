// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Binary layout constants for PIV object storage.
//!
//! All multi-byte integers are little-endian unless noted.
//! Objects are written at the minimum size required for their content;
//! the PIV `GET DATA` response length tells the reader how large each
//! object is.

/// Magic marker at offset 0x00 (little-endian u32).
pub const YBLOB_MAGIC: u32 = 0xF2ED5F0B;

/// Minimum valid object size: the 9-byte empty-slot sentinel.
pub const OBJECT_MIN_SIZE: usize = 9;

/// Maximum PIV object payload in bytes.
///
/// The YubiKey firmware APDU buffer is 3,072 bytes; the TLV framing overhead
/// is 9 bytes (`5C 03 XX XX XX` + `53 82 HH LL`), leaving 3,063 bytes for
/// the payload.  Empirically confirmed on firmware 5.4.3.
pub const OBJECT_MAX_SIZE: usize = 3_063;

/// Total NVM budget of the YubiKey 5 PIV application (bytes).
pub const YUBIKEY_NVM_BYTES: usize = 51_200;

/// Default number of PIV objects allocated per store.
pub const DEFAULT_OBJECT_COUNT: u8 = 20;

/// First PIV object data-object ID (object index 0).
pub const OBJECT_ID_ZERO: u32 = 0x5f_0000;

/// Default PIV slot used for the ECDH encryption key (slot 0x82).
#[allow(dead_code)]
pub const DEFAULT_KEY_SLOT: u8 = 0x82;

/// Default X.509 subject for the self-signed ECDH certificate.
pub const DEFAULT_SUBJECT: &str = "/CN=YBLOB ECCP256";

// ---------------------------------------------------------------------------
// Field offsets — present in every object (empty or occupied)
// ---------------------------------------------------------------------------

/// Offset of YBLOB_MAGIC (4 bytes, u32 LE).
pub const MAGIC_O: usize = 0x00;

/// Offset of object-count-in-store (1 byte).
pub const OBJECT_COUNT_O: usize = 0x04;

/// Offset of store encryption key slot (1 byte, PIV slot ID).
pub const STORE_KEY_SLOT_O: usize = 0x05;

/// Offset of object age (3 bytes, u24 LE; 0 = empty slot).
pub const OBJECT_AGE_O: usize = 0x06;

// ---------------------------------------------------------------------------
// Fields present only when age != 0
// ---------------------------------------------------------------------------

/// Offset of chunk position within blob (1 byte; 0 = head, 1+ = continuation).
pub const CHUNK_POS_O: usize = 0x09;

/// Offset of next-chunk object index (1 byte; equals own index for last chunk).
pub const NEXT_CHUNK_O: usize = 0x0A;

// ---------------------------------------------------------------------------
// Fields present only in head chunks (chunk_pos == 0)
// ---------------------------------------------------------------------------

/// Offset of blob modification time (4 bytes, u32 LE, Unix seconds).
pub const BLOB_MTIME_O: usize = 0x0B;

/// Offset of encrypted blob size (3 bytes, u24 LE).
pub const BLOB_SIZE_O: usize = 0x0F;

/// Offset of blob encryption key slot (1 byte; 0 = unencrypted).
pub const BLOB_KEY_SLOT_O: usize = 0x12;

/// Offset of unencrypted blob size (3 bytes, u24 LE).
pub const BLOB_PLAIN_SIZE_O: usize = 0x13;

/// Offset of blob name length (1 byte; 1–255).
pub const BLOB_NAME_LEN_O: usize = 0x16;

/// Offset of blob name UTF-8 bytes (variable length).
pub const BLOB_NAME_O: usize = 0x17;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// First byte of chunk payload in a head object (after name).
#[allow(dead_code)]
pub fn head_payload_offset(name_len: usize) -> usize {
    BLOB_NAME_O + name_len
}

/// First byte of chunk payload in a continuation object.
pub const CONTINUATION_PAYLOAD_O: usize = CHUNK_POS_O + 2; // = 0x0B

/// Maximum blob name length in bytes.
pub const MAX_NAME_LEN: usize = 255;
