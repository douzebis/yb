// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Binary layout constants for PIV object storage.
//!
//! All multi-byte integers are little-endian unless noted.
//! Every PIV object is exactly `object_size` bytes (512–3052).

/// Magic marker at offset 0x00 (little-endian u32).
pub const YBLOB_MAGIC: u32 = 0xF2ED5F0B;

/// Minimum / maximum PIV object size in bytes.
pub const OBJECT_MIN_SIZE: usize = 512;
pub const OBJECT_MAX_SIZE: usize = 3_052;

/// Default number of PIV objects allocated per store.
///
/// 20 objects × 2,048 bytes = 40,960 bytes gross, leaving ~10 KB of the
/// YubiKey 5's 51,200-byte NVM pool for standard-slot certificates.
pub const DEFAULT_OBJECT_COUNT: u8 = 20;

/// Default PIV object size.
///
/// 2,048 bytes balances fragmentation (avg ~1,024 B wasted per blob's last
/// chunk) against write amplification (an 8 KB blob needs 5 PIV writes
/// instead of 3 at the 3,052-byte maximum).
pub const DEFAULT_OBJECT_SIZE: usize = 2_048;

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
