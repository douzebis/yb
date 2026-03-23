// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Shared types and constants for blob operations.

use p256::PublicKey;

/// Encryption mode for `store_blob`.
pub enum Encryption<'a> {
    /// Store the blob in plaintext.
    None,
    /// Encrypt the blob to the given P-256 public key.
    Encrypted(&'a PublicKey),
}

/// Compression mode for `store_blob`.
#[derive(Clone, Copy)]
pub enum Compression {
    /// Try brotli level 11 and xz preset 9; store whichever is smaller,
    /// or uncompressed if compression makes no progress.
    Auto,
    /// Never compress.
    None,
}

/// Options for `store_blob`.
pub struct StoreOptions<'a> {
    pub encryption: Encryption<'a>,
    pub compression: Compression,
}

/// Magic prefix prepended to brotli-compressed payloads ("YBr\x01").
pub(super) const BROTLI_MAGIC: &[u8; 4] = b"\x59\x42\x72\x01";

/// Standard xz stream magic.
pub(super) const XZ_MAGIC: &[u8; 6] = b"\xfd7zXZ\x00";

/// Bit 23 of the u24 `blob_plain_size` / `blob_size` wire fields.
/// Used as the compression flag (C-bit) in `blob_plain_size`, and as a
/// mask to verify that a size value fits in the remaining 23 bits.
pub(crate) const BLOB_SIZE_C_BIT: usize = 0x80_0000;

/// Metadata returned by list_blobs.
#[derive(Debug, Clone)]
pub struct BlobInfo {
    pub name: String,
    pub encrypted_size: u32,
    pub plain_size: u32,
    pub is_encrypted: bool,
    /// Modification time as a Unix timestamp (seconds since epoch).
    pub mtime: u32,
    pub chunk_count: usize,
}

#[cfg(feature = "chrono")]
impl BlobInfo {
    /// Return `mtime` as a local [`chrono::DateTime`].
    pub fn mtime_local(&self) -> chrono::DateTime<chrono::Local> {
        use chrono::TimeZone as _;
        chrono::Local
            .timestamp_opt(self.mtime as i64, 0)
            .single()
            .unwrap_or_else(chrono::Local::now)
    }
}
