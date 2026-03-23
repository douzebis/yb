// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Compression and encryption pipeline for blob payloads.

use super::types::{BLOB_SIZE_C_BIT, BROTLI_MAGIC, XZ_MAGIC};
use crate::crypto;
use anyhow::{Context, Result};

use super::types::{Compression, Encryption, StoreOptions};

/// Compress and/or encrypt `payload` according to `options`.
///
/// Returns `(stored_bytes, blob_key_slot, is_compressed)` where:
/// - `stored_bytes` is the data to be written across the chunk chain
/// - `blob_key_slot` is the PIV slot used (0 = unencrypted)
/// - `is_compressed` is true when the C-bit should be set in the header
pub(super) fn compress_and_encrypt(
    name: &str,
    payload: &[u8],
    options: &StoreOptions<'_>,
    store_key_slot: u8,
) -> Result<(Vec<u8>, u8, bool)> {
    // Compress if requested.
    let (candidate, is_compressed) = match options.compression {
        Compression::None => (payload.to_vec(), false),
        Compression::Auto => compress_payload(name, payload)?,
    };

    // Encrypt if requested.
    let (data, blob_key_slot) = match options.encryption {
        Encryption::Encrypted(pk) => {
            let enc = crypto::hybrid_encrypt(&candidate, pk).context("encrypting blob")?;
            (enc, store_key_slot)
        }
        Encryption::None => (candidate, 0u8),
    };

    // blob_size is a u24 field; bit 23 is the C flag and must not be set.
    if data.len() & BLOB_SIZE_C_BIT != 0 {
        anyhow::bail!(
            "blob '{}': stored size too large ({} bytes, max 0x7FFFFF)",
            name,
            data.len()
        );
    }

    Ok((data, blob_key_slot, is_compressed))
}

/// Compress `payload` with both brotli and xz; return the better candidate
/// and whether compression was applied.
pub(super) fn compress_payload(name: &str, payload: &[u8]) -> Result<(Vec<u8>, bool)> {
    use std::io::Write as _;

    // Brotli level 11.
    let mut brotli_body = Vec::new();
    {
        let mut enc = brotli::CompressorWriter::new(&mut brotli_body, 4096, 11, 22);
        enc.write_all(payload)
            .with_context(|| format!("brotli compress blob '{name}'"))?;
    }
    // Prepend YBr\x01 magic.
    let mut brotli_out = Vec::with_capacity(BROTLI_MAGIC.len() + brotli_body.len());
    brotli_out.extend_from_slice(BROTLI_MAGIC);
    brotli_out.extend_from_slice(&brotli_body);

    // xz preset 9.
    let mut xz_out = Vec::new();
    {
        let mut enc = lzma_rust2::XzWriter::new(&mut xz_out, lzma_rust2::XzOptions::with_preset(9))
            .with_context(|| format!("xz compress blob '{name}'"))?;
        enc.write_all(payload)
            .with_context(|| format!("xz compress blob '{name}'"))?;
        enc.finish()
            .with_context(|| format!("xz compress blob '{name}'"))?;
    }

    if !xz_out.starts_with(XZ_MAGIC) {
        anyhow::bail!("xz output for blob '{name}' has unexpected magic — library bug");
    }

    // Pick the smaller candidate.
    let pick = if brotli_out.len() <= xz_out.len() {
        brotli_out
    } else {
        xz_out
    };

    if pick.len() < payload.len() {
        Ok((pick, true))
    } else {
        Ok((payload.to_vec(), false))
    }
}

/// Decompress a payload whose C-bit was set.  Dispatches on magic bytes.
pub(super) fn decompress_payload(name: &str, payload: &[u8]) -> Result<Vec<u8>> {
    use std::io::Read as _;

    if payload.starts_with(XZ_MAGIC) {
        let mut out = Vec::new();
        let mut dec = lzma_rust2::XzReader::new(payload, false);
        dec.read_to_end(&mut out)
            .with_context(|| format!("decompressing blob '{name}'"))?;
        return Ok(out);
    }

    if payload.starts_with(BROTLI_MAGIC) {
        let compressed = &payload[BROTLI_MAGIC.len()..];
        let mut dec = brotli::Decompressor::new(compressed, 4096);
        let mut out = Vec::new();
        dec.read_to_end(&mut out)
            .with_context(|| format!("decompressing blob '{name}'"))?;
        return Ok(out);
    }

    anyhow::bail!("unknown compression format in blob '{name}'")
}
