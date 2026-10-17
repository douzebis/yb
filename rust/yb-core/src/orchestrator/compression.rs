// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Compression of blob payloads (before encryption).

use super::types::{Compression, BROTLI_MAGIC, XZ_MAGIC};
use anyhow::{Context, Result};

/// Compress `payload` if `compression` asks for it and it helps; return
/// the bytes to protect and whether the C-bit is set.
pub(super) fn compress(
    name: &str,
    payload: &[u8],
    compression: Compression,
) -> Result<(Vec<u8>, bool)> {
    match compression {
        Compression::None => Ok((payload.to_vec(), false)),
        Compression::Auto => compress_payload(name, payload),
    }
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
