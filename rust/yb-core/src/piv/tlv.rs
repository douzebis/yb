// SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! BER-TLV encoding/decoding and management-key ECB crypto helpers.

use crate::auxiliaries::decode_tlv_length;
use anyhow::{bail, Result};

// ---------------------------------------------------------------------------
// TLV encoding / decoding
// ---------------------------------------------------------------------------

/// Encode `tag || length || value`.
pub(crate) fn encode_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(encode_length(value.len()));
    out.extend_from_slice(value);
    out
}

pub(crate) fn encode_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len <= 0xFF {
        vec![0x81, len as u8]
    } else if len <= 0xFFFF {
        vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
    } else {
        // SAFETY: PIV data objects are bounded by OBJECT_MAX_SIZE (3,052 bytes)
        // which is well within the 0xFFFF BER two-byte limit.
        unreachable!(
            "encode_length called with len={len} > 0xFFFF; PIV objects cannot exceed 3,052 bytes"
        )
    }
}

/// Strip the outer `53 <len>` wrapper from a GET DATA response.
pub(crate) fn parse_tlv53(data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    if data[0] != 0x53 {
        bail!(
            "GET DATA response: expected tag 0x53, got 0x{:02x}",
            data[0]
        );
    }
    let (len, consumed) = decode_tlv_length(&data[1..]);
    let start = 1 + consumed;
    if start + len > data.len() {
        bail!(
            "GET DATA response: truncated TLV (len={len}, available={})",
            data.len() - start
        );
    }
    Ok(data[start..start + len].to_vec())
}

/// Parse the GENERATE ASYMMETRIC KEY response to extract the public key point.
/// Response: 7F 49 <len> 86 <len> <65-byte-uncompressed-point>
pub(crate) fn parse_gen_key_response(data: &[u8]) -> Result<Vec<u8>> {
    // 7F 49 is a constructed two-byte tag.
    if data.len() < 2 || data[0] != 0x7F || data[1] != 0x49 {
        bail!("GENERATE KEY response: expected tag 7F 49");
    }
    let (outer_len, consumed) = decode_tlv_length(&data[2..]);
    let inner_start = 2 + consumed;
    if inner_start + outer_len > data.len() {
        bail!("GENERATE KEY response: truncated");
    }
    let inner = &data[inner_start..inner_start + outer_len];

    // Inside: 86 <len> <point>
    if inner.is_empty() || inner[0] != 0x86 {
        bail!(
            "GENERATE KEY inner: expected tag 0x86, got 0x{:02x}",
            inner.first().unwrap_or(&0)
        );
    }
    let (point_len, point_consumed) = decode_tlv_length(&inner[1..]);
    let point_start = 1 + point_consumed;
    if point_start + point_len > inner.len() {
        bail!("GENERATE KEY inner: truncated point");
    }
    Ok(inner[point_start..point_start + point_len].to_vec())
}

// ---------------------------------------------------------------------------
// Management key crypto (3DES / AES ECB for the 3-pass mutual auth)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub(crate) enum EcbDir {
    Encrypt,
    Decrypt,
}

pub(crate) fn crypto_ecb(
    key: &[u8],
    data: &[u8],
    block_size: usize,
    dir: EcbDir,
) -> Result<Vec<u8>> {
    let dir_str = match dir {
        EcbDir::Encrypt => "encrypt",
        EcbDir::Decrypt => "decrypt",
    };
    if data.len() != block_size {
        bail!(
            "ECB {dir_str}: data length {} != block size {}",
            data.len(),
            block_size
        );
    }
    let mut block = data.to_vec();
    match (key.len(), dir) {
        (24, EcbDir::Decrypt) => {
            use des::cipher::{BlockDecrypt, KeyInit};
            use des::TdesEde3;
            let cipher =
                TdesEde3::new_from_slice(key).map_err(|e| anyhow::anyhow!("3DES key: {e}"))?;
            let mut b = des::cipher::generic_array::GenericArray::clone_from_slice(&block);
            cipher.decrypt_block(&mut b);
            block.copy_from_slice(&b);
        }
        (24, EcbDir::Encrypt) => {
            use des::cipher::{BlockEncrypt, KeyInit};
            use des::TdesEde3;
            let cipher =
                TdesEde3::new_from_slice(key).map_err(|e| anyhow::anyhow!("3DES key: {e}"))?;
            let mut b = des::cipher::generic_array::GenericArray::clone_from_slice(&block);
            cipher.encrypt_block(&mut b);
            block.copy_from_slice(&b);
        }
        (16, EcbDir::Decrypt) => {
            use aes::cipher::{BlockDecrypt, KeyInit};
            let cipher = aes::Aes128::new_from_slice(key)
                .map_err(|e| anyhow::anyhow!("AES-128 key: {e}"))?;
            let mut b = aes::cipher::generic_array::GenericArray::clone_from_slice(&block);
            cipher.decrypt_block(&mut b);
            block.copy_from_slice(&b);
        }
        (16, EcbDir::Encrypt) => {
            use aes::cipher::{BlockEncrypt, KeyInit};
            let cipher = aes::Aes128::new_from_slice(key)
                .map_err(|e| anyhow::anyhow!("AES-128 key: {e}"))?;
            let mut b = aes::cipher::generic_array::GenericArray::clone_from_slice(&block);
            cipher.encrypt_block(&mut b);
            block.copy_from_slice(&b);
        }
        (32, EcbDir::Decrypt) => {
            use aes::cipher::{BlockDecrypt, KeyInit};
            let cipher = aes::Aes256::new_from_slice(key)
                .map_err(|e| anyhow::anyhow!("AES-256 key: {e}"))?;
            let mut b = aes::cipher::generic_array::GenericArray::clone_from_slice(&block);
            cipher.decrypt_block(&mut b);
            block.copy_from_slice(&b);
        }
        (32, EcbDir::Encrypt) => {
            use aes::cipher::{BlockEncrypt, KeyInit};
            let cipher = aes::Aes256::new_from_slice(key)
                .map_err(|e| anyhow::anyhow!("AES-256 key: {e}"))?;
            let mut b = aes::cipher::generic_array::GenericArray::clone_from_slice(&block);
            cipher.encrypt_block(&mut b);
            block.copy_from_slice(&b);
        }
        (n, _) => bail!("unsupported key length for ECB: {n}"),
    }
    Ok(block)
}
