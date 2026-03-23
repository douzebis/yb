// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Crypto operations: GENERAL AUTHENTICATE, key generation, DER/raw ECDSA conversion.

use super::transport::PcscSession;
use crate::auxiliaries::parse_tlv_flat;
use crate::piv::tlv::{encode_length, encode_tlv, parse_gen_key_response};
use anyhow::Result;

impl PcscSession {
    /// GENERAL AUTHENTICATE — inner helper used by ECDH and SIGN.
    fn general_authenticate(
        &mut self,
        slot: u8,
        p1: u8,
        inner_tag: u8,
        payload: &[u8],
        label: &str,
    ) -> Result<Vec<u8>> {
        // Data: 7C <len> [ 82 00  <inner_tag> <len> <payload> ]
        let mut inner = vec![0x82, 0x00];
        inner.extend(encode_tlv(inner_tag, payload));
        let outer = encode_tlv(0x7C, &inner);

        let mut apdu = vec![0x00, 0x87, p1, slot];
        apdu.extend(encode_length(outer.len()));
        apdu.extend(&outer);
        apdu.push(0x00); // Le

        let resp = self.transmit_check(&apdu, label)?;

        // Response: 7C <len> 82 <len> <result>
        let outer_r = tlv_get(&resp, 0x7C, label)?;
        tlv_get(&outer_r, 0x82, label)
    }

    /// GENERAL AUTHENTICATE ECDH — slot-based key agreement.
    pub(crate) fn general_authenticate_ecdh(
        &mut self,
        slot: u8,
        peer_point: &[u8],
    ) -> Result<Vec<u8>> {
        self.general_authenticate(slot, 0x11, 0x85, peer_point, "GENERAL AUTHENTICATE ECDH")
    }

    /// GENERAL AUTHENTICATE SIGN — produce an EC signature over `digest`.
    pub(crate) fn general_authenticate_sign(&mut self, slot: u8, digest: &[u8]) -> Result<Vec<u8>> {
        self.general_authenticate(slot, 0x11, 0x81, digest, "GENERAL AUTHENTICATE SIGN")
    }

    /// GENERAL AUTHENTICATE SIGN — returns raw (r || s), each 32 bytes.
    pub(crate) fn general_authenticate_sign_raw(
        &mut self,
        slot: u8,
        digest: &[u8],
    ) -> Result<[u8; 64]> {
        let der = self.general_authenticate_sign(slot, digest)?;
        der_ecdsa_to_raw(&der)
    }

    /// GENERATE ASYMMETRIC KEY — generate an EC P-256 key in `slot`.
    /// Returns the uncompressed public key point (65 bytes).
    /// Caller must authenticate management key first.
    pub(crate) fn generate_key(&mut self, slot: u8) -> Result<Vec<u8>> {
        // Data: AC 03 80 01 11 (algorithm = ECC P-256)
        let apdu = [
            0x00, 0x47, 0x00, slot, 0x05, 0xAC, 0x03, 0x80, 0x01, 0x11, 0x00,
        ];
        let resp = self.transmit_check(&apdu, "GENERATE ASYMMETRIC KEY")?;
        parse_gen_key_response(&resp)
    }
}

// ---------------------------------------------------------------------------
// ECDSA DER ↔ raw helpers (pub(crate) so orchestrator can use them)
// ---------------------------------------------------------------------------

/// Parse a DER-encoded `SEQUENCE { INTEGER r, INTEGER s }` from the YubiKey
/// and return the raw 64-byte `[r (32 bytes) || s (32 bytes)]` representation.
///
/// Each INTEGER is zero-padded or sign-stripped to exactly 32 bytes.
pub(crate) fn der_ecdsa_to_raw(der: &[u8]) -> Result<[u8; 64]> {
    // SEQUENCE tag 0x30
    let (seq_body, _) = consume_tlv(der, 0x30, "ECDSA DER SEQUENCE")?;
    let (r_bytes, rest) = consume_tlv(seq_body, 0x02, "ECDSA DER r")?;
    let (s_bytes, _) = consume_tlv(rest, 0x02, "ECDSA DER s")?;
    let mut out = [0u8; 64];
    copy_integer_to_fixed(r_bytes, &mut out[0..32], "r")?;
    copy_integer_to_fixed(s_bytes, &mut out[32..64], "s")?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// Private ASN.1 / TLV helpers
// ---------------------------------------------------------------------------

/// Extract one tag from a flat TLV map, returning an owned copy of the value.
///
/// Equivalent to `parse_tlv_flat(buf).get(&tag).ok_or_else(|| …)?.clone()`
/// but with a uniform error message.
pub(crate) fn tlv_get(buf: &[u8], tag: u8, label: &str) -> Result<Vec<u8>> {
    parse_tlv_flat(buf)
        .get(&tag)
        .ok_or_else(|| anyhow::anyhow!("{label}: missing tag 0x{tag:02x}"))
        .cloned()
}

/// Read one TLV element (tag 1 byte, length 1 byte assumed < 128), return
/// `(value_bytes, remainder)`.
fn consume_tlv<'a>(data: &'a [u8], expected_tag: u8, label: &str) -> Result<(&'a [u8], &'a [u8])> {
    if data.len() < 2 {
        anyhow::bail!("{label}: truncated TLV");
    }
    if data[0] != expected_tag {
        anyhow::bail!(
            "{label}: expected tag 0x{expected_tag:02x}, got 0x{:02x}",
            data[0]
        );
    }
    let len = data[1] as usize;
    if data.len() < 2 + len {
        anyhow::bail!(
            "{label}: truncated TLV value (need {len}, have {})",
            data.len() - 2
        );
    }
    Ok((&data[2..2 + len], &data[2 + len..]))
}

/// Copy a DER INTEGER value into a fixed 32-byte big-endian field.
///
/// DER INTEGERs are signed; a leading 0x00 byte is added when the high bit
/// is set.  We strip that padding and left-pad with zeros to exactly 32 bytes.
fn copy_integer_to_fixed(src: &[u8], dst: &mut [u8], label: &str) -> Result<()> {
    // Strip the optional sign-padding zero.
    let src = if src.first() == Some(&0x00) {
        &src[1..]
    } else {
        src
    };
    if src.len() > dst.len() {
        anyhow::bail!("ECDSA integer {label} too long ({} bytes)", src.len());
    }
    let pad = dst.len() - src.len();
    dst[..pad].fill(0);
    dst[pad..].copy_from_slice(src);
    Ok(())
}
