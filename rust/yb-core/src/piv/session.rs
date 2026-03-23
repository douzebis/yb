// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! PC/SC session: a single card connection with APDU helpers.

use super::tlv::{
    crypto_ecb, encode_length, encode_tlv, parse_gen_key_response, parse_tlv53, EcbDir,
};
use crate::auxiliaries::{extract_pin_protected_key, parse_tlv_flat, OBJ_PRINTED};
use anyhow::{bail, Context, Result};
use std::ffi::CString;
use subtle::ConstantTimeEq;

// ---------------------------------------------------------------------------
// PcscSession — card handle + helpers for a single PC/SC connection
// ---------------------------------------------------------------------------

pub(crate) struct PcscSession {
    pub(crate) card: pcsc::Card,
}

impl PcscSession {
    /// Open a connection to `reader` and SELECT the PIV applet.
    pub(crate) fn open(reader: &str) -> Result<Self> {
        Self::open_with_mode(reader, pcsc::ShareMode::Shared)
    }

    fn open_with_mode(reader: &str, mode: pcsc::ShareMode) -> Result<Self> {
        let ctx =
            pcsc::Context::establish(pcsc::Scope::User).context("establishing PC/SC context")?;
        let card = connect_reader_mode(&ctx, reader, mode)?;

        let mut session = Self { card };
        session.select_piv()?;
        Ok(session)
    }

    /// SELECT PIV applet (AID A0 00 00 03 08).
    pub(crate) fn select_piv(&mut self) -> Result<()> {
        self.transmit_check(SELECT_PIV, "SELECT PIV")?;
        Ok(())
    }

    /// Send an APDU and return the full response (including SW).
    pub(crate) fn transmit_raw(&mut self, apdu: &[u8]) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; pcsc::MAX_BUFFER_SIZE_EXTENDED];
        let resp = self
            .card
            .transmit(apdu, &mut buf)
            .context("APDU transmit")?;
        Ok(resp.to_vec())
    }

    /// Send an APDU, handle SW=61xx chaining, check SW=9000, return data (SW stripped).
    pub(crate) fn transmit_check(&mut self, apdu: &[u8], label: &str) -> Result<Vec<u8>> {
        let mut resp = self.transmit_raw(apdu)?;
        let mut data = Vec::new();

        loop {
            let n = resp.len();
            if n < 2 {
                bail!("{label}: response too short ({n} bytes)");
            }
            let sw1 = resp[n - 2];
            let sw2 = resp[n - 1];
            data.extend_from_slice(&resp[..n - 2]);

            if sw1 == 0x90 && sw2 == 0x00 {
                break; // success
            }
            if sw1 == 0x61 {
                // More data available: issue GET RESPONSE.
                let le = if sw2 == 0x00 { 0x00u8 } else { sw2 };
                let get_resp = [0x00, 0xC0, 0x00, 0x00, le];
                resp = self.transmit_raw(&get_resp)?;
                continue;
            }
            bail!(
                "{label} failed: SW={sw1:02x}{sw2:02x} ({})",
                sw_description(sw1, sw2)
            );
        }

        Ok(data)
    }

    /// GET DATA — fetch a PIV data object by 3-byte object ID.
    pub(crate) fn get_data(&mut self, object_id: u32) -> Result<Vec<u8>> {
        let id = object_id.to_be_bytes(); // 4 bytes; we use the last 3
        let apdu = [
            0x00, 0xCB, 0x3F, 0xFF, // CLA INS P1 P2
            0x05, // Lc = 5
            0x5C, 0x03, id[1], id[2], id[3], // Tag 5C, length 3, 3-byte object ID
            0x00,  // Le
        ];
        let raw = self.transmit_check(&apdu, "GET DATA")?;
        // Response is BER-TLV: 53 <len> <data>.  Strip the outer wrapper.
        parse_tlv53(&raw)
    }

    /// GET DATA — return the payload length, or None if the object is not
    /// found (SW 6A82).  Other errors are propagated.
    pub(crate) fn try_get_data_size(&mut self, object_id: u32) -> Result<Option<usize>> {
        let id = object_id.to_be_bytes();
        let apdu = [
            0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, id[1], id[2], id[3], 0x00,
        ];
        let mut resp = self.transmit_raw(&apdu)?;
        let mut data: Vec<u8> = Vec::new();
        loop {
            let n = resp.len();
            if n < 2 {
                bail!("GET DATA: response too short");
            }
            let sw1 = resp[n - 2];
            let sw2 = resp[n - 1];
            if sw1 == 0x6A && sw2 == 0x82 {
                return Ok(None); // object not found
            }
            if sw1 == 0x69 && sw2 == 0x82 {
                return Ok(None); // security condition not met — skip silently
            }
            data.extend_from_slice(&resp[..n - 2]);
            if sw1 == 0x90 && sw2 == 0x00 {
                break;
            }
            if sw1 == 0x61 {
                let le = if sw2 == 0x00 { 0x00u8 } else { sw2 };
                let get_resp = [0x00, 0xC0, 0x00, 0x00, le];
                resp = self.transmit_raw(&get_resp)?;
            } else {
                bail!(
                    "GET DATA failed: SW={sw1:02x}{sw2:02x} ({})",
                    sw_description(sw1, sw2)
                );
            }
        }
        // data is 53 <len> <payload>; parse payload length.
        if data.is_empty() || data[0] != 0x53 {
            bail!(
                "GET DATA: unexpected TLV tag 0x{:02x}",
                data.first().unwrap_or(&0)
            );
        }
        let payload_len = if data.len() < 2 {
            0
        } else if data[1] < 0x80 {
            data[1] as usize
        } else if data[1] == 0x81 {
            if data.len() < 3 {
                bail!("GET DATA: truncated length");
            }
            data[2] as usize
        } else if data[1] == 0x82 {
            if data.len() < 4 {
                bail!("GET DATA: truncated length");
            }
            ((data[2] as usize) << 8) | data[3] as usize
        } else {
            bail!("GET DATA: unsupported length encoding 0x{:02x}", data[1]);
        };
        Ok(Some(payload_len))
    }

    /// PUT DATA — write a PIV data object.  Returns Ok(false) on 6A84 (NVM
    /// full) or 6700 (payload too large).  Caller must authenticate management
    /// key first.
    pub(crate) fn try_put_data(&mut self, object_id: u32, data: &[u8]) -> Result<bool> {
        let id = object_id.to_be_bytes();
        let mut content = encode_tlv(0x53, data);
        let mut data_field = vec![0x5C, 0x03, id[1], id[2], id[3]];
        data_field.append(&mut content);

        let tx = self
            .card
            .transaction()
            .context("SCardBeginTransaction for PUT DATA")?;

        let mut remaining = data_field.as_slice();
        loop {
            let chunk_len = remaining.len().min(0xFF);
            let is_last = chunk_len == remaining.len();
            let cla: u8 = if is_last { 0x00 } else { 0x10 };
            let mut apdu = vec![cla, 0xDB, 0x3F, 0xFF, chunk_len as u8];
            apdu.extend_from_slice(&remaining[..chunk_len]);
            remaining = &remaining[chunk_len..];

            let resp = transmit_raw_card(&tx, &apdu)?;
            let n = resp.len();
            if n < 2 {
                bail!("PUT DATA: response too short");
            }
            let sw1 = resp[n - 2];
            let sw2 = resp[n - 1];
            if is_last {
                drop(tx);
                if sw1 == 0x90 && sw2 == 0x00 {
                    return Ok(true);
                }
                if (sw1 == 0x6A && sw2 == 0x84) || (sw1 == 0x67 && sw2 == 0x00) {
                    return Ok(false);
                }
                bail!(
                    "PUT DATA failed: SW={sw1:02x}{sw2:02x} ({})",
                    sw_description(sw1, sw2)
                );
            } else if (sw1 == 0x6A && sw2 == 0x84) || (sw1 == 0x67 && sw2 == 0x00) {
                drop(tx);
                return Ok(false);
            } else if sw1 != 0x90 || sw2 != 0x00 {
                bail!(
                    "PUT DATA (chained) failed: SW={sw1:02x}{sw2:02x} ({})",
                    sw_description(sw1, sw2)
                );
            }
        }
    }

    /// PUT DATA — write a PIV data object.  Caller must authenticate management
    /// key first (call `authenticate_management_key`).
    pub(crate) fn put_data(&mut self, object_id: u32, data: &[u8]) -> Result<()> {
        let id = object_id.to_be_bytes();

        // Encode the content as BER-TLV: 53 <len> <data>.
        let mut content = encode_tlv(0x53, data);

        // Build the APDU data field: 5C 03 XX XX XX <content>.
        let mut data_field = vec![0x5C, 0x03, id[1], id[2], id[3]];
        data_field.append(&mut content);

        // yubico-piv-tool wraps every write in SCardBeginTransaction so that
        // pcsclite accepts the SCardTransmit calls.  Without a transaction,
        // pcsclite returns SCARD_E_NOT_TRANSACTED on some platforms.
        let tx = self
            .card
            .transaction()
            .context("SCardBeginTransaction for PUT DATA")?;

        // Send via command chaining (CLA |= 0x10, 255-byte chunks) — the same
        // approach used by yubico-piv-tool.  Extended-Lc APDUs are not used
        // because pcsclite / some CCID drivers reject them without a transaction.
        let mut remaining = data_field.as_slice();
        loop {
            let chunk_len = remaining.len().min(0xFF);
            let is_last = chunk_len == remaining.len();
            let cla: u8 = if is_last { 0x00 } else { 0x10 };
            let mut apdu = vec![cla, 0xDB, 0x3F, 0xFF, chunk_len as u8];
            apdu.extend_from_slice(&remaining[..chunk_len]);
            remaining = &remaining[chunk_len..];

            let resp = transmit_raw_card(&tx, &apdu)?;
            let n = resp.len();
            if n < 2 {
                bail!("PUT DATA: response too short");
            }
            let sw1 = resp[n - 2];
            let sw2 = resp[n - 1];
            if is_last {
                if sw1 != 0x90 || sw2 != 0x00 {
                    bail!(
                        "PUT DATA failed: SW={sw1:02x}{sw2:02x} ({})",
                        sw_description(sw1, sw2)
                    );
                }
                break;
            } else if sw1 != 0x90 || sw2 != 0x00 {
                bail!(
                    "PUT DATA (chained) failed: SW={sw1:02x}{sw2:02x} ({})",
                    sw_description(sw1, sw2)
                );
            }
        }

        // Transaction drops here with SCARD_LEAVE_CARD (pcsc crate default).
        Ok(())
    }

    /// VERIFY PIN (P2=0x80 = user PIN reference).
    /// YubiKey PIV requires the PIN padded to 8 bytes with 0xFF.
    pub(crate) fn verify_pin(&mut self, pin: &str) -> Result<()> {
        let pin_bytes = pin.as_bytes();
        if pin_bytes.len() > 8 {
            bail!("PIN too long (max 8 bytes)");
        }
        let mut padded = [0xFFu8; 8];
        padded[..pin_bytes.len()].copy_from_slice(pin_bytes);
        let mut apdu = vec![0x00, 0x20, 0x00, 0x80, 0x08];
        apdu.extend_from_slice(&padded);
        let resp = self.transmit_raw(&apdu)?;
        let n = resp.len();
        if n < 2 {
            bail!("VERIFY PIN: response too short");
        }
        let sw1 = resp[n - 2];
        let sw2 = resp[n - 1];
        match (sw1, sw2) {
            (0x90, 0x00) => Ok(()),
            (0x63, n) => bail!("VERIFY PIN failed: {} retries remaining", n & 0x0f),
            (0x69, 0x83) => bail!("VERIFY PIN failed: PIN blocked"),
            (s1, s2) => bail!("VERIFY PIN failed: SW={s1:02x}{s2:02x}"),
        }
    }

    /// Authenticate the management key using GENERAL AUTHENTICATE (3-pass mutual auth).
    /// `key_hex` is 48 hex chars for 3DES, or 32/48/64 for AES-128/192/256.
    pub(crate) fn authenticate_management_key(&mut self, key_hex: &str) -> Result<()> {
        let key_bytes = hex::decode(key_hex).context("decoding management key")?;
        let (p1, block_size): (u8, usize) = match key_bytes.len() {
            24 => (0x03, 8),  // 3DES
            16 => (0x08, 16), // AES-128
            32 => (0x0C, 16), // AES-256
            n => bail!("unsupported management key length: {n} bytes"),
        };

        // Step 1: request witness (card encrypts a challenge).
        let step1 = [0x00, 0x87, p1, 0x9B, 0x04, 0x7C, 0x02, 0x80, 0x00];
        let resp1 = self.transmit_check(&step1, "MGMT AUTH step1")?;

        // Parse: 7C <len> 80 <len> <witness>
        let tlv1 = parse_tlv_flat(&resp1);
        let outer = tlv1
            .get(&0x7C)
            .ok_or_else(|| anyhow::anyhow!("MGMT AUTH step1: missing tag 7C"))?;
        let tlv_inner = parse_tlv_flat(outer);
        let witness_enc = tlv_inner
            .get(&0x80)
            .ok_or_else(|| anyhow::anyhow!("MGMT AUTH step1: missing tag 80"))?;

        // Step 2: decrypt witness, generate our own challenge, send both.
        let witness_dec = crypto_ecb(&key_bytes, witness_enc, block_size, EcbDir::Decrypt)?;
        let challenge: Vec<u8> = (0..block_size).map(|_| rand::random::<u8>()).collect();

        // Build data: 7C <len> [ 80 <len> <decrypted-witness> 81 <len> <challenge> ]
        let mut inner2 = encode_tlv(0x80, &witness_dec);
        inner2.extend(encode_tlv(0x81, &challenge));
        let outer2 = encode_tlv(0x7C, &inner2);

        let mut step2 = vec![0x00, 0x87, p1, 0x9B];
        step2.extend(encode_length(outer2.len()));
        step2.extend(&outer2);

        let resp2 = self.transmit_check(&step2, "MGMT AUTH step2")?;

        // Step 3: verify the card encrypted our challenge correctly.
        let tlv2 = parse_tlv_flat(&resp2);
        let outer_r = tlv2
            .get(&0x7C)
            .ok_or_else(|| anyhow::anyhow!("MGMT AUTH step2: missing tag 7C"))?;
        let tlv_inner_r = parse_tlv_flat(outer_r);
        let challenge_resp = tlv_inner_r
            .get(&0x82)
            .ok_or_else(|| anyhow::anyhow!("MGMT AUTH step2: missing tag 82"))?;

        let challenge_enc = crypto_ecb(&key_bytes, &challenge, block_size, EcbDir::Encrypt)?;
        if challenge_enc.ct_eq(challenge_resp).unwrap_u8() == 0 {
            bail!("management key authentication failed: card response mismatch");
        }

        Ok(())
    }

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
        let tlv = parse_tlv_flat(&resp);
        let outer_r = tlv
            .get(&0x7C)
            .ok_or_else(|| anyhow::anyhow!("{label}: missing tag 7C in response"))?;
        let tlv_inner = parse_tlv_flat(outer_r);
        Ok(tlv_inner
            .get(&0x82)
            .ok_or_else(|| anyhow::anyhow!("{label}: missing tag 82 in response"))?
            .clone())
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

    pub(crate) fn resolve_and_auth_management_key(
        &mut self,
        management_key: Option<&str>,
        pin: Option<&str>,
        caller: &str,
    ) -> Result<String> {
        if let Some(k) = management_key {
            self.authenticate_management_key(k)?;
            return Ok(k.to_owned());
        }
        if let Some(p) = pin {
            self.verify_pin(p)?;
            let raw = self.get_data(OBJ_PRINTED).map_err(|_| {
                anyhow::anyhow!(
                    "management key not found on device; \
                     supply it via YB_MANAGEMENT_KEY or the --key flag"
                )
            })?;
            let key_hex = extract_pin_protected_key(&raw)?;
            self.authenticate_management_key(&key_hex)?;
            return Ok(key_hex);
        }
        bail!("{caller}: management_key or pin required");
    }
}

// ---------------------------------------------------------------------------
// Low-level PC/SC helpers
// ---------------------------------------------------------------------------

pub(crate) const SELECT_PIV: &[u8] = &[0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08];

/// Transmit an APDU via a `&pcsc::Card` (or anything that derefs to it, like `Transaction`).
pub(crate) fn transmit_raw_card(card: &pcsc::Card, apdu: &[u8]) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; pcsc::MAX_BUFFER_SIZE_EXTENDED];
    let resp = card.transmit(apdu, &mut buf).context("APDU transmit")?;
    Ok(resp.to_vec())
}

pub(crate) fn connect_reader_mode(
    ctx: &pcsc::Context,
    reader: &str,
    mode: pcsc::ShareMode,
) -> Result<pcsc::Card> {
    let cstring = CString::new(reader).map_err(|e| anyhow::anyhow!("reader name: {e}"))?;
    ctx.connect(&cstring, mode, pcsc::Protocols::ANY)
        .map_err(|e| anyhow::anyhow!("connecting to reader '{reader}': {e}"))
}

fn query_card_apdu(reader: &str, query: &[u8]) -> Result<Vec<u8>> {
    let ctx = pcsc::Context::establish(pcsc::Scope::User)?;
    let card = connect_reader_mode(&ctx, reader, pcsc::ShareMode::Shared)?;
    let mut buf = vec![0u8; 258];
    let _ = card.transmit(SELECT_PIV, &mut buf)?;
    let resp = card.transmit(query, &mut buf)?;
    Ok(resp.to_vec())
}

pub(crate) fn serial_from_reader(reader: &str) -> Result<u32> {
    let resp = query_card_apdu(reader, &[0x00, 0xF8, 0x00, 0x00, 0x00])?;
    if resp.len() < 4 {
        bail!("GET_SERIAL response too short");
    }
    Ok(u32::from_be_bytes(resp[0..4].try_into().unwrap()))
}

pub(crate) fn version_from_reader(reader: &str) -> Option<String> {
    let resp = query_card_apdu(reader, &[0x00, 0xFD, 0x00, 0x00, 0x00]).ok()?;
    if resp.len() < 3 {
        return None;
    }
    Some(format!("{}.{}.{}", resp[0], resp[1], resp[2]))
}

// ---------------------------------------------------------------------------
// SW description helper
// ---------------------------------------------------------------------------

/// Return a short human-readable description for a PIV status word.
fn sw_description(sw1: u8, sw2: u8) -> &'static str {
    match (sw1, sw2) {
        (0x63, _) => "wrong PIN",
        (0x67, 0x00) => "wrong length (object too large?)",
        (0x69, 0x82) => "security condition not met (PIN or management key required)",
        (0x69, 0x83) => "PIN blocked",
        (0x69, 0x84) => "referenced data invalidated (key slot empty?)",
        (0x69, 0x85) => "conditions of use not satisfied",
        (0x6A, 0x80) => "incorrect parameters in data field",
        (0x6A, 0x82) => "object not found",
        (0x6A, 0x84) => "not enough NVM space",
        (0x6A, 0x86) => "incorrect parameters P1/P2",
        (0x6D, 0x00) => "instruction not supported",
        _ => "unexpected status",
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

/// Reconstruct a DER `SEQUENCE { INTEGER r, INTEGER s }` from 64 raw bytes.
///
/// Used by `fsck` to convert stored (r, s) back into a form the P-256 verifier
/// accepts.
pub fn raw_ecdsa_to_der(raw: &[u8; 64]) -> Vec<u8> {
    let r_der = encode_integer(&raw[0..32]);
    let s_der = encode_integer(&raw[32..64]);
    let mut seq_body = Vec::with_capacity(r_der.len() + s_der.len());
    seq_body.extend_from_slice(&r_der);
    seq_body.extend_from_slice(&s_der);
    encode_tlv_vec(0x30, &seq_body)
}

// ---------------------------------------------------------------------------
// Private ASN.1 helpers
// ---------------------------------------------------------------------------

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

/// Encode a raw big-endian integer as a DER INTEGER, adding a 0x00 sign byte
/// when the high bit is set.
fn encode_integer(raw: &[u8]) -> Vec<u8> {
    // Strip leading zero bytes (but keep at least one byte).
    let trimmed = match raw.iter().position(|&b| b != 0) {
        Some(i) => &raw[i..],
        None => &raw[raw.len() - 1..],
    };
    let needs_pad = trimmed[0] & 0x80 != 0;
    let len = trimmed.len() + usize::from(needs_pad);
    let mut out = Vec::with_capacity(2 + len);
    out.push(0x02);
    out.push(len as u8);
    if needs_pad {
        out.push(0x00);
    }
    out.extend_from_slice(trimmed);
    out
}

fn encode_tlv_vec(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + value.len());
    out.push(tag);
    out.push(value.len() as u8);
    out.extend_from_slice(value);
    out
}
