// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! PIV data-object read/write (GET DATA / PUT DATA).

use super::transport::{sw_description, transmit_raw_card, PcscSession};
use crate::piv::tlv::{encode_tlv, parse_tlv53};
use anyhow::{bail, Context, Result};

impl PcscSession {
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
                    "GET DATA: SW={sw1:02x}{sw2:02x} ({})",
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
                    "PUT DATA: SW={sw1:02x}{sw2:02x} ({})",
                    sw_description(sw1, sw2)
                );
            } else if (sw1 == 0x6A && sw2 == 0x84) || (sw1 == 0x67 && sw2 == 0x00) {
                drop(tx);
                return Ok(false);
            } else if sw1 != 0x90 || sw2 != 0x00 {
                bail!(
                    "PUT DATA (chained): SW={sw1:02x}{sw2:02x} ({})",
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
                        "PUT DATA: SW={sw1:02x}{sw2:02x} ({})",
                        sw_description(sw1, sw2)
                    );
                }
                break;
            } else if sw1 != 0x90 || sw2 != 0x00 {
                bail!(
                    "PUT DATA (chained): SW={sw1:02x}{sw2:02x} ({})",
                    sw_description(sw1, sw2)
                );
            }
        }

        // Transaction drops here with SCARD_LEAVE_CARD (pcsc crate default).
        Ok(())
    }
}
