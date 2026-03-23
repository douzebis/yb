// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
// SPDX-FileCopyrightText: 2025 - 2026 Thales Cloud Sécurisé
//
// SPDX-License-Identifier: MIT

//! Card info queries: serial number, firmware version.

use super::transport::{connect_reader_mode, SELECT_PIV};
use anyhow::{bail, Result};

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
