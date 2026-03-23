// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
// SPDX-FileCopyrightText: 2025 - 2026 Thales Cloud Sécurisé
//
// SPDX-License-Identifier: MIT

//! PC/SC session struct and low-level APDU transport helpers.

use anyhow::{bail, Context, Result};
use std::ffi::CString;

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

    pub(super) fn open_with_mode(reader: &str, mode: pcsc::ShareMode) -> Result<Self> {
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

// ---------------------------------------------------------------------------
// SW description helper
// ---------------------------------------------------------------------------

/// Return a short human-readable description for a PIV status word.
pub(super) fn sw_description(sw1: u8, sw2: u8) -> &'static str {
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
