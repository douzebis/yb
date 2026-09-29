// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! PC/SC session struct and low-level APDU transport helpers.

use crate::errors::{CardError, CardOp, ErrCtx, PcscOp};
use anyhow::Result;
use std::ffi::CString;

// ---------------------------------------------------------------------------
// PcscSession — card handle + helpers for a single PC/SC connection
// ---------------------------------------------------------------------------

pub(crate) struct PcscSession {
    pub(crate) card: pcsc::Card,
    /// Management key algorithm, detected on first use and cached for the
    /// lifetime of the session (spec 0021 §1).
    pub(super) mgmt_algo: Option<crate::piv::MgmtAlgo>,
}

impl PcscSession {
    /// Open a connection to `reader` and SELECT the PIV applet.
    pub(crate) fn open(reader: &str) -> Result<Self> {
        Self::open_with_mode(reader, pcsc::ShareMode::Shared)
    }

    pub(super) fn open_with_mode(reader: &str, mode: pcsc::ShareMode) -> Result<Self> {
        let ctx = pcsc::Context::establish(pcsc::Scope::User)
            .map_err(|e| CardError::pcsc(PcscOp::Establish, e))?;
        let card = connect_reader_mode(&ctx, reader, mode)?;

        let mut session = Self {
            card,
            mgmt_algo: None,
        };
        session.select_piv()?;
        Ok(session)
    }

    /// SELECT PIV applet (AID A0 00 00 03 08).
    pub(crate) fn select_piv(&mut self) -> Result<()> {
        self.transmit_check(SELECT_PIV, CardOp::SelectPiv)?;
        Ok(())
    }

    /// Send an APDU and return the full response (including SW).
    pub(crate) fn transmit_raw(&mut self, apdu: &[u8]) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; pcsc::MAX_BUFFER_SIZE_EXTENDED];
        let resp = self
            .card
            .transmit(apdu, &mut buf)
            .map_err(|e| CardError::pcsc(PcscOp::Transmit, e))?;
        Ok(resp.to_vec())
    }

    /// What this session knows, for error reports (spec 0025 §1).
    pub(crate) fn err_ctx(&self) -> ErrCtx {
        ErrCtx {
            algo: self.mgmt_algo,
        }
    }

    /// A card error for `op` with status word `sw1 sw2`, carrying this
    /// session's context.
    pub(crate) fn status_error(&self, op: CardOp, sw1: u8, sw2: u8) -> CardError {
        CardError::status(op, sw1, sw2).with_ctx(self.err_ctx())
    }

    /// Send an APDU, handle SW=61xx chaining, check SW=9000, return data (SW stripped).
    pub(crate) fn transmit_check(&mut self, apdu: &[u8], op: CardOp) -> Result<Vec<u8>> {
        let mut resp = self.transmit_raw(apdu)?;
        let mut data = Vec::new();

        loop {
            let n = resp.len();
            if n < 2 {
                return Err(
                    CardError::protocol(op, format!("response too short ({n} bytes)")).into(),
                );
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
            return Err(self.status_error(op, sw1, sw2).into());
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
    let resp = card
        .transmit(apdu, &mut buf)
        .map_err(|e| CardError::pcsc(PcscOp::Transmit, e))?;
    Ok(resp.to_vec())
}

pub(crate) fn connect_reader_mode(
    ctx: &pcsc::Context,
    reader: &str,
    mode: pcsc::ShareMode,
) -> Result<pcsc::Card> {
    // No reader name in errors: it can identify the device (spec 0025 §3).
    let cstring = CString::new(reader).map_err(|_| anyhow::anyhow!("invalid reader name"))?;
    Ok(ctx
        .connect(&cstring, mode, pcsc::Protocols::ANY)
        .map_err(|e| CardError::pcsc(PcscOp::Connect, e))?)
}
