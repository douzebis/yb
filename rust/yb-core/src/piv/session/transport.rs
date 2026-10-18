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
    /// The connection; `None` only while closing (see `Drop`).
    card: Option<pcsc::Card>,
    /// Whether a command may have changed the card's security state (a
    /// PIN verified, the management key authenticated): the card is then
    /// reset when the connection closes.
    secured: bool,
    /// Management key algorithm, detected on first use and cached for the
    /// lifetime of the session (spec 0021 §1).
    pub(super) mgmt_algo: Option<crate::piv::MgmtAlgo>,
    /// The management key this session last authenticated with, so that a
    /// sequence of writes on one connection authenticates once (spec 0048).
    pub(super) authenticated: Option<zeroize::Zeroizing<String>>,
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
            card: Some(card),
            secured: false,
            mgmt_algo: None,
            authenticated: None,
        };
        session.select_piv()?;
        Ok(session)
    }

    /// SELECT PIV applet (AID A0 00 00 03 08).
    pub(crate) fn select_piv(&mut self) -> Result<()> {
        self.transmit_check(SELECT_PIV, CardOp::SelectPiv)?;
        Ok(())
    }

    /// The connection.
    pub(crate) fn card(&self) -> &pcsc::Card {
        self.card.as_ref().expect("an open connection")
    }

    /// Send an APDU and return the full response (including SW).
    pub(crate) fn transmit_raw(&mut self, apdu: &[u8]) -> Result<Vec<u8>> {
        if !apdu.get(1).is_some_and(|ins| READ_ONLY_INS.contains(ins)) {
            self.secured = true;
        }
        transmit_raw_card(self.card(), apdu)
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

/// Closing the connection: the card is reset after a command that may have
/// changed its security state, so that the next program does not inherit
/// a verified PIN or an authenticated management key.  A connection that
/// only read is closed leaving the card as it is: resetting it would make
/// every other program's connection reconnect (spec 0048).
impl Drop for PcscSession {
    fn drop(&mut self) {
        if let Some(card) = self.card.take() {
            let disposition = if self.secured {
                pcsc::Disposition::ResetCard
            } else {
                pcsc::Disposition::LeaveCard
            };
            // On failure, the card is dropped, which resets it.
            let _ = card.disconnect(disposition);
        }
    }
}

/// Instructions that change nothing on the card: SELECT, GET DATA, GET
/// RESPONSE, GET METADATA, GET SERIAL, GET VERSION.
const READ_ONLY_INS: [u8; 6] = [0xA4, 0xCB, 0xC0, 0xF7, 0xF8, 0xFD];

/// How long to keep reconnecting after other programs reset the card.
const RESET_PATIENCE: std::time::Duration = std::time::Duration::from_secs(30);

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

/// Connect to `reader`, and hold the card lock while connected (spec
/// 0048): PC/SC's transaction, which other programs' commands wait for.
/// The transaction ends when the connection closes (`SCardDisconnect`, or
/// the process ending), so its guard is not kept: a `pcsc::Transaction`
/// borrows the card, which a session must own.
pub(crate) fn connect_reader_mode(
    ctx: &pcsc::Context,
    reader: &str,
    mode: pcsc::ShareMode,
) -> Result<pcsc::Card> {
    // No reader name in errors: it can identify the device (spec 0025 §3).
    let cstring = CString::new(reader).map_err(|_| anyhow::anyhow!("invalid reader name"))?;
    // pcsc-lite's SCardConnect, too, waits while another program holds the
    // card: the notice covers both.
    crate::piv::lock::waiting(|| {
        let mut card = ctx
            .connect(&cstring, mode, pcsc::Protocols::ANY)
            .map_err(|e| CardError::pcsc(PcscOp::Connect, e))?;
        // A program that resets the card when it closes its connection (yb
        // does, after verifying the PIN) makes the connections opened
        // before then reconnect.  Each reset means another program got its
        // turn, so keep at it for a while.
        let start = std::time::Instant::now();
        loop {
            match card.transaction().map(std::mem::forget) {
                Ok(()) => return Ok(card),
                Err(pcsc::Error::ResetCard) if start.elapsed() < RESET_PATIENCE => {
                    card.reconnect(mode, pcsc::Protocols::ANY, pcsc::Disposition::LeaveCard)
                        .map_err(|e| CardError::pcsc(PcscOp::Connect, e))?;
                }
                Err(e) => return Err(CardError::pcsc(PcscOp::Lock, e).into()),
            }
        }
    })
}
