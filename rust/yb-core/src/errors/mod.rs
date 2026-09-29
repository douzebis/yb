// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Typed errors and their human-readable rendering (spec 0025).
//!
//! - [`CardError`]: a failure reported by the card (status word) or by
//!   PC/SC, tagged with the operation yb was performing.
//! - [`YbError`]: one of yb's own errors, already phrased as what / why /
//!   fix.
//!
//! Both travel through `anyhow` unchanged; [`render`] turns an error chain
//! into the text shown to the user.

mod catalog;

pub use catalog::{explain_pcsc, render, Explanation, RenderEnv};

use crate::piv::MgmtAlgo;
use std::fmt;

/// The card operation that failed, in yb terms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardOp {
    SelectPiv,
    VerifyPin,
    /// CHANGE REFERENCE DATA for the PIN.
    ChangePin,
    /// CHANGE REFERENCE DATA for the PUK.
    ChangePuk,
    MgmtAuth,
    SetMgmtKey,
    ReadObject(u32),
    /// Reading the certificate of a key slot.
    ReadCertificate(u8),
    WriteObject(u32),
    GenerateKey(u8),
    Sign(u8),
    Ecdh(u8),
    GetMetadata(u8),
    /// Any other card command (e.g. a raw `send_apdu`).
    Command,
}

impl CardOp {
    /// Short description, used on the details line.
    pub fn describe(&self) -> String {
        match self {
            Self::SelectPiv => "selecting the PIV application".to_owned(),
            Self::VerifyPin => "PIN verification".to_owned(),
            Self::ChangePin => "PIN change".to_owned(),
            Self::ChangePuk => "PUK change".to_owned(),
            Self::MgmtAuth => "management key authentication".to_owned(),
            Self::SetMgmtKey => "changing the management key".to_owned(),
            Self::ReadObject(id) => format!("read object 0x{id:06X}"),
            Self::ReadCertificate(slot) => format!("read certificate of slot 0x{slot:02x}"),
            Self::WriteObject(id) => format!("write object 0x{id:06X}"),
            Self::GenerateKey(slot) => format!("key generation in slot 0x{slot:02x}"),
            Self::Sign(slot) => format!("signature with slot 0x{slot:02x}"),
            Self::Ecdh(slot) => format!("key agreement with slot 0x{slot:02x}"),
            Self::GetMetadata(slot) => format!("metadata of slot 0x{slot:02x}"),
            Self::Command => "card command".to_owned(),
        }
    }
}

/// What the failing step knew when it failed (spec 0025 §1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ErrCtx {
    /// The management key algorithm yb used, when known.
    pub algo: Option<MgmtAlgo>,
}

/// The PC/SC step that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcscOp {
    Establish,
    ListReaders,
    Connect,
    Transmit,
}

impl PcscOp {
    fn describe(self) -> &'static str {
        match self {
            Self::Establish => "PC/SC context",
            Self::ListReaders => "listing PC/SC readers",
            Self::Connect => "connecting to the YubiKey",
            Self::Transmit => "exchanging data with the YubiKey",
        }
    }
}

/// A PC/SC failure, reduced to the cases the catalog explains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PcscCode {
    NoService,
    NoReaders,
    SharingViolation,
    RemovedCard,
    ResetCard,
    /// Anything else, with the PC/SC library's description.
    Other(String),
}

impl From<pcsc::Error> for PcscCode {
    fn from(e: pcsc::Error) -> Self {
        match e {
            pcsc::Error::NoService | pcsc::Error::ServiceStopped => Self::NoService,
            pcsc::Error::NoReadersAvailable | pcsc::Error::UnknownReader => Self::NoReaders,
            pcsc::Error::SharingViolation => Self::SharingViolation,
            pcsc::Error::RemovedCard | pcsc::Error::NoSmartcard => Self::RemovedCard,
            pcsc::Error::ResetCard => Self::ResetCard,
            other => Self::Other(format!("{other:?}")),
        }
    }
}

impl fmt::Display for PcscCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoService => f.write_str("SCARD_E_NO_SERVICE"),
            Self::NoReaders => f.write_str("SCARD_E_NO_READERS_AVAILABLE"),
            Self::SharingViolation => f.write_str("SCARD_E_SHARING_VIOLATION"),
            Self::RemovedCard => f.write_str("SCARD_W_REMOVED_CARD"),
            Self::ResetCard => f.write_str("SCARD_W_RESET_CARD"),
            Self::Other(name) => write!(f, "PC/SC {name}"),
        }
    }
}

/// A failure reported by the card or by PC/SC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CardError {
    /// The card answered with a status word other than 9000.
    Status { op: CardOp, sw: u16, ctx: ErrCtx },
    /// PC/SC failed.
    Pcsc { op: PcscOp, code: PcscCode },
    /// The card's answer made no sense (too short, malformed, a
    /// cryptographic check failed).
    Protocol { op: CardOp, what: String },
}

impl CardError {
    pub fn status(op: CardOp, sw1: u8, sw2: u8) -> Self {
        Self::Status {
            op,
            sw: u16::from_be_bytes([sw1, sw2]),
            ctx: ErrCtx::default(),
        }
    }

    pub fn with_ctx(mut self, new_ctx: ErrCtx) -> Self {
        if let Self::Status { ref mut ctx, .. } = self {
            *ctx = new_ctx;
        }
        self
    }

    pub fn pcsc(op: PcscOp, e: pcsc::Error) -> Self {
        Self::Pcsc { op, code: e.into() }
    }

    pub fn protocol(op: CardOp, what: impl Into<String>) -> Self {
        Self::Protocol {
            op,
            what: what.into(),
        }
    }

    /// The details line content: operation and code, no identifying data.
    pub fn details(&self) -> String {
        match self {
            Self::Status { op, sw, .. } => format!("{} → SW {sw:04X}", op.describe()),
            Self::Pcsc { op, code } => format!("{} → {code}", op.describe()),
            Self::Protocol { op, what } => format!("{} → {what}", op.describe()),
        }
    }
}

impl fmt::Display for CardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.details())
    }
}

impl std::error::Error for CardError {}

/// One of yb's own errors (not from the card), phrased for the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YbError {
    pub what: String,
    pub why: Option<String>,
    pub fix: Option<String>,
}

impl YbError {
    pub fn new(what: impl Into<String>) -> Self {
        Self {
            what: what.into(),
            why: None,
            fix: None,
        }
    }

    pub fn why(mut self, why: impl Into<String>) -> Self {
        self.why = Some(why.into());
        self
    }

    pub fn fix(mut self, fix: impl Into<String>) -> Self {
        self.fix = Some(fix.into());
        self
    }
}

impl fmt::Display for YbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.what)?;
        if let Some(ref why) = self.why {
            write!(f, " ({why})")?;
        }
        if let Some(ref fix) = self.fix {
            write!(f, "; {fix}")?;
        }
        Ok(())
    }
}

impl std::error::Error for YbError {}
