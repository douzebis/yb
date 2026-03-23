// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
// SPDX-FileCopyrightText: 2025 - 2026 Thales Cloud Sécurisé
//
// SPDX-License-Identifier: MIT

//! PC/SC session: a single card connection with APDU helpers.
//!
//! Sub-modules:
//! - [`transport`] — `PcscSession` struct, APDU send/receive, SW helper
//! - [`objects`]   — GET DATA / PUT DATA (PIV data objects)
//! - [`auth`]      — PIN verify, management-key authenticate/resolve
//! - [`crypto`]    — GENERAL AUTHENTICATE, key generation, DER/raw ECDSA
//! - [`info`]      — serial number, firmware version queries

mod auth;
mod crypto;
mod info;
mod objects;
mod transport;

pub(crate) use info::{serial_from_reader, version_from_reader};
pub(crate) use transport::{PcscSession, SELECT_PIV};
