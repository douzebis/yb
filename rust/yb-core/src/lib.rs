// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Core library for `yb` — secure blob storage on a YubiKey.
//!
//! # Quick start
//!
//! ```no_run
//! use yb_core::{store::Store, orchestrator, Context, ContextOptions, OutputOptions};
//!
//! let ctx = Context::new(ContextOptions { pin: Some("123456".into()), ..Default::default() }, Box::new(|| Ok(None)), Box::new(|_, _| Ok(None)), OutputOptions::default())?;
//! let store = Store::from_device(&ctx.reader, ctx.piv.as_ref())?;
//! for blob in orchestrator::list_blobs(&store) {
//!     println!("{} ({} bytes)", blob.name, blob.plain_size);
//! }
//! let data = orchestrator::fetch_blob(
//!     &store, ctx.piv.as_ref(), &ctx.reader, "my-secret", ctx.require_pin()?.as_deref(), false,
//! )?;
//! # Ok::<(), anyhow::Error>(())
//! ```
//!
//! # Features
//!
//! | Feature | Purpose | Default |
//! |---|---|---|
//! | `chrono` | `BlobInfo::mtime_local()` convenience method | No |
//! | `virtual-piv` | `VirtualPiv` in-memory backend for testing | No |
//! | `integration-tests` | vsmartcard + piv-authenticator tests | No |
//! | `hardware-tests` | Real YubiKey destructive tests | No |
//!
//! # Security note
//!
//! Private key material on the YubiKey is never extracted. ECDH key
//! agreement is performed on-card via the PIV GENERAL AUTHENTICATE command.

pub mod auxiliaries;
pub mod crypto;

pub mod context;
pub mod errors;
// Post-quantum stores need libfido2 (spec 0028, D9); not on Windows, where
// yb is not shipped (only libyubiblob is checked there, on legacy stores).
#[cfg(not(windows))]
pub mod fido2;
pub mod nvm;
pub mod orchestrator;
pub mod piv;
pub mod policy;
pub mod report;
pub mod store;

pub use context::{
    parse_ec_public_key_from_cert_der, Context, ContextOptions, DevicePicker, KeySource,
    OutputOptions, PrintedRepair, Repairs, SlotKeyCheck,
};
pub use nvm::{scan_nvm, scan_store_memory, NvmUsage};
pub use orchestrator::{
    chunks_needed, collect_blob_chain, fetch_blob, list_blobs, objects_needed, remove_blob,
    remove_blobs, remove_blobs_checked, store_blob, store_blob_checked, store_blob_with_checked,
    unchanged_since, BeforeWrite, BlobChanged, BlobInfo, Compression, Encryption, StoreOptions,
};
pub use piv::hardware::HardwarePiv;
pub use piv::{fixture_path, open_backend, DeviceInfo, FlashHandle, MgmtAlgo, PinRef, PivBackend};
#[cfg(any(feature = "virtual-piv", feature = "test-utils"))]
pub use piv::{Fault, VirtualPiv};
pub use policy::SecretOp;
/// Secrets (management key, PIN) are held in `Zeroizing` buffers.
pub use zeroize::Zeroizing;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

/// The README's example, compiled as a doctest, so that it stays true.
/// Not on Windows: the example uses a post-quantum store, which needs
/// libfido2 (spec 0028, D9).
#[cfg(all(doctest, not(windows)))]
#[doc = include_str!("../README.md")]
pub struct ReadmeDoctests;
