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
pub mod nvm;
pub mod orchestrator;
pub mod piv;
pub mod store;

pub use context::{
    parse_ec_public_key_from_cert_der, Context, ContextOptions, DevicePicker, OutputOptions,
};
pub use nvm::{scan_nvm, NvmUsage};
pub use orchestrator::{
    chunks_needed, collect_blob_chain, fetch_blob, list_blobs, remove_blob, store_blob, BlobInfo,
    Compression, Encryption, StoreOptions,
};
pub use piv::hardware::HardwarePiv;
#[cfg(any(feature = "virtual-piv", feature = "test-utils"))]
pub use piv::VirtualPiv;
pub use piv::{DeviceInfo, FlashHandle, PivBackend};

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
