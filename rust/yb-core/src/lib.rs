// SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Core library for `yb` — secure blob storage on a YubiKey.
//!
//! # Quick start
//!
//! ```no_run
//! use yb_core::{store::Store, orchestrator, Context};
//!
//! let ctx = Context::new(None, None, None, Some("123456".into()), false, false)?;
//! let store = Store::from_device(&ctx.reader, ctx.piv.as_ref())?;
//! for blob in orchestrator::list_blobs(&store) {
//!     println!("{} ({} bytes)", blob.name, blob.plain_size);
//! }
//! let data = orchestrator::fetch_blob(
//!     &store, ctx.piv.as_ref(), &ctx.reader, "my-secret", ctx.pin.as_deref(), false,
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

pub(crate) mod auxiliaries;
pub(crate) mod crypto;

pub mod context;
pub mod orchestrator;
pub mod piv;
pub mod store;

pub use context::Context;
pub use orchestrator::{fetch_blob, list_blobs, remove_blob, store_blob, BlobInfo};
pub use piv::hardware::HardwarePiv;
pub use piv::{DeviceInfo, PivBackend, VirtualPiv};
