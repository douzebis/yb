// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! PIV backend trait and implementations.

pub mod emulated;
pub mod hardware;
pub mod mgmt;
pub mod session;
pub(crate) mod tlv;
pub mod virtual_piv;

pub use mgmt::MgmtAlgo;
pub use virtual_piv::{Fault, VirtualPiv};

use anyhow::Result;

// ---------------------------------------------------------------------------
// FlashHandle — returned by PivBackend::start_flash
// ---------------------------------------------------------------------------

/// Opaque handle returned by [`PivBackend::start_flash`].
///
/// Dropping the handle stops the flash loop on the device.
pub trait FlashHandle: Send {}

/// No-op flash handle used by backends that do not support LED flashing
/// (e.g. `VirtualPiv`).
pub struct NoopFlash;
impl FlashHandle for NoopFlash {}

// ---------------------------------------------------------------------------
// DeviceInfo
// ---------------------------------------------------------------------------

/// Device info returned by list_devices.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub serial: u32,
    pub version: String,
    pub reader: String,
}

/// The credential changed by [`PivBackend::change_reference`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinRef {
    Pin,
    Puk,
}

impl PinRef {
    /// Key reference (P2 of VERIFY / CHANGE REFERENCE DATA).
    pub fn reference(self) -> u8 {
        match self {
            Self::Pin => 0x80,
            Self::Puk => 0x81,
        }
    }
}

impl std::fmt::Display for PinRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Pin => "PIN",
            Self::Puk => "PUK",
        })
    }
}

/// Abstract PIV backend.  Both HardwarePiv and EmulatedPiv implement this.
pub trait PivBackend: Send + Sync {
    /// List connected PC/SC readers.
    fn list_readers(&self) -> Result<Vec<String>>;

    /// List connected YubiKey devices.
    fn list_devices(&self) -> Result<Vec<DeviceInfo>>;

    /// Read a PIV data object by its numeric ID.
    fn read_object(&self, reader: &str, id: u32) -> Result<Vec<u8>>;

    /// Write a PIV data object, authenticating with `management_key`.
    ///
    /// Empty `data` deletes the object.  The management key is always
    /// explicit: resolving it (e.g. from the PIN-protected PRINTED object)
    /// is the caller's job — see `Context::management_key_for_write`.
    fn write_object(&self, reader: &str, id: u32, data: &[u8], management_key: &str) -> Result<()>;

    /// Authenticate with `management_key` and write nothing.  Fails if the
    /// card rejects the key.
    fn authenticate_management_key(&self, reader: &str, management_key: &str) -> Result<()>;

    /// Verify the user PIN.  Returns Err if verification fails.
    fn verify_pin(&self, reader: &str, pin: &str) -> Result<()>;

    /// Send a raw APDU and return the response bytes (SW stripped).
    /// Returns Err if the card returns a non-9000 status.
    fn send_apdu(&self, reader: &str, apdu: &[u8]) -> Result<Vec<u8>>;

    /// ECDH key agreement: given the peer's uncompressed P-256 point (65 bytes),
    /// return the shared secret point (65 bytes).
    fn ecdh(&self, reader: &str, slot: u8, peer_point: &[u8], pin: Option<&str>)
        -> Result<Vec<u8>>;

    /// ECDSA sign: compute SHA-256(`digest`) and sign it with the P-256 key in
    /// `slot`.  Returns the raw 64-byte signature `[r (32 bytes) || s (32 bytes)]`.
    /// PIN is required; pass `None` only if already verified in a prior call.
    fn ecdsa_sign(
        &self,
        reader: &str,
        slot: u8,
        digest: &[u8],
        pin: Option<&str>,
    ) -> Result<[u8; 64]> {
        let _ = (reader, slot, digest, pin);
        anyhow::bail!("ecdsa_sign not implemented for this backend")
    }

    /// Read the DER-encoded X.509 certificate from a PIV slot.
    fn read_certificate(&self, reader: &str, slot: u8) -> Result<Vec<u8>>;

    /// Generate an EC P-256 key pair in `slot`; return the public key as an
    /// uncompressed point (65 bytes).  Requires prior management key auth.
    fn generate_key(&self, reader: &str, slot: u8, management_key: Option<&str>)
        -> Result<Vec<u8>>;

    /// Generate an EC P-256 key pair in `slot`, create a self-signed X.509
    /// certificate with the given subject, and import it into the slot.
    /// Returns the DER-encoded certificate.
    fn generate_certificate(
        &self,
        reader: &str,
        slot: u8,
        subject: &str,
        management_key: &str,
        pin: Option<&str>,
    ) -> Result<Vec<u8>>;

    /// Read the raw content of the PRINTED object (0x5FC109) after verifying PIN.
    ///
    /// Implementations must perform PIN verification and object read in the same
    /// session to prevent the card from resetting PIN-verified state between calls.
    fn read_printed_object_with_pin(&self, reader: &str, pin: &str) -> Result<Vec<u8>>;

    /// Return the algorithm of the card's current management key.
    ///
    /// The default implementation reports 3DES, for backends that do not
    /// model the management key algorithm.
    fn management_key_algorithm(&self, reader: &str) -> Result<MgmtAlgo> {
        let _ = reader;
        Ok(MgmtAlgo::Tdes)
    }

    /// Replace the management key.
    ///
    /// `old_key_hex` is the current management key.  `new_key_hex` is the
    /// replacement, which must be `algo.key_len()` bytes long; it is
    /// installed with algorithm `algo`.
    /// The implementation must authenticate with `old_key_hex` first, then
    /// issue SET MANAGEMENT KEY to install `new_key_hex`.
    fn set_management_key(
        &self,
        reader: &str,
        old_key_hex: &str,
        new_key_hex: &str,
        algo: MgmtAlgo,
    ) -> Result<()>;

    /// Change the PIN or the PUK (CHANGE REFERENCE DATA).  Both values are
    /// at most 8 bytes; the card enforces its own rules on the new one.
    fn change_reference(&self, reader: &str, which: PinRef, old: &str, new: &str) -> Result<()> {
        let _ = (reader, which, old, new);
        anyhow::bail!("changing the {which} is not implemented for this backend")
    }

    /// Return the size in bytes of a PIV data object, or `None` if the object
    /// does not exist.  Used by `scan_nvm` to measure NVM usage without writes.
    /// The default implementation attempts `read_object` and maps "not found"
    /// errors to `None`; hardware backends should override with an efficient
    /// implementation that issues a single GET DATA without reading the payload.
    fn object_size(&self, reader: &str, id: u32) -> Result<Option<usize>> {
        match self.read_object(reader, id) {
            Ok(data) => Ok(Some(data.len())),
            Err(_) => Ok(None),
        }
    }

    /// Persist state to a fixture file (no-op for hardware backends).
    ///
    /// `VirtualPiv` overrides this to serialize its in-memory state back to
    /// disk, allowing subprocess tests to share state across process
    /// boundaries via the `YB_FIXTURE` env var.
    fn save_fixture(&self, _path: &std::path::Path) -> Result<()> {
        Ok(())
    }

    /// Start flashing the LED on the device attached to `reader`.
    ///
    /// `on_ms` — how long the LED stays on per cycle (milliseconds).
    /// `off_ms` — how long the LED stays off per cycle (milliseconds).
    ///
    /// Recommended values:
    /// - Device selection: on=400, off=400 (calm 1.25 Hz, easy to follow)
    /// - Destructive confirmation: on=200, off=400 (faster, conveys urgency)
    ///
    /// Returns a [`FlashHandle`]; the LED stops flashing when the handle is
    /// dropped.  The default implementation is a no-op so existing backends
    /// are unaffected.
    fn start_flash(&self, _reader: &str, _on_ms: u64, _off_ms: u64) -> Box<dyn FlashHandle> {
        Box::new(NoopFlash)
    }
}
