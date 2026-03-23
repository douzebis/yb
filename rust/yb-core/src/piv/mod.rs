// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
// SPDX-FileCopyrightText: 2025 - 2026 Thales Cloud Sécurisé
//
// SPDX-License-Identifier: MIT

//! PIV backend trait and implementations.

pub mod emulated;
pub mod hardware;
pub mod session;
pub(crate) mod tlv;
pub mod virtual_piv;

pub use virtual_piv::VirtualPiv;

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

/// Abstract PIV backend.  Both HardwarePiv and EmulatedPiv implement this.
pub trait PivBackend: Send + Sync {
    /// List connected PC/SC readers.
    fn list_readers(&self) -> Result<Vec<String>>;

    /// List connected YubiKey devices.
    fn list_devices(&self) -> Result<Vec<DeviceInfo>>;

    /// Read a PIV data object by its numeric ID.
    fn read_object(&self, reader: &str, id: u32) -> Result<Vec<u8>>;

    /// Write a PIV data object.
    ///
    /// If `management_key` is Some, it is used directly for authentication.
    /// If `management_key` is None and `pin` is Some, the management key is
    /// retrieved from the PIN-protected PRINTED object in the same session.
    fn write_object(
        &self,
        reader: &str,
        id: u32,
        data: &[u8],
        management_key: Option<&str>,
        pin: Option<&str>,
    ) -> Result<()>;

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
        management_key: Option<&str>,
        pin: Option<&str>,
    ) -> Result<Vec<u8>>;

    /// Read the raw content of the PRINTED object (0x5FC109) after verifying PIN.
    ///
    /// Implementations must perform PIN verification and object read in the same
    /// session to prevent the card from resetting PIN-verified state between calls.
    fn read_printed_object_with_pin(&self, reader: &str, pin: &str) -> Result<Vec<u8>>;

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
