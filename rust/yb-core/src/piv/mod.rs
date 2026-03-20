// SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! PIV backend trait and implementations.

pub mod emulated;
pub mod hardware;

use anyhow::Result;

/// Device info returned by list_devices.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub serial: u32,
    pub version: String,
    pub reader: String,
}

/// Abstract PIV backend.  Both HardwarePiv and EmulatedPiv implement this.
pub trait PivBackend {
    /// List connected PC/SC readers.
    fn list_readers(&self) -> Result<Vec<String>>;

    /// List connected YubiKey devices.
    fn list_devices(&self) -> Result<Vec<DeviceInfo>>;

    /// Read a PIV data object by its numeric ID.
    fn read_object(&self, reader: &str, id: u32) -> Result<Vec<u8>>;

    /// Write a PIV data object.
    fn write_object(
        &self,
        reader: &str,
        id: u32,
        data: &[u8],
        management_key: Option<&str>,
        pin: Option<&str>,
    ) -> Result<()>;

    /// Verify that a reader/slot combination is accessible (PIN check).
    fn verify_pin(&self, reader: &str, pin: &str) -> Result<bool>;

    /// Send a raw APDU and return the response bytes (status word stripped).
    /// Returns Err if the card returns a non-9000 status.
    fn send_apdu(&self, reader: &str, apdu: &[u8]) -> Result<Vec<u8>>;
}
