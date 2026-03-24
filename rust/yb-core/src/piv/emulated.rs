// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! In-memory PIV backend used by tests.

#![allow(dead_code)]
//!
//! Emulates a single YubiKey with configurable serial, reader name, and
//! per-object storage.  Supports optional random write failures (ejection
//! simulation) for reliability testing.

use super::{DeviceInfo, PivBackend};
use anyhow::{anyhow, bail, Result};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Debug, Default)]
struct DeviceState {
    objects: HashMap<u32, Vec<u8>>,
}

/// A simple in-memory PIV device.
pub struct EmulatedPiv {
    serial: u32,
    reader: String,
    version: String,
    state: Arc<Mutex<DeviceState>>,
    /// If Some(p), each write_object call fails with probability p (0.0–1.0).
    ejection_probability: Option<f64>,
}

impl EmulatedPiv {
    pub fn new(serial: u32) -> Self {
        Self {
            serial,
            reader: format!("Emulated YubiKey {serial}"),
            version: "5.4.3".to_owned(),
            state: Arc::new(Mutex::new(DeviceState::default())),
            ejection_probability: None,
        }
    }

    pub fn with_ejection(mut self, probability: f64) -> Self {
        self.ejection_probability = Some(probability);
        self
    }

    pub fn reader_name(&self) -> &str {
        &self.reader
    }
}

impl PivBackend for EmulatedPiv {
    fn list_readers(&self) -> Result<Vec<String>> {
        Ok(vec![self.reader.clone()])
    }

    fn list_devices(&self) -> Result<Vec<DeviceInfo>> {
        Ok(vec![DeviceInfo {
            serial: self.serial,
            version: self.version.clone(),
            reader: self.reader.clone(),
        }])
    }

    fn read_object(&self, reader: &str, id: u32) -> Result<Vec<u8>> {
        if reader != self.reader {
            bail!("emulated: unknown reader '{reader}'");
        }
        let state = self.state.lock().unwrap();
        state
            .objects
            .get(&id)
            .cloned()
            .ok_or_else(|| anyhow!("emulated: object 0x{id:06x} not found"))
    }

    fn write_object(
        &self,
        reader: &str,
        id: u32,
        data: &[u8],
        _management_key: Option<&str>,
        _pin: Option<&str>,
    ) -> Result<()> {
        if reader != self.reader {
            bail!("emulated: unknown reader '{reader}'");
        }
        if let Some(p) = self.ejection_probability {
            if rand::random::<f64>() < p {
                bail!("emulated: simulated ejection during write of 0x{id:06x}");
            }
        }
        let mut state = self.state.lock().unwrap();
        state.objects.insert(id, data.to_vec());
        Ok(())
    }

    fn verify_pin(&self, reader: &str, _pin: &str) -> Result<()> {
        if reader != self.reader {
            bail!("emulated: unknown reader '{reader}'");
        }
        Ok(())
    }

    fn send_apdu(&self, reader: &str, apdu: &[u8]) -> Result<Vec<u8>> {
        if reader != self.reader {
            bail!("emulated: unknown reader '{reader}'");
        }
        // Minimal emulation of GET_METADATA (INS=0xF7) for default-credential checks.
        if apdu.len() >= 4 && apdu[0] == 0x00 && apdu[1] == 0xF7 {
            // Return TLV: tag 0x05 (is_default) = 0x00 (not default).
            return Ok(vec![0x05, 0x01, 0x00]);
        }
        Ok(vec![])
    }

    fn ecdh(
        &self,
        reader: &str,
        _slot: u8,
        _peer_point: &[u8],
        _pin: Option<&str>,
    ) -> Result<Vec<u8>> {
        if reader != self.reader {
            bail!("emulated: unknown reader '{reader}'");
        }
        bail!("emulated: ECDH not implemented (use VirtualPiv for crypto tests)")
    }

    fn ecdsa_sign(
        &self,
        reader: &str,
        _slot: u8,
        _digest: &[u8],
        _pin: Option<&str>,
    ) -> Result<[u8; 64]> {
        if reader != self.reader {
            bail!("emulated: unknown reader '{reader}'");
        }
        bail!("emulated: ECDSA sign not implemented (use VirtualPiv for crypto tests)")
    }

    fn read_certificate(&self, reader: &str, slot: u8) -> Result<Vec<u8>> {
        if reader != self.reader {
            bail!("emulated: unknown reader '{reader}'");
        }
        bail!("emulated: no certificate in slot 0x{slot:02x}")
    }

    fn generate_key(
        &self,
        reader: &str,
        _slot: u8,
        _management_key: Option<&str>,
    ) -> Result<Vec<u8>> {
        if reader != self.reader {
            bail!("emulated: unknown reader '{reader}'");
        }
        bail!("emulated: generate_key not implemented (use VirtualPiv for crypto tests)")
    }

    fn generate_certificate(
        &self,
        reader: &str,
        _slot: u8,
        _subject: &str,
        _management_key: Option<&str>,
        _pin: Option<&str>,
    ) -> Result<Vec<u8>> {
        if reader != self.reader {
            bail!("emulated: unknown reader '{reader}'");
        }
        bail!("emulated: generate_certificate not implemented (use VirtualPiv for crypto tests)")
    }

    fn read_printed_object_with_pin(&self, reader: &str, _pin: &str) -> Result<Vec<u8>> {
        use crate::auxiliaries::OBJ_PRINTED;
        if reader != self.reader {
            bail!("emulated: unknown reader '{reader}'");
        }
        let state = self.state.lock().unwrap();
        state
            .objects
            .get(&OBJ_PRINTED)
            .cloned()
            .ok_or_else(|| anyhow!("emulated: no PRINTED object stored"))
    }

    fn set_management_key(
        &self,
        reader: &str,
        _old_key_hex: &str,
        _new_key_hex: &str,
    ) -> Result<()> {
        if reader != self.reader {
            bail!("emulated: unknown reader '{reader}'");
        }
        Ok(())
    }
}
