// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Pairing the two sides of a YubiKey (spec 0028, "Finding the FIDO2 side
//! of the selected YubiKey").
//!
//! A YubiKey appears as a PIV reader and a FIDO2 device with nothing in
//! common.  yb has selected the PIV side, so it knows the serial; this
//! module finds the FIDO2 device of the same key:
//!
//! 1. the device whose serial (Yubico's vendor command) is the target's;
//! 2. else, with one YubiKey on each side, that device;
//! 3. else, touch selection: every candidate blinks, the one touched is
//!    used (no PIN, so no attempt is spent on the wrong key);
//! 4. else refuse.
//!
//! The PIN is never sent to several devices in turn.

use super::{Device, DeviceInfo, YUBICO_VENDOR_ID};
use anyhow::Result;
use std::time::{Duration, Instant};

/// What a candidate FIDO2 device says about its serial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerialProbe {
    /// The serial the device reports.
    Is(u32),
    /// The device does not report one, or it cannot be read here (no
    /// vendor command on this platform, or no permission).
    Unknown,
}

/// The pairing decision, from the candidates' serials alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pairing {
    /// The candidate at this position.
    Device(usize),
    /// Ask the user to touch one of these candidates.
    Touch(Vec<usize>),
    /// None can be the target.
    NotFound,
}

/// Decide which FIDO2 candidate is the YubiKey with `serial`, given the
/// candidates' serial probes and the number of YubiKeys seen on the PIV
/// side.
pub fn decide(serial: u32, probes: &[SerialProbe], piv_yubikeys: usize) -> Pairing {
    if let Some(i) = probes.iter().position(|p| *p == SerialProbe::Is(serial)) {
        return Pairing::Device(i);
    }
    // Candidates that could still be the target: those whose serial is
    // unknown (a known, different serial rules a device out).
    let unknown: Vec<usize> = probes
        .iter()
        .enumerate()
        .filter(|(_, p)| **p == SerialProbe::Unknown)
        .map(|(i, _)| i)
        .collect();
    match unknown.len() {
        0 => Pairing::NotFound,
        1 if probes.len() == 1 && piv_yubikeys == 1 => Pairing::Device(unknown[0]),
        _ => Pairing::Touch(unknown),
    }
}

/// The Yubico FIDO2 devices connected.
pub fn yubikeys() -> Result<Vec<DeviceInfo>> {
    Ok(super::list_devices()?
        .into_iter()
        .filter(|d| d.vendor_id == YUBICO_VENDOR_ID)
        .collect())
}

/// Read a device's serial, where the platform allows it.
pub fn probe_serial(info: &DeviceInfo) -> SerialProbe {
    #[cfg(target_os = "linux")]
    {
        let read = super::hid::Hidraw::open(&info.path)
            .and_then(|mut ch| super::hid::read_serial(&mut ch));
        if let Ok(Some(serial)) = read {
            return SerialProbe::Is(serial);
        }
    }
    let _ = info;
    SerialProbe::Unknown
}

/// Wait for a touch on one of `devices` (each blinks), at most `timeout`;
/// return the position of the one touched.  No PIN is involved.
pub fn touch_select(devices: &[Device], timeout: Duration) -> Result<usize> {
    for dev in devices {
        dev.touch_begin()?;
    }
    let start = Instant::now();
    let result = loop {
        let mut found = None;
        for (i, dev) in devices.iter().enumerate() {
            if dev.touched(50)? {
                found = Some(i);
                break;
            }
        }
        if let Some(i) = found {
            break Ok(i);
        }
        if start.elapsed() >= timeout {
            break Err(super::Fido2Error::NoTouch.into());
        }
    };
    for dev in devices {
        dev.cancel();
    }
    result
}

/// Open the FIDO2 device of the YubiKey with `serial`, following the rules
/// above.  `piv_yubikeys` is the number of YubiKeys on the PIV side;
/// `on_touch_select` is called before asking for a selection touch.
pub fn open_yubikey(
    serial: u32,
    piv_yubikeys: usize,
    on_touch_select: &dyn Fn(),
) -> Result<Device> {
    #[cfg(all(unix, feature = "test-fixture"))]
    if let Some(path) = super::socket::socket_path() {
        return open_emulator(serial, &path);
    }
    let candidates = yubikeys()?;
    if candidates.is_empty() {
        return Err(super::Fido2Error::NoDevice.into());
    }
    let probes: Vec<SerialProbe> = candidates.iter().map(probe_serial).collect();
    match decide(serial, &probes, piv_yubikeys) {
        Pairing::Device(i) => Device::open(&candidates[i].path),
        Pairing::NotFound => Err(super::Fido2Error::NoDevice.into()),
        Pairing::Touch(indices) => {
            let devices = indices
                .iter()
                .map(|&i| Device::open(&candidates[i].path))
                .collect::<Result<Vec<_>>>()?;
            on_touch_select();
            let chosen = touch_select(&devices, Duration::from_secs(30))?;
            Ok(devices.into_iter().nth(chosen).expect("chosen among them"))
        }
    }
}

/// Open the FIDO2 device of the YubiKey with `serial` when the rules above
/// identify it without a touch (by serial, or the only YubiKey on each
/// side); `None` when a touch would be needed to choose.  For reports that
/// must not ask anything (`yb fsck`, spec 0045).
pub fn open_without_touch(serial: u32, piv_yubikeys: usize) -> Result<Option<Device>> {
    #[cfg(all(unix, feature = "test-fixture"))]
    if let Some(path) = super::socket::socket_path() {
        return open_emulator(serial, &path).map(Some);
    }
    let candidates = yubikeys()?;
    if candidates.is_empty() {
        return Err(super::Fido2Error::NoDevice.into());
    }
    let probes: Vec<SerialProbe> = candidates.iter().map(probe_serial).collect();
    match decide(serial, &probes, piv_yubikeys) {
        Pairing::Device(i) => Device::open(&candidates[i].path).map(Some),
        Pairing::NotFound => Err(super::Fido2Error::NoDevice.into()),
        Pairing::Touch(_) => Ok(None),
    }
}

/// The emulator of the command-line tests, checked by serial as a
/// YubiKey is.
#[cfg(all(unix, feature = "test-fixture"))]
fn open_emulator(serial: u32, path: &str) -> Result<Device> {
    let mut ch = super::socket::SocketChannel::open(path)?;
    if super::hid::read_serial(&mut ch)? != Some(serial) {
        return Err(super::Fido2Error::NoDevice.into());
    }
    drop(ch);
    Device::open_with_io_path(path, &super::socket::SOCKET_IO)
}

#[cfg(test)]
mod tests {
    use super::*;
    use SerialProbe::{Is, Unknown};

    #[test]
    fn by_serial() {
        assert_eq!(decide(7, &[Is(5), Is(7), Unknown], 3), Pairing::Device(1));
    }

    #[test]
    fn a_different_serial_rules_out() {
        assert_eq!(decide(7, &[Is(5)], 1), Pairing::NotFound);
        assert_eq!(decide(7, &[Is(5), Unknown], 2), Pairing::Touch(vec![1]));
    }

    #[test]
    fn one_yubikey_on_each_side() {
        assert_eq!(decide(7, &[Unknown], 1), Pairing::Device(0));
        // Two PIV readers, one FIDO2 device: not necessarily the same key.
        assert_eq!(decide(7, &[Unknown], 2), Pairing::Touch(vec![0]));
    }

    #[test]
    fn several_unknown() {
        assert_eq!(
            decide(7, &[Unknown, Unknown], 2),
            Pairing::Touch(vec![0, 1])
        );
    }
}
