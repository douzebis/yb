// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Reading a YubiKey's serial number over FIDO HID (spec 0028, "Finding
//! the FIDO2 side of the selected YubiKey").
//!
//! libfido2 has no call for vendor commands, so yb does this exchange
//! itself, as ykman does (`yubikit/management.py`): CTAPHID INIT, then
//! Yubico's `READ_CONFIG` (`0x42`) for page 0.  The reply is the device
//! info: a length byte, then TLVs, the serial under tag `0x02`.

use anyhow::{bail, Context, Result};

/// The size of a CTAPHID report.
pub const REPORT_LEN: usize = 64;

const BROADCAST_CID: [u8; 4] = [0xff; 4];
const TYPE_INIT: u8 = 0x80;
const CTAPHID_INIT: u8 = 0x06;
const CTAPHID_KEEPALIVE: u8 = 0x3b;
const CTAPHID_ERROR: u8 = 0x3f;
/// Yubico's vendor command `READ_CONFIG` (`CTAP_VENDOR_FIRST + 2`).
pub const YK_READ_CONFIG: u8 = 0x42;
const TAG_SERIAL: u8 = 0x02;
/// At most this many reports are read for one reply: a reply never
/// legitimately needs more than a handful, and a device that keeps sending
/// keepalives or other channels' traffic must not hang yb.
const MAX_REPORTS: usize = 64;

/// Something that sends and receives 64-byte CTAPHID reports.
pub trait ReportChannel {
    fn write_report(&mut self, report: &[u8; REPORT_LEN]) -> Result<()>;
    fn read_report(&mut self) -> Result<[u8; REPORT_LEN]>;
}

/// Send one CTAPHID message on channel `cid`.
fn send(ch: &mut dyn ReportChannel, cid: [u8; 4], cmd: u8, data: &[u8]) -> Result<()> {
    let mut report = [0u8; REPORT_LEN];
    report[..4].copy_from_slice(&cid);
    report[4] = TYPE_INIT | cmd;
    report[5..7].copy_from_slice(&(data.len() as u16).to_be_bytes());
    let first = data.len().min(REPORT_LEN - 7);
    report[7..7 + first].copy_from_slice(&data[..first]);
    ch.write_report(&report)?;
    for (seq, chunk) in data[first..].chunks(REPORT_LEN - 5).enumerate() {
        let mut report = [0u8; REPORT_LEN];
        report[..4].copy_from_slice(&cid);
        report[4] = seq as u8;
        report[5..5 + chunk.len()].copy_from_slice(chunk);
        ch.write_report(&report)?;
    }
    Ok(())
}

/// Receive one CTAPHID message for `cid` and command `cmd`.
fn recv(ch: &mut dyn ReportChannel, cid: [u8; 4], cmd: u8) -> Result<Vec<u8>> {
    for _ in 0..MAX_REPORTS {
        let report = ch.read_report()?;
        if report[..4] != cid {
            continue;
        }
        match report[4] {
            c if c == TYPE_INIT | CTAPHID_KEEPALIVE => continue,
            c if c == TYPE_INIT | CTAPHID_ERROR => bail!("CTAPHID error 0x{:02x}", report[7]),
            c if c == TYPE_INIT | cmd => {}
            c => bail!("unexpected CTAPHID reply 0x{c:02x}"),
        }
        let size = u16::from_be_bytes([report[5], report[6]]) as usize;
        let mut data = report[7..].to_vec();
        data.truncate(size);
        while data.len() < size {
            let cont = ch.read_report()?;
            if cont[..4] == cid {
                let take = (size - data.len()).min(REPORT_LEN - 5);
                data.extend_from_slice(&cont[5..5 + take]);
            }
        }
        return Ok(data);
    }
    bail!("no CTAPHID reply")
}

/// Open a CTAPHID channel (INIT on the broadcast channel).
fn init(ch: &mut dyn ReportChannel) -> Result<[u8; 4]> {
    let nonce: [u8; 8] = rand::random();
    send(ch, BROADCAST_CID, CTAPHID_INIT, &nonce)?;
    for _ in 0..MAX_REPORTS {
        let reply = recv(ch, BROADCAST_CID, CTAPHID_INIT)?;
        // Another client's INIT reply carries another nonce.
        if reply.len() >= 12 && reply[..8] == nonce {
            return Ok([reply[8], reply[9], reply[10], reply[11]]);
        }
    }
    bail!("no CTAPHID INIT reply")
}

/// The value of `tag` in a list of one-byte-tag BER TLVs.
fn find_tlv(mut data: &[u8], tag: u8) -> Option<&[u8]> {
    while data.len() >= 2 {
        let (len, off) = match data[1] {
            0x81 if data.len() >= 3 => (data[2] as usize, 3),
            0x82 if data.len() >= 4 => (u16::from_be_bytes([data[2], data[3]]) as usize, 4),
            l if l < 0x80 => (l as usize, 2),
            _ => return None,
        };
        let value = data.get(off..off + len)?;
        if data[0] == tag {
            return Some(value);
        }
        data = &data[off + len..];
    }
    None
}

/// The serial number in a `READ_CONFIG` reply, if it has one.
pub fn parse_device_info_serial(info: &[u8]) -> Result<Option<u32>> {
    let Some((&len, tlvs)) = info.split_first() else {
        bail!("empty device info");
    };
    if len as usize != tlvs.len() {
        bail!("invalid device info length");
    }
    Ok(find_tlv(tlvs, TAG_SERIAL).map(|v| v.iter().fold(0u32, |n, &b| (n << 8) | u32::from(b))))
}

/// Read the YubiKey's serial number over `ch`; `None` if the device does
/// not report one.
pub fn read_serial(ch: &mut dyn ReportChannel) -> Result<Option<u32>> {
    let cid = init(ch)?;
    send(ch, cid, YK_READ_CONFIG, &[0x00])?;
    let info = recv(ch, cid, YK_READ_CONFIG).context("reading the YubiKey's device info")?;
    parse_device_info_serial(&info)
}

/// A Linux hidraw device (`/dev/hidrawN`), as libfido2 lists it.
#[cfg(target_os = "linux")]
pub struct Hidraw(std::fs::File);

#[cfg(target_os = "linux")]
impl Hidraw {
    pub fn open(path: &str) -> Result<Self> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .with_context(|| format!("opening {path}"))?;
        Ok(Self(file))
    }
}

#[cfg(target_os = "linux")]
impl ReportChannel for Hidraw {
    fn write_report(&mut self, report: &[u8; REPORT_LEN]) -> Result<()> {
        use std::io::Write as _;
        // hidraw takes the report ID (0) first.
        let mut buf = [0u8; REPORT_LEN + 1];
        buf[1..].copy_from_slice(report);
        self.0.write_all(&buf).context("writing to the FIDO device")
    }

    fn read_report(&mut self) -> Result<[u8; REPORT_LEN]> {
        use std::io::Read as _;
        let mut buf = [0u8; REPORT_LEN];
        let n = self
            .0
            .read(&mut buf)
            .context("reading from the FIDO device")?;
        if n != REPORT_LEN {
            bail!("short HID report ({n} bytes)");
        }
        Ok(buf)
    }
}

/// A device behind libfido2-style I/O functions: the test emulator (spec
/// 0028, "Tests").  Test builds only (invariant 0012).
#[cfg(any(test, feature = "test-utils", feature = "test-fixture"))]
pub struct IoChannel {
    io: super::ffi::FidoDevIo,
    handle: *mut std::ffi::c_void,
}

#[cfg(any(test, feature = "test-utils", feature = "test-fixture"))]
impl IoChannel {
    pub fn open(io: &super::ffi::FidoDevIo) -> Result<Self> {
        // SAFETY: the emulator's `open` takes any C string.
        let handle = unsafe { (io.open)(c"emulator".as_ptr()) };
        if handle.is_null() {
            bail!("the emulator did not open");
        }
        Ok(Self { io: *io, handle })
    }
}

#[cfg(any(test, feature = "test-utils", feature = "test-fixture"))]
impl Drop for IoChannel {
    fn drop(&mut self) {
        // SAFETY: `handle` came from `open`, and is closed once.
        unsafe { (self.io.close)(self.handle) }
    }
}

#[cfg(any(test, feature = "test-utils", feature = "test-fixture"))]
impl ReportChannel for IoChannel {
    fn write_report(&mut self, report: &[u8; REPORT_LEN]) -> Result<()> {
        let mut buf = [0u8; REPORT_LEN + 1];
        buf[1..].copy_from_slice(report);
        // SAFETY: `buf` holds `buf.len()` bytes.
        let n = unsafe { (self.io.write)(self.handle, buf.as_ptr(), buf.len()) };
        if n != buf.len() as std::ffi::c_int {
            bail!("emulator write failed");
        }
        Ok(())
    }

    fn read_report(&mut self) -> Result<[u8; REPORT_LEN]> {
        let mut buf = [0u8; REPORT_LEN];
        // SAFETY: `buf` holds REPORT_LEN writable bytes.
        let n = unsafe { (self.io.read)(self.handle, buf.as_mut_ptr(), REPORT_LEN, -1) };
        if n != REPORT_LEN as std::ffi::c_int {
            bail!("emulator read failed");
        }
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_info_serial() {
        // Page 0 of a YubiKey 5 NFC: USB supported (0x01), serial (0x02),
        // version (0x05).
        let tlvs = [
            0x01, 0x02, 0x02, 0x3b, 0x02, 0x04, 0x01, 0xec, 0x98, 0x5d, 0x05, 0x03, 0x05, 0x07,
            0x01,
        ];
        let mut info = vec![tlvs.len() as u8];
        info.extend_from_slice(&tlvs);
        assert_eq!(parse_device_info_serial(&info).unwrap(), Some(32_282_717));
        assert!(parse_device_info_serial(&[5, 1, 2]).is_err());
    }

    #[test]
    fn device_info_without_serial() {
        let tlvs = [0x05, 0x03, 0x05, 0x07, 0x01];
        let mut info = vec![tlvs.len() as u8];
        info.extend_from_slice(&tlvs);
        assert_eq!(parse_device_info_serial(&info).unwrap(), None);
    }
}
