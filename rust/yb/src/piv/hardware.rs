// SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Hardware PIV backend — shells out to yubico-piv-tool for object I/O
//! and uses the pcsc crate for device enumeration and raw APDU access.

use super::{DeviceInfo, PivBackend};
use anyhow::{bail, Context, Result};
use std::io::Write as _;
use std::process::{Command, Stdio};

pub struct HardwarePiv;

impl HardwarePiv {
    pub fn new() -> Self {
        Self
    }
}

impl Default for HardwarePiv {
    fn default() -> Self {
        Self::new()
    }
}

impl PivBackend for HardwarePiv {
    fn list_readers(&self) -> Result<Vec<String>> {
        let out = Command::new("yubico-piv-tool")
            .args(["--action", "list-readers"])
            .output()
            .context("running yubico-piv-tool")?;
        if !out.status.success() {
            bail!(
                "yubico-piv-tool list-readers failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        let readers = String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|l| l.trim().to_owned())
            .filter(|l| !l.is_empty())
            .collect();
        Ok(readers)
    }

    fn list_devices(&self) -> Result<Vec<DeviceInfo>> {
        // Use `ykman list --serials` to enumerate; one serial per line.
        let out = Command::new("ykman")
            .args(["list", "--serials"])
            .output()
            .context("running ykman list --serials")?;
        if !out.status.success() {
            bail!(
                "ykman list failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }

        let serials: Vec<u32> = String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| l.trim().parse().ok())
            .collect();

        let readers = self.list_readers()?;

        // Match readers to serials by querying each reader's serial via APDU.
        // Fallback: if only one device present, pair it directly.
        let mut devices = Vec::new();
        for reader in &readers {
            if let Ok(serial) = serial_from_reader(reader) {
                if let Some(ver) = version_from_reader(reader) {
                    devices.push(DeviceInfo {
                        serial,
                        version: ver,
                        reader: reader.clone(),
                    });
                }
            }
        }

        // If APDU path found nothing, fall back to pairing by position.
        if devices.is_empty() && serials.len() == readers.len() {
            for (serial, reader) in serials.iter().zip(readers.iter()) {
                devices.push(DeviceInfo {
                    serial: *serial,
                    version: "unknown".to_owned(),
                    reader: reader.clone(),
                });
            }
        }

        Ok(devices)
    }

    fn read_object(&self, reader: &str, id: u32) -> Result<Vec<u8>> {
        let out = Command::new("yubico-piv-tool")
            .args([
                "--reader",
                reader,
                "--action",
                "read-object",
                "--format",
                "binary",
                "--id",
                &format!("0x{id:06x}"),
            ])
            .output()
            .context("running yubico-piv-tool read-object")?;
        if !out.status.success() {
            bail!(
                "yubico-piv-tool read-object 0x{id:06x} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        Ok(out.stdout)
    }

    fn write_object(
        &self,
        reader: &str,
        id: u32,
        data: &[u8],
        management_key: Option<&str>,
        _pin: Option<&str>,
    ) -> Result<()> {
        let mut args = vec!["--reader".to_owned(), reader.to_owned()];
        if let Some(key) = management_key {
            args.push(format!("--key={key}"));
        }
        args.extend([
            "--action".to_owned(),
            "write-object".to_owned(),
            "--format".to_owned(),
            "binary".to_owned(),
            "--id".to_owned(),
            format!("0x{id:06x}"),
        ]);

        let mut child = Command::new("yubico-piv-tool")
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context("spawning yubico-piv-tool write-object")?;

        child
            .stdin
            .take()
            .unwrap()
            .write_all(data)
            .context("writing to yubico-piv-tool stdin")?;

        let out = child
            .wait_with_output()
            .context("waiting for yubico-piv-tool")?;
        if !out.status.success() {
            bail!(
                "yubico-piv-tool write-object 0x{id:06x} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        Ok(())
    }

    fn verify_pin(&self, reader: &str, pin: &str) -> Result<bool> {
        let out = Command::new("yubico-piv-tool")
            .args(["--reader", reader, "--action", "verify-pin", "--pin", pin])
            .output()
            .context("running yubico-piv-tool verify-pin")?;
        Ok(out.status.success())
    }

    fn send_apdu(&self, reader: &str, apdu: &[u8]) -> Result<Vec<u8>> {
        pcsc_send_apdu(reader, apdu)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Connect to a named PC/SC reader and return a Card handle.
/// The pcsc crate uses null-terminated reader names (CStr), so we append \0.
fn connect_reader(ctx: &pcsc::Context, reader: &str) -> Result<pcsc::Card> {
    // Build a null-terminated reader name as required by the pcsc crate.
    let mut name = reader.to_owned();
    name.push('\0');
    let cstr = std::ffi::CStr::from_bytes_with_nul(name.as_bytes())
        .map_err(|e| anyhow::anyhow!("reader name: {e}"))?;
    ctx.connect(cstr, pcsc::ShareMode::Shared, pcsc::Protocols::ANY)
        .map_err(|e| anyhow::anyhow!("connecting to reader '{reader}': {e}"))
}

/// Send an APDU to a named reader (selects PIV applet first).
fn pcsc_send_apdu(reader: &str, apdu: &[u8]) -> Result<Vec<u8>> {
    let ctx = pcsc::Context::establish(pcsc::Scope::User).context("establishing PC/SC context")?;
    let card = connect_reader(&ctx, reader)?;

    // Select PIV applet first.
    let select_piv = &[0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08];
    let mut resp_buf = [0u8; 258];
    let resp = card
        .transmit(select_piv, &mut resp_buf)
        .context("SELECT PIV")?;
    check_sw(resp, "SELECT PIV")?;

    // Send the user APDU.
    let resp = card
        .transmit(apdu, &mut resp_buf)
        .context("transmit APDU")?;
    let n = resp.len();
    if n < 2 {
        bail!("APDU response too short");
    }
    check_sw(resp, "APDU")?;
    Ok(resp[..n - 2].to_vec())
}

fn check_sw(resp: &[u8], label: &str) -> Result<()> {
    let n = resp.len();
    if n < 2 {
        bail!("{label}: response too short");
    }
    let sw = &resp[n - 2..];
    if sw != [0x90, 0x00] {
        bail!("{label} failed: {:02x}{:02x}", sw[0], sw[1]);
    }
    Ok(())
}

/// Read the YubiKey serial number from a reader via GET_SERIAL APDU.
fn serial_from_reader(reader: &str) -> Result<u32> {
    let ctx = pcsc::Context::establish(pcsc::Scope::User)?;
    let card = connect_reader(&ctx, reader)?;

    let mut buf = [0u8; 258];

    // SELECT PIV
    let select_piv = &[0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08];
    let _ = card.transmit(select_piv, &mut buf)?;

    // GET SERIAL (YubiKey proprietary INS=0xF8)
    let get_serial = &[0x00, 0xF8, 0x00, 0x00, 0x00];
    let resp = card.transmit(get_serial, &mut buf)?;
    if resp.len() < 6 {
        bail!("GET_SERIAL response too short");
    }
    Ok(u32::from_be_bytes(resp[0..4].try_into().unwrap()))
}

/// Read firmware version from GET_VERSION APDU.
fn version_from_reader(reader: &str) -> Option<String> {
    let ctx = pcsc::Context::establish(pcsc::Scope::User).ok()?;
    let card = connect_reader(&ctx, reader).ok()?;

    let mut buf = [0u8; 258];
    let select_piv = &[0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08];
    let _ = card.transmit(select_piv, &mut buf).ok()?;

    // GET_VERSION INS=0xFD
    let get_ver = &[0x00, 0xFD, 0x00, 0x00, 0x00];
    let resp = card.transmit(get_ver, &mut buf).ok()?;
    if resp.len() < 5 {
        return None;
    }
    Some(format!("{}.{}.{}", resp[0], resp[1], resp[2]))
}
