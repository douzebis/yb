// SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Runtime context shared across all CLI commands.

use crate::{
    auxiliaries,
    piv::{hardware::HardwarePiv, DeviceInfo, PivBackend},
};
use anyhow::{bail, Context as _, Result};
use p256::{pkcs8::DecodePublicKey, PublicKey};
use std::process::Command;
use std::sync::Arc;

pub struct Context {
    pub reader: String,
    pub serial: u32,
    pub management_key: Option<String>,
    pub pin: Option<String>,
    pub piv: Arc<dyn PivBackend>,
    pub debug: bool,
    pub pin_protected: bool,
}

impl Context {
    /// Build a Context from global CLI options, selecting the device.
    pub fn new(
        serial: Option<u32>,
        reader: Option<String>,
        management_key: Option<String>,
        pin: Option<String>,
        debug: bool,
        allow_defaults: bool,
    ) -> Result<Self> {
        let piv: Arc<dyn PivBackend> = Arc::new(HardwarePiv::new());

        let devices = piv.list_devices().context("listing YubiKey devices")?;

        let (device, selected_reader) =
            select_device(&devices, serial.as_ref(), reader.as_deref())?;

        // Check for default credentials unless skipped by environment.
        if std::env::var("YB_SKIP_DEFAULT_CHECK").is_err() {
            auxiliaries::check_for_default_credentials(
                &selected_reader,
                piv.as_ref(),
                allow_defaults,
            )?;
        }

        let (pin_protected, pin_derived) =
            auxiliaries::detect_pin_protected_mode(&selected_reader, piv.as_ref())
                .unwrap_or((false, false));

        if pin_derived {
            bail!(
                "PIN-derived management key mode is deprecated and not supported. \
                 Please migrate to PIN-protected mode."
            );
        }

        Ok(Self {
            reader: selected_reader,
            serial: device.serial,
            management_key,
            pin,
            piv,
            debug,
            pin_protected,
        })
    }

    /// Return the management key to use for write operations.
    ///
    /// Priority: explicit --key > PIN-protected retrieval > None (use default).
    pub fn management_key_for_write(&self) -> Result<Option<String>> {
        if let Some(ref k) = self.management_key {
            return Ok(Some(k.clone()));
        }
        if self.pin_protected {
            let pin = self.pin.as_deref().ok_or_else(|| {
                anyhow::anyhow!("PIN required to retrieve PIN-protected management key")
            })?;
            let key = auxiliaries::get_pin_protected_management_key(
                &self.reader,
                self.piv.as_ref(),
                pin,
            )?;
            return Ok(Some(key));
        }
        Ok(None)
    }

    /// Retrieve the YubiKey's public key from the given PIV slot.
    pub fn get_public_key(&self, slot: u8) -> Result<PublicKey> {
        let slot_hex = format!("{slot:02x}");

        // Read the certificate from the YubiKey via yubico-piv-tool.
        let out = Command::new("yubico-piv-tool")
            .args([
                "--reader",
                &self.reader,
                "--slot",
                &slot_hex,
                "--action",
                "read-certificate",
            ])
            .output()
            .context("running yubico-piv-tool read-certificate")?;

        if !out.status.success() {
            bail!(
                "yubico-piv-tool read-certificate failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }

        // Parse the PEM certificate and extract the public key.
        let cert_pem = std::str::from_utf8(&out.stdout).context("certificate is not UTF-8")?;
        parse_ec_public_key_from_cert_pem(cert_pem)
    }
}

// ---------------------------------------------------------------------------
// Device selection
// ---------------------------------------------------------------------------

fn select_device<'a>(
    devices: &'a [DeviceInfo],
    serial: Option<&u32>,
    reader: Option<&str>,
) -> Result<(&'a DeviceInfo, String)> {
    if let Some(s) = serial {
        let dev = devices
            .iter()
            .find(|d| &d.serial == s)
            .ok_or_else(|| anyhow::anyhow!("no YubiKey with serial {s} found"))?;
        return Ok((dev, dev.reader.clone()));
    }

    if let Some(r) = reader {
        let dev = devices
            .iter()
            .find(|d| d.reader == r)
            .ok_or_else(|| anyhow::anyhow!("no device on reader '{r}'"))?;
        return Ok((dev, r.to_owned()));
    }

    match devices.len() {
        0 => bail!("no YubiKey found"),
        1 => Ok((&devices[0], devices[0].reader.clone())),
        _ => {
            // Multiple devices: print list and ask user to specify.
            eprintln!("Multiple YubiKeys found. Use --serial to select one:");
            for d in devices {
                eprintln!(
                    "  serial={} version={} reader={}",
                    d.serial, d.version, d.reader
                );
            }
            bail!("ambiguous device selection — use --serial or --reader");
        }
    }
}

// ---------------------------------------------------------------------------
// Certificate / public-key parsing
// ---------------------------------------------------------------------------

/// Extract the EC P-256 public key from a PEM-encoded X.509 certificate.
/// Uses `openssl x509` subprocess to keep the dependency footprint small
/// (avoids pulling in a full X.509 parser crate for now).
fn parse_ec_public_key_from_cert_pem(cert_pem: &str) -> Result<PublicKey> {
    use std::io::Write as _;

    // Write cert to a temp file, then extract the SubjectPublicKeyInfo in DER.
    let mut cert_file = tempfile::NamedTempFile::new()?;
    cert_file.write_all(cert_pem.as_bytes())?;

    let out = Command::new("openssl")
        .args([
            "x509",
            "-noout",
            "-pubkey",
            "-in",
            cert_file.path().to_str().unwrap(),
        ])
        .output()
        .context("running openssl x509 -pubkey")?;

    if !out.status.success() {
        bail!(
            "openssl x509 -pubkey failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // `openssl x509 -pubkey` outputs PEM-encoded SubjectPublicKeyInfo.
    let pubkey_pem = std::str::from_utf8(&out.stdout)?;
    let pk = p256::PublicKey::from_public_key_pem(pubkey_pem.trim())
        .map_err(|e| anyhow::anyhow!("parsing public key PEM: {e}"))?;
    Ok(pk)
}
