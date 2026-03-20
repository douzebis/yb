// SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Runtime context shared across all CLI commands.

use crate::{
    auxiliaries,
    piv::{hardware::HardwarePiv, DeviceInfo, PivBackend},
};
use anyhow::{bail, Context as _, Result};
use p256::PublicKey;
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
        let cert_der = self
            .piv
            .read_certificate(&self.reader, slot)
            .with_context(|| format!("reading certificate from slot 0x{slot:02x}"))?;
        parse_ec_public_key_from_cert_der(&cert_der)
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

/// Extract the EC P-256 public key from a DER-encoded X.509 certificate.
fn parse_ec_public_key_from_cert_der(cert_der: &[u8]) -> Result<PublicKey> {
    use der::Decode;
    use p256::elliptic_curve::sec1::FromEncodedPoint;
    use x509_cert::Certificate;

    let cert = Certificate::from_der(cert_der).context("parsing DER certificate")?;

    // SubjectPublicKeyInfo → raw bit string → uncompressed EC point.
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let point_bytes = spki.subject_public_key.as_bytes().ok_or_else(|| {
        anyhow::anyhow!("certificate SubjectPublicKeyInfo: unexpected bit-string encoding")
    })?;

    let encoded = p256::EncodedPoint::from_bytes(point_bytes)
        .map_err(|e| anyhow::anyhow!("parsing EC point from SPKI: {e}"))?;
    let pk = p256::PublicKey::from_encoded_point(&encoded);
    if pk.is_none().into() {
        bail!("EC point in certificate is not on P-256 curve");
    }
    Ok(pk.unwrap())
}
