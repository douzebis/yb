// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Runtime context shared across all CLI commands.

#[cfg(feature = "virtual-piv")]
use crate::piv::VirtualPiv;
use crate::{
    auxiliaries,
    piv::{hardware::HardwarePiv, DeviceInfo, PivBackend},
};
use anyhow::{bail, Context as _, Result};
use p256::PublicKey;
use std::cell::RefCell;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Output-control flags passed to `Context::new`.
#[derive(Debug, Clone, Copy, Default)]
pub struct OutputOptions {
    pub debug: bool,
    pub quiet: bool,
}

pub struct Context {
    pub reader: String,
    pub serial: u32,
    pub management_key: Option<String>,
    /// Cached PIN.  Starts as `None` when no non-interactive source provided
    /// one; populated on the first call to `require_pin()`.
    /// Wrapped in `Zeroizing` so the bytes are overwritten on drop.
    pin: RefCell<Option<Zeroizing<String>>>,
    /// Called by `require_pin()` when `pin` is still `None`.
    /// Returns `Some(pin)` if it can supply one, `None` otherwise.
    pin_fn: Box<dyn Fn() -> Result<Option<String>>>,
    pub piv: Arc<dyn PivBackend>,
    pub debug: bool,
    pub quiet: bool,
    pub pin_protected: bool,
}

impl Context {
    /// Build a Context from global CLI options, selecting the device.
    ///
    /// `pin` is the PIN resolved from non-interactive sources (env var, stdin,
    /// deprecated flag).  `pin_fn` is called by `require_pin()` the first time
    /// a PIN is needed and `pin` is still `None` — typically a TTY prompt
    /// closure supplied by the application layer.
    pub fn new(
        serial: Option<u32>,
        reader: Option<String>,
        management_key: Option<String>,
        pin: Option<String>,
        pin_fn: Box<dyn Fn() -> Result<Option<String>>>,
        device_picker: Box<
            dyn Fn(&Arc<dyn PivBackend>, &[DeviceInfo]) -> Result<Option<DeviceInfo>>,
        >,
        output: OutputOptions,
        allow_defaults: bool,
    ) -> Result<Self> {
        let debug = output.debug;
        let quiet = output.quiet;
        #[cfg(feature = "virtual-piv")]
        let piv: Arc<dyn PivBackend> = if let Ok(path) = std::env::var("YB_FIXTURE") {
            Arc::new(VirtualPiv::from_fixture(std::path::Path::new(&path))?)
        } else {
            Arc::new(HardwarePiv::new())
        };
        #[cfg(not(feature = "virtual-piv"))]
        let piv: Arc<dyn PivBackend> = Arc::new(HardwarePiv::new());

        let devices = piv.list_devices().context("listing YubiKey devices")?;

        let (device, selected_reader) = select_device(
            &devices,
            serial.as_ref(),
            reader.as_deref(),
            &piv,
            &*device_picker,
        )?;

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

        reject_pin_derived(pin_derived)?;

        Ok(Self {
            reader: selected_reader,
            serial: device.serial,
            management_key,
            pin: RefCell::new(pin.map(Zeroizing::new)),
            pin_fn,
            piv,
            debug,
            quiet,
            pin_protected,
        })
    }

    /// Build a `Context` from an explicit PIV backend.
    ///
    /// Use this when you have a `VirtualPiv` (for tests) or any other
    /// custom `PivBackend` implementation.  The backend must expose exactly
    /// one device; if it exposes none or more than one, an error is returned.
    ///
    /// Default-credential and PIN-derived-key checks are skipped (the caller
    /// controls the backend and is assumed to have configured it correctly).
    pub fn with_backend(
        backend: Arc<dyn PivBackend>,
        pin: Option<String>,
        debug: bool,
    ) -> Result<Self> {
        let devices = backend
            .list_devices()
            .context("listing devices in backend")?;
        let device = match devices.as_slice() {
            [] => bail!("no device found in backend"),
            [d] => d.clone(),
            _ => bail!("multiple devices in backend — use Context::new with --serial"),
        };
        let reader = device.reader.clone();

        let (pin_protected, pin_derived) =
            auxiliaries::detect_pin_protected_mode(&reader, backend.as_ref())
                .unwrap_or((false, false));

        reject_pin_derived(pin_derived)?;

        Ok(Self {
            reader,
            serial: device.serial,
            management_key: None,
            pin: RefCell::new(pin.map(Zeroizing::new)),
            pin_fn: Box::new(|| Ok(None)),
            piv: backend,
            debug,
            quiet: false,
            pin_protected,
        })
    }

    /// Return the PIN, invoking `pin_fn` on first call if not yet resolved.
    ///
    /// Resolution order:
    /// 1. Already-cached PIN (from a non-interactive source or a prior call).
    /// 2. `pin_fn()` — supplied by the caller of `Context::new`; typically a
    ///    TTY prompt closure in the application layer.  The result is cached so
    ///    subsequent calls never invoke `pin_fn` again.
    /// 3. `None` — the caller must decide whether to error.
    pub fn require_pin(&self) -> Result<Option<String>> {
        if self.pin.borrow().is_some() {
            return Ok(self.pin.borrow().as_ref().map(|z| z.as_str().to_owned()));
        }
        let resolved = (self.pin_fn)()?;
        *self.pin.borrow_mut() = resolved.as_deref().map(|s| Zeroizing::new(s.to_owned()));
        Ok(resolved)
    }

    /// Return the management key to use for write operations.
    ///
    /// Priority: explicit --key > PIN-protected retrieval > None (use default).
    pub fn management_key_for_write(&self) -> Result<Option<String>> {
        if let Some(ref k) = self.management_key {
            return Ok(Some(k.clone()));
        }
        if self.pin_protected {
            let pin = self.require_pin()?.ok_or_else(|| {
                anyhow::anyhow!("PIN required to retrieve PIN-protected management key")
            })?;
            let key = auxiliaries::get_pin_protected_management_key(
                &self.reader,
                self.piv.as_ref(),
                &pin,
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

fn reject_pin_derived(pin_derived: bool) -> Result<()> {
    if pin_derived {
        bail!(
            "PIN-derived management key mode is deprecated and not supported. \
             Please migrate to PIN-protected mode."
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Device selection
// ---------------------------------------------------------------------------

fn select_device(
    devices: &[DeviceInfo],
    serial: Option<&u32>,
    reader: Option<&str>,
    piv: &Arc<dyn PivBackend>,
    device_picker: &dyn Fn(&Arc<dyn PivBackend>, &[DeviceInfo]) -> Result<Option<DeviceInfo>>,
) -> Result<(DeviceInfo, String)> {
    if let Some(s) = serial {
        let dev = devices
            .iter()
            .find(|d| &d.serial == s)
            .ok_or_else(|| anyhow::anyhow!("no YubiKey with serial {s} found"))?;
        return Ok((dev.clone(), dev.reader.clone()));
    }

    if let Some(r) = reader {
        let dev = devices
            .iter()
            .find(|d| d.reader == r)
            .ok_or_else(|| anyhow::anyhow!("no device on reader '{r}'"))?;
        return Ok((dev.clone(), r.to_owned()));
    }

    match devices.len() {
        0 => bail!("no YubiKey found"),
        1 => Ok((devices[0].clone(), devices[0].reader.clone())),
        _ => {
            // Multiple devices: invoke the picker (interactive or fallback).
            match device_picker(piv, devices)? {
                Some(dev) => {
                    let reader = dev.reader.clone();
                    Ok((dev, reader))
                }
                None => bail!("device selection cancelled"),
            }
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
    let pk: Option<p256::PublicKey> = p256::PublicKey::from_encoded_point(&encoded).into();
    pk.ok_or_else(|| anyhow::anyhow!("EC point in certificate is not on P-256 curve"))
}
