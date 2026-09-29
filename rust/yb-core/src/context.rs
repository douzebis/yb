// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Runtime context shared across all CLI commands.

#[cfg(feature = "virtual-piv")]
use crate::piv::VirtualPiv;
use crate::{
    auxiliaries::{self, ProtectionMode},
    errors::{CardError, PcscCode, PcscOp, YbError},
    piv::{hardware::HardwarePiv, DeviceInfo, PivBackend},
    policy::{self, SecretOp},
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

/// Callback type for interactive device selection.
///
/// Returns the selected device together with an optional flash handle.  When
/// the picker has been flashing the LED of the chosen device, it may pass that
/// handle through so the flash continues uninterrupted into the next prompt.
pub type DevicePicker = Box<
    dyn Fn(
        &Arc<dyn PivBackend>,
        &[DeviceInfo],
    ) -> Result<Option<(DeviceInfo, Option<Box<dyn crate::piv::FlashHandle>>)>>,
>;

/// Plain configuration options for `Context::new`.
#[derive(Debug, Default)]
pub struct ContextOptions {
    pub serial: Option<u32>,
    pub reader: Option<String>,
    pub management_key: Option<String>,
    pub pin: Option<String>,
    pub allow_defaults: bool,
}

/// Where the management key used for writes came from (spec 0022 §1
/// step 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    /// `YB_MANAGEMENT_KEY` (or the deprecated `--key`).
    Explicit,
    /// PRINTED tag `89`.
    Printed,
    /// PRINTED tag `8A`: the previous key, kept during an interrupted switch.
    PrintedPrevious,
    /// The factory default, not stored anywhere.
    FactoryDefault,
}

impl KeySource {
    /// Whether the key was read from the PRINTED object.
    pub fn is_printed(self) -> bool {
        matches!(self, Self::Printed | Self::PrintedPrevious)
    }
}

/// What to do to PRINTED after resolving the management key.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PrintedRepair {
    #[default]
    None,
    /// Rewrite as `88 { 89 <key> }`, dropping a leftover tag `8A`.
    Rewrite,
    /// Delete: the card uses the factory key, which needs no storage.
    Delete,
}

/// Repairs due after resolving the management key (spec 0022 §1 step 4).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Repairs {
    /// ADMIN DATA does not record the stored key in the standard layout
    /// (legacy yb flag, or an interrupted `--protect`).
    pub flags: bool,
    pub printed: PrintedRepair,
}

impl Repairs {
    pub fn any(&self) -> bool {
        self.flags || self.printed != PrintedRepair::None
    }
}

/// What the resolver reports when no candidate key is accepted: the key
/// must be supplied (see [`Context::management_key_for_write`]).
pub const MANAGEMENT_KEY_NOT_FOUND: &str =
    "the management key is not in PRINTED and is not the factory default";

/// Outcome of [`Context::check_slot_key`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotKeyCheck {
    NoCertificate,
    Match,
    Mismatch,
}

struct ResolvedKey {
    key: Zeroizing<String>,
    source: KeySource,
    repairs: Repairs,
}

impl ResolvedKey {
    fn new(key: &str, source: KeySource, repairs: Repairs) -> Self {
        Self {
            key: Zeroizing::new(key.to_owned()),
            source,
            repairs,
        }
    }
}

pub struct Context {
    pub reader: String,
    pub serial: u32,
    /// Firmware version of the selected YubiKey, as reported by the device
    /// list (e.g. "5.4.3").  Only the unexpected-error report uses it.
    pub firmware: String,
    pub management_key: Option<String>,
    /// Which factory-default credentials were still active at startup.
    pub defaults: auxiliaries::DefaultCredentials,
    /// `--allow-defaults`: the default-credential policy warns instead of
    /// refusing (spec 0024 §3).
    pub allow_defaults: bool,
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
    /// How the management key is protected, from ADMIN DATA at startup.
    pub protection: ProtectionMode,
    /// The management key for writes, once resolved (see
    /// [`Context::management_key_for_write`]).
    resolved: RefCell<Option<ResolvedKey>>,
    /// Optional flash handle passed in from the interactive device picker.
    /// Kept alive so the LED continues to flash into the next prompt.
    /// Consumed by [`Context::take_flash`].
    pub flash_handle: Option<Box<dyn crate::piv::FlashHandle>>,
}

impl Context {
    /// Build a Context from global CLI options, selecting the device.
    ///
    /// `pin` is the PIN resolved from non-interactive sources (env var, stdin,
    /// deprecated flag).  `pin_fn` is called by `require_pin()` the first time
    /// a PIN is needed and `pin` is still `None` — typically a TTY prompt
    /// closure supplied by the application layer.
    pub fn new(
        opts: ContextOptions,
        pin_fn: Box<dyn Fn() -> Result<Option<String>>>,
        device_picker: DevicePicker,
        output: OutputOptions,
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

        let (device, selected_reader, flash_handle) = select_device(
            &devices,
            opts.serial.as_ref(),
            opts.reader.as_deref(),
            &piv,
            &*device_picker,
        )?;

        let (defaults, protection) = probe_card(&selected_reader, piv.as_ref());

        Ok(Self {
            reader: selected_reader,
            serial: device.serial,
            firmware: device.version.clone(),
            management_key: opts.management_key,
            defaults,
            allow_defaults: opts.allow_defaults,
            pin: initial_pin(opts.pin, &defaults),
            pin_fn,
            piv,
            debug,
            quiet,
            protection,
            resolved: RefCell::new(None),
            flash_handle,
        })
    }

    /// Build a `Context` from an explicit PIV backend.
    ///
    /// Use this when you have a `VirtualPiv` (for tests) or any other
    /// custom `PivBackend` implementation.  The backend must expose exactly
    /// one device; if it exposes none or more than one, an error is returned.
    ///
    /// The card is probed exactly as by [`Context::new`] (default
    /// credentials, protection mode).  `allow_defaults` starts false.
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
        let (defaults, protection) = probe_card(&reader, backend.as_ref());

        Ok(Self {
            reader,
            serial: device.serial,
            firmware: device.version.clone(),
            management_key: None,
            defaults,
            allow_defaults: false,
            pin: initial_pin(pin, &defaults),
            pin_fn: Box::new(|| Ok(None)),
            piv: backend,
            debug,
            quiet: false,
            protection,
            resolved: RefCell::new(None),
            flash_handle: None,
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

    /// The PIN known so far (from a non-interactive source, the factory
    /// default, or an earlier prompt), without prompting.
    pub fn known_pin(&self) -> Option<String> {
        self.pin.borrow().as_ref().map(|z| z.as_str().to_owned())
    }

    /// Replace the cached PIN, e.g. after changing it on the card.
    pub fn set_pin(&self, pin: &str) {
        *self.pin.borrow_mut() = Some(Zeroizing::new(pin.to_owned()));
    }

    /// Detect the factory-default credentials again, after changing some
    /// of them (spec 0023 §6).
    pub fn refresh_defaults(&mut self) {
        self.defaults = probe_card(&self.reader, self.piv.as_ref()).0;
    }

    /// Apply the default-credential policy for `op` (spec 0024): refuse
    /// with `Err`, or return the warnings that apply, printed unless
    /// `--quiet`.  Call once per command, before its first card write.
    pub fn enforce_default_policy(&self, op: SecretOp) -> Result<Vec<String>> {
        let warnings = policy::default_policy(op, &self.defaults, self.allow_defaults)?;
        if !self.quiet {
            for warning in &warnings {
                eprintln!("{warning}");
            }
        }
        Ok(warnings)
    }

    /// Fail if the card's management key protection is one yb cannot write
    /// with (PIN-derived, or unparseable ADMIN DATA).
    pub fn ensure_supported_protection(&self) -> Result<()> {
        match self.protection {
            ProtectionMode::Derived => Err(auxiliaries::pin_derived_unsupported().into()),
            ProtectionMode::Invalid => Err(YbError::new(
                "the YubiKey's ADMIN DATA object (0x5FFF00) cannot be parsed",
            )
            .why("yb does not write to a YubiKey whose management key setup it cannot read")
            .fix("inspect it with `ykman piv objects export 0x5fff00 -`")
            .into()),
            ProtectionMode::None
            | ProtectionMode::Standard
            | ProtectionMode::LegacyOrPukBlocked => Ok(()),
        }
    }

    /// Return the management key to use for write operations, after
    /// checking that the card accepts it (spec 0022 §1 step 4).
    ///
    /// This is the single place in yb that reads PRINTED for a key.  The
    /// first candidate the card accepts wins:
    /// 1. the explicit key (`YB_MANAGEMENT_KEY`) — if rejected, fail;
    /// 2. PRINTED tag `89`, then tag `8A` (kept during a key switch), when
    ///    a PIN is available — whatever the ADMIN DATA flags say;
    /// 3. the factory default.
    ///
    /// A key found in PRINTED may leave repairs due (see [`Repairs`]),
    /// carried out by [`Context::complete_pending_repairs`].  The result
    /// is cached for the rest of the invocation.
    pub fn management_key_for_write(&self) -> Result<String> {
        if let Some(r) = self.resolved.borrow().as_ref() {
            return Ok(r.key.to_string());
        }
        self.ensure_supported_protection()?;
        let resolved = self.resolve_management_key()?;
        let key = resolved.key.to_string();
        *self.resolved.borrow_mut() = Some(resolved);
        Ok(key)
    }

    fn resolve_management_key(&self) -> Result<ResolvedKey> {
        let piv = self.piv.as_ref();
        let accepts = |key: &str| piv.authenticate_management_key(&self.reader, key).is_ok();

        if let Some(ref key) = self.management_key {
            piv.authenticate_management_key(&self.reader, key)
                .context("the YubiKey rejected the management key from YB_MANAGEMENT_KEY")?;
            return Ok(ResolvedKey::new(
                key,
                KeySource::Explicit,
                Repairs::default(),
            ));
        }

        let printed = match self.require_pin()? {
            Some(pin) => {
                // Verify first, so that a wrong PIN is reported as such and
                // not mistaken for an empty PRINTED object.
                piv.verify_pin(&self.reader, &pin)?;
                auxiliaries::read_printed_keys(&self.reader, piv, &pin)?
            }
            None if matches!(
                self.protection,
                ProtectionMode::Standard | ProtectionMode::LegacyOrPukBlocked
            ) =>
            {
                return Err(YbError::new(
                    "a PIN is needed to read the management key kept on the YubiKey",
                )
                .fix("set YB_PIN, use --pin-stdin, or run yb in a terminal")
                .into())
            }
            None => auxiliaries::PrintedKeys::default(),
        };
        let has_printed_keys = printed.current.is_some() || printed.previous.is_some();

        let candidates = [
            (printed.current.as_deref(), KeySource::Printed),
            (printed.previous.as_deref(), KeySource::PrintedPrevious),
            (
                Some(auxiliaries::DEFAULT_MANAGEMENT_KEY),
                KeySource::FactoryDefault,
            ),
        ];
        for (key, source) in candidates {
            let Some(key) = key.filter(|k| accepts(k)) else {
                continue;
            };
            let repairs = if key == auxiliaries::DEFAULT_MANAGEMENT_KEY {
                // The factory key needs no protection: drop any key left in
                // PRINTED (e.g. a switch from the factory key that did not
                // take effect).
                Repairs {
                    flags: false,
                    printed: if has_printed_keys {
                        PrintedRepair::Delete
                    } else {
                        PrintedRepair::None
                    },
                }
            } else {
                Repairs {
                    flags: self.protection != ProtectionMode::Standard,
                    printed: if printed.previous.is_some() {
                        PrintedRepair::Rewrite
                    } else {
                        PrintedRepair::None
                    },
                }
            };
            return Ok(ResolvedKey::new(key, source, repairs));
        }
        Err(YbError::new(MANAGEMENT_KEY_NOT_FOUND)
            .fix("set YB_MANAGEMENT_KEY")
            .into())
    }

    /// Whether the management key is already PIN-protected (spec 0023
    /// §3a): PRINTED tag `89` holds the key the card accepts, however that
    /// key was obtained.  The factory key never counts as protected.
    ///
    /// Resolves the management key first.  When the key was given
    /// explicitly, PRINTED is read with the PIN, and the repairs a
    /// protected card needs (legacy flag, leftover tag `8A`) are recorded
    /// as for a key read from PRINTED.
    pub fn management_key_protected(&self) -> Result<bool> {
        let key = self.management_key_for_write()?;
        if key.eq_ignore_ascii_case(auxiliaries::DEFAULT_MANAGEMENT_KEY) {
            return Ok(false);
        }
        match self.management_key_source() {
            Some(KeySource::Printed) => Ok(true),
            Some(KeySource::Explicit) => {
                let Some(pin) = self.require_pin()? else {
                    return Ok(false);
                };
                self.piv.verify_pin(&self.reader, &pin)?;
                let printed =
                    auxiliaries::read_printed_keys(&self.reader, self.piv.as_ref(), &pin)?;
                let protected = printed
                    .current
                    .as_deref()
                    .is_some_and(|k| k.eq_ignore_ascii_case(&key));
                if protected {
                    if let Some(r) = self.resolved.borrow_mut().as_mut() {
                        r.repairs = Repairs {
                            flags: self.protection != ProtectionMode::Standard,
                            printed: if printed.previous.is_some() {
                                PrintedRepair::Rewrite
                            } else {
                                PrintedRepair::None
                            },
                        };
                    }
                }
                Ok(protected)
            }
            Some(KeySource::PrintedPrevious | KeySource::FactoryDefault) | None => Ok(false),
        }
    }

    /// Whether PRINTED holds the resolved management key, in tag `89` or
    /// `8A`, whatever the key's source (spec 0027 §3a).  A failed key
    /// switch puts it back there.
    pub fn management_key_in_printed(&self) -> Result<bool> {
        let key = self.management_key_for_write()?;
        match self.management_key_source() {
            Some(source) if source.is_printed() => Ok(true),
            Some(KeySource::Explicit) => {
                let Some(pin) = self.require_pin()? else {
                    return Ok(false);
                };
                self.piv.verify_pin(&self.reader, &pin)?;
                let printed =
                    auxiliaries::read_printed_keys(&self.reader, self.piv.as_ref(), &pin)?;
                Ok([printed.current, printed.previous]
                    .iter()
                    .flatten()
                    .any(|k| k.eq_ignore_ascii_case(&key)))
            }
            _ => Ok(false),
        }
    }

    /// Where the resolved management key came from, once resolved.
    pub fn management_key_source(&self) -> Option<KeySource> {
        self.resolved.borrow().as_ref().map(|r| r.source)
    }

    /// Repairs due from the management key resolution (none before it).
    pub fn pending_repairs(&self) -> Repairs {
        self.resolved
            .borrow()
            .as_ref()
            .map(|r| r.repairs)
            .unwrap_or_default()
    }

    /// Carry out the repairs found by [`Context::management_key_for_write`]:
    /// rewrite ADMIN DATA in the standard layout (spec 0021 §4) and/or
    /// clean up PRINTED (spec 0022 §1 step 4).
    ///
    /// Call once the command's own writes have succeeded.  A failure is a
    /// warning and does not fail the command: the next write retries.
    pub fn complete_pending_repairs(&self) {
        let (key, repairs) = match self.resolved.borrow_mut().as_mut() {
            Some(r) => (r.key.to_string(), std::mem::take(&mut r.repairs)),
            None => return,
        };
        let (reader, piv) = (self.reader.as_str(), self.piv.as_ref());
        let note = |msg: &str| {
            if !self.quiet {
                eprintln!("yb: note: {msg}");
            }
        };

        if repairs.flags {
            match auxiliaries::admin_data_with_stored_key(reader, piv, true)
                .and_then(|data| piv.write_object(reader, auxiliaries::OBJ_ADMIN_DATA, &data, &key))
            {
                Ok(()) if self.protection == ProtectionMode::LegacyOrPukBlocked => note(
                    "upgraded the stored management key metadata \
                     to the standard (ykman-compatible) layout",
                ),
                Ok(()) => note(
                    "repaired the stored management key metadata \
                     after an interrupted key switch",
                ),
                Err(e) => {
                    eprintln!("Warning: could not update the stored management key metadata: {e:#}")
                }
            }
        }

        let printed = match repairs.printed {
            PrintedRepair::None => return,
            PrintedRepair::Rewrite => auxiliaries::encode_printed(&key, None),
            PrintedRepair::Delete => Ok(Vec::new()),
        };
        match printed
            .and_then(|data| piv.write_object(reader, auxiliaries::OBJ_PRINTED, &data, &key))
        {
            Ok(()) => note("removed a management key left in PRINTED by an interrupted key switch"),
            Err(e) => eprintln!("Warning: could not clean up PRINTED: {e:#}"),
        }
    }

    /// Check that the key in `slot` matches the public key in the slot's
    /// certificate, by signing a random digest and verifying the signature
    /// (spec 0022 §1 step 5).  Needs the PIN.
    pub fn check_slot_key(&self, slot: u8) -> Result<SlotKeyCheck> {
        use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};

        let Ok(cert_der) = self.piv.read_certificate(&self.reader, slot) else {
            return Ok(SlotKeyCheck::NoCertificate);
        };
        let public_key = parse_ec_public_key_from_cert_der(&cert_der).with_context(|| {
            format!("the certificate in slot 0x{slot:02x} does not hold an EC P-256 key")
        })?;
        let digest: [u8; 32] = rand::random();
        let pin = self.require_pin()?;
        let raw = self
            .piv
            .ecdsa_sign(&self.reader, slot, &digest, pin.as_deref())
            .with_context(|| format!("signing with the key in slot 0x{slot:02x}"))?;
        let signature = Signature::from_slice(&raw).context("parsing the slot signature")?;
        let matches = VerifyingKey::from(&public_key)
            .verify_prehash(&digest, &signature)
            .is_ok();
        Ok(if matches {
            SlotKeyCheck::Match
        } else {
            SlotKeyCheck::Mismatch
        })
    }

    /// Take the flash handle passed in from the interactive device picker.
    ///
    /// Returns `Some(handle)` the first time it is called (if the picker
    /// provided one), and `None` on all subsequent calls.  The LED stops
    /// flashing when the returned handle is dropped.
    pub fn take_flash(&mut self) -> Option<Box<dyn crate::piv::FlashHandle>> {
        self.flash_handle.take()
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
// Card probe shared by both constructors
// ---------------------------------------------------------------------------

/// Read-only state probed when a `Context` is built: which credentials are
/// still at their factory values (unless `YB_SKIP_DEFAULT_CHECK` is set),
/// and how the management key is protected.  Nothing is enforced here:
/// unsupported protection modes are refused only when a management key is
/// needed, and default credentials per command (spec 0024).
fn probe_card(
    reader: &str,
    piv: &dyn PivBackend,
) -> (auxiliaries::DefaultCredentials, ProtectionMode) {
    let defaults = if std::env::var("YB_SKIP_DEFAULT_CHECK").is_ok() {
        auxiliaries::DefaultCredentials::default()
    } else {
        auxiliaries::detect_default_credentials(reader, piv)
    };
    (defaults, auxiliaries::detect_protection_mode(reader, piv))
}

/// The PIN a `Context` starts with: an explicit one always wins; otherwise
/// the factory PIN when the card reports it (spec 0024 §2a).
fn initial_pin(
    explicit: Option<String>,
    defaults: &auxiliaries::DefaultCredentials,
) -> RefCell<Option<Zeroizing<String>>> {
    let pin = explicit.or_else(|| defaults.pin.then(|| auxiliaries::DEFAULT_PIN.to_owned()));
    RefCell::new(pin.map(Zeroizing::new))
}

// ---------------------------------------------------------------------------
// Device selection
// ---------------------------------------------------------------------------

#[allow(clippy::type_complexity)]
fn select_device(
    devices: &[DeviceInfo],
    serial: Option<&u32>,
    reader: Option<&str>,
    piv: &Arc<dyn PivBackend>,
    device_picker: &dyn Fn(
        &Arc<dyn PivBackend>,
        &[DeviceInfo],
    ) -> Result<
        Option<(DeviceInfo, Option<Box<dyn crate::piv::FlashHandle>>)>,
    >,
) -> Result<(DeviceInfo, String, Option<Box<dyn crate::piv::FlashHandle>>)> {
    if let Some(s) = serial {
        let dev = devices.iter().find(|d| &d.serial == s).ok_or_else(|| {
            // Not echoing the serial: it would end up in pasted reports.
            YbError::new("no connected YubiKey has the requested serial number")
                .fix("`ykman list --serials` lists the connected YubiKeys")
        })?;
        return Ok((dev.clone(), dev.reader.clone(), None));
    }

    if let Some(r) = reader {
        let dev = devices.iter().find(|d| d.reader == r).ok_or_else(|| {
            YbError::new("no YubiKey on the requested reader")
                .fix("`yb list-readers` lists the readers")
        })?;
        return Ok((dev.clone(), r.to_owned(), None));
    }

    match devices.len() {
        0 => Err(CardError::Pcsc {
            op: PcscOp::ListReaders,
            code: PcscCode::NoReaders,
        }
        .into()),
        1 => Ok((devices[0].clone(), devices[0].reader.clone(), None)),
        _ => {
            // Multiple devices: invoke the picker (interactive or fallback).
            match device_picker(piv, devices)? {
                Some((dev, flash)) => {
                    let reader = dev.reader.clone();
                    Ok((dev, reader, flash))
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
pub fn parse_ec_public_key_from_cert_der(cert_der: &[u8]) -> Result<PublicKey> {
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "virtual-piv"))]
mod tests {
    use super::*;

    /// `YB_SKIP_DEFAULT_CHECK` disables detection in both constructors
    /// (spec 0024 §3).  This is the only test in this binary that builds a
    /// `Context`, so setting the process-wide variable cannot race.
    #[test]
    fn skip_default_check_disables_detection() {
        // VirtualPiv::new() keeps every factory credential.
        let piv: Arc<dyn PivBackend> = Arc::new(VirtualPiv::new());
        let ctx = Context::with_backend(piv.clone(), None, false).unwrap();
        assert!(ctx.defaults.any());
        assert_eq!(ctx.require_pin().unwrap().as_deref(), Some("123456"));

        std::env::set_var("YB_SKIP_DEFAULT_CHECK", "1");
        let ctx = Context::with_backend(piv, None, false);
        std::env::remove_var("YB_SKIP_DEFAULT_CHECK");
        let ctx = ctx.unwrap();
        assert!(!ctx.defaults.any());
        assert_eq!(ctx.require_pin().unwrap(), None, "no PIN filled in");
        assert!(ctx
            .enforce_default_policy(SecretOp::Store)
            .unwrap()
            .is_empty());
    }
}
