// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Read-only report on the state of a YubiKey (spec 0023 §1), shared by
//! `yb fsck` and the guided `yb format`, by application: PIV, then FIDO2,
//! each with its role for the store (spec 0045).
//!
//! Building a report sends read-only APDUs only and needs no PIN.  The
//! key/certificate match check, which needs the PIN, is added by the
//! caller.

use crate::auxiliaries::ProtectionMode;
use crate::context::{Context, SlotKeyCheck};
use crate::piv::mgmt::{
    get_metadata_apdu, key_algorithm_name, parse_credential_metadata, parse_mgmt_metadata,
    parse_slot_metadata, CredentialMetadata, KeyOrigin, MgmtMetadata, SlotMetadata, TouchPolicy,
    ALGO_ECCP256, GET_METADATA_MGMT, GET_METADATA_PIN, GET_METADATA_PUK,
};
use crate::piv::PivBackend;
use crate::store::{constants::OBJECT_ID_ZERO, Store};

/// How serious a report item is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Ok,
    Warning,
    Error,
}

/// The certificate of the store slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotCertificate {
    None,
    /// An EC P-256 certificate, with its subject.
    P256 {
        subject: String,
    },
    /// A certificate for another key type (e.g. RSA).
    NotP256 {
        subject: String,
    },
    /// Data that does not parse as a certificate.
    Unparseable,
}

/// The store slot: its key (as GET METADATA reports it) and certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotReport {
    pub slot: u8,
    /// `None` when the slot is empty, or the firmware cannot tell.
    pub key: Option<SlotMetadata>,
    pub certificate: SlotCertificate,
}

impl SlotReport {
    /// The slot holds something yb would replace: a key or a certificate.
    pub fn is_occupied(&self) -> bool {
        self.key.is_some() || self.certificate != SlotCertificate::None
    }

    /// The certificate exists but does not hold an EC P-256 key.
    pub fn certificate_unusable(&self) -> bool {
        matches!(
            self.certificate,
            SlotCertificate::NotP256 { .. } | SlotCertificate::Unparseable
        )
    }
}

/// Whether a store exists (spec 0023 §1).
pub enum StorePresence {
    None,
    Present(Store),
    /// Object 0 exists but the store cannot be parsed.
    Unreadable(String),
}

impl StorePresence {
    /// Read the store, telling "no store" from "unreadable store".
    pub fn probe(reader: &str, piv: &dyn PivBackend) -> Self {
        match Store::from_device_raw(reader, piv) {
            Ok(store) => Self::Present(store),
            Err(e) => match piv.object_size(reader, OBJECT_ID_ZERO) {
                Ok(Some(_)) => Self::Unreadable(format!("{e:#}")),
                _ => Self::None,
            },
        }
    }
}

/// The store the report is about, which sets each application's role
/// (spec 0045).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportStore {
    /// No store (yet): the guided format, or `fsck` on a bare YubiKey.
    None,
    /// A legacy store: the PIV application protects it.
    Legacy,
    /// A post-quantum store: the PIV application holds its objects, the
    /// FIDO2 application protects it.
    PostQuantum,
}

/// The FIDO2 PIN, as read without using an attempt (spec 0045).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fido2State {
    /// A PIN is set, with this many attempts left.
    Pin { retries: u32 },
    /// No PIN: the FIDO2 application was reset, or never set up.
    PinNotSet,
    /// The FIDO2 side could not be read: why.
    Unreachable(String),
}

/// The FIDO2 application, for a post-quantum store (spec 0045).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fido2Report {
    pub state: Fido2State,
    /// The length of the store's credential ID.
    pub credential_id_len: usize,
    /// The credential is checked further on (`fsck --seals`).
    pub checked_below: bool,
    /// The store has unencrypted blobs, readable with `--no-check` (spec
    /// 0044) whatever the FIDO2 PIN's state.
    pub unencrypted_blobs: bool,
}

/// The FIDO2 state of the YubiKey of `ctx`, without a PIN, a touch, or an
/// attempt used: the device is used only when it is identified without a
/// touch (spec 0045).
#[cfg(not(windows))]
pub fn fido2_state(ctx: &Context) -> Fido2State {
    let piv_yubikeys = ctx.piv.list_devices().map(|d| d.len()).unwrap_or(1);
    match crate::fido2::pairing::open_without_touch(ctx.serial, piv_yubikeys) {
        Ok(Some(dev)) if !dev.has_pin() => Fido2State::PinNotSet,
        Ok(Some(dev)) => match dev.pin_retries() {
            Ok(retries) => Fido2State::Pin { retries },
            Err(e) => Fido2State::Unreachable(format!("{e:#}")),
        },
        Ok(None) => Fido2State::Unreachable(
            "several FIDO2 security keys are connected; yb tells them apart only with a touch"
                .to_owned(),
        ),
        Err(e) => Fido2State::Unreachable(format!("{e:#}")),
    }
}

#[cfg(windows)]
pub fn fido2_state(_: &Context) -> Fido2State {
    Fido2State::Unreachable("post-quantum stores are not supported on Windows".to_owned())
}

/// One line of the YubiKey section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub label: String,
    pub text: String,
    pub severity: Severity,
    /// Advice shown under the line by `yb fsck` (spec 0027 §8).
    pub hint: Vec<String>,
}

/// The state of a YubiKey, from read-only APDUs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardReport {
    pub serial: u32,
    pub firmware: String,
    /// `None` on firmware without GET METADATA (< 5.3).
    pub pin: Option<CredentialMetadata>,
    pub puk: Option<CredentialMetadata>,
    pub management_key: Option<MgmtMetadata>,
    pub protection: ProtectionMode,
    pub slot: SlotReport,
    /// The key/certificate match check, when the caller ran it.
    pub key_check: Option<SlotKeyCheck>,
    /// The store, which sets each application's role.  A post-quantum
    /// store (spec 0028) has no store slot, so no slot and key/certificate
    /// lines.
    pub store: ReportStore,
    /// The FIDO2 application, filled by the caller for a post-quantum
    /// store.
    pub fido2: Option<Fido2Report>,
}

impl CardReport {
    /// Build the report for the YubiKey of `ctx`, with `slot` as the store
    /// slot.  Read-only; no PIN.
    pub fn build(ctx: &Context, slot: u8) -> Self {
        let (reader, piv) = (ctx.reader.as_str(), ctx.piv.as_ref());
        let metadata = |apdu: &[u8]| piv.send_apdu(reader, apdu).ok();
        Self {
            serial: ctx.serial,
            firmware: ctx.firmware.clone(),
            pin: metadata(&GET_METADATA_PIN).and_then(|d| parse_credential_metadata(&d).ok()),
            puk: metadata(&GET_METADATA_PUK).and_then(|d| parse_credential_metadata(&d).ok()),
            management_key: metadata(&GET_METADATA_MGMT).and_then(|d| parse_mgmt_metadata(&d).ok()),
            protection: ctx.protection,
            slot: SlotReport {
                slot,
                key: metadata(&get_metadata_apdu(slot)).and_then(|d| parse_slot_metadata(&d).ok()),
                certificate: read_slot_certificate(reader, piv, slot),
            },
            key_check: None,
            store: ReportStore::None,
            fido2: None,
        }
    }

    /// The firmware reports PIN, PUK and management key metadata (5.3+).
    pub fn has_metadata(&self) -> bool {
        self.pin.is_some()
    }

    pub fn pin_blocked(&self) -> bool {
        self.pin.is_some_and(|m| m.retries_left == 0)
    }

    pub fn puk_blocked(&self) -> bool {
        self.puk.is_some_and(|m| m.retries_left == 0)
    }

    /// The PIV application's lines, in display order.  `key_check_hint`
    /// is shown on the Key/certificate line when the check did not run;
    /// `None` omits the line.
    pub fn items(&self, key_check_hint: Option<&str>) -> Vec<Item> {
        let mut pin = credential_item("PIN", self.pin);
        if self.store == ReportStore::PostQuantum {
            pin.text.push_str(" — not used by this store");
        }
        let mut items = vec![
            pin,
            credential_item("PUK", self.puk),
            self.management_key_item(),
        ];
        if self.store == ReportStore::PostQuantum {
            return items;
        }
        items.push(self.slot_item());
        let check = match self.key_check {
            Some(SlotKeyCheck::Match) => Some(("match".to_owned(), Severity::Ok)),
            Some(SlotKeyCheck::Mismatch) => Some((
                "the key does not match its certificate".to_owned(),
                Severity::Error,
            )),
            Some(SlotKeyCheck::NoCertificate) => Some(("no certificate".to_owned(), Severity::Ok)),
            None => key_check_hint.map(|hint| (format!("not checked ({hint})"), Severity::Ok)),
        };
        if let Some((text, severity)) = check {
            items.push(item("Key/certificate", text, severity));
        }
        items
    }

    /// The FIDO2 application's lines (post-quantum stores).
    pub fn fido2_items(&self) -> Vec<Item> {
        let Some(f) = &self.fido2 else {
            return Vec::new();
        };
        let no_check = || {
            vec![
                "Its unencrypted blobs stay readable without the FIDO2 PIN:".to_owned(),
                "yb fetch --no-check NAME (checksum only, spec 0044)".to_owned(),
            ]
        };
        let mut pin = match &f.state {
            Fido2State::Pin { retries: 0 } => {
                let mut i = item(
                    "PIN",
                    format!(
                        "blocked, 0/{FIDO2_MAX_TRIES} tries left (a FIDO2 reset clears it, and \
                         destroys this store's encrypted blobs)"
                    ),
                    Severity::Error,
                );
                if f.unencrypted_blobs {
                    i.hint = no_check();
                }
                i
            }
            Fido2State::Pin { retries } if *retries <= 3 => {
                let mut i = item(
                    "PIN",
                    format!("set, {retries}/{FIDO2_MAX_TRIES} tries left"),
                    Severity::Warning,
                );
                i.hint = vec![
                    "yb does not try it with so few left: a FIDO2 PIN with no attempt".to_owned(),
                    "left is blocked for good (--allow-low-pin-attempts overrides).".to_owned(),
                ];
                i
            }
            Fido2State::Pin { retries } => item(
                "PIN",
                format!("set, {retries}/{FIDO2_MAX_TRIES} tries left"),
                Severity::Ok,
            ),
            Fido2State::PinNotSet => {
                let mut i = item("PIN", "not set (FIDO2 reset?)".to_owned(), Severity::Error);
                if f.unencrypted_blobs {
                    i.hint = no_check();
                }
                i
            }
            Fido2State::Unreachable(why) => {
                let mut i = item("PIN", format!("not reachable ({why})"), Severity::Error);
                if f.unencrypted_blobs {
                    i.hint = no_check();
                }
                i
            }
        };
        if !pin.hint.is_empty() && pin.severity == Severity::Ok {
            pin.hint.clear();
        }
        let checked = if f.checked_below {
            "checked below"
        } else {
            "not checked (needs the FIDO2 PIN)"
        };
        vec![
            pin,
            item(
                "Credential",
                format!("the store's: {}-byte ID, {checked}", f.credential_id_len),
                Severity::Ok,
            ),
        ]
    }

    /// The most serious severity among the items of both applications.
    pub fn severity(&self) -> Severity {
        self.items(None)
            .iter()
            .chain(self.fido2_items().iter())
            .map(|i| i.severity)
            .max()
            .unwrap_or(Severity::Ok)
    }

    /// The YubiKey section (spec 0023 §2), by application (spec 0045): one
    /// line per item, followed by the item's hint lines when `hints` is set.
    pub fn render(&self, key_check_hint: Option<&str>, hints: bool) -> String {
        let mut out = format!("YubiKey {} — firmware {}\n", self.serial, self.firmware);
        let (piv_role, fido2_role) = match self.store {
            ReportStore::None => ("", None),
            ReportStore::Legacy => (" — protects this store", Some(" — not used by this store")),
            ReportStore::PostQuantum => (
                " — holds the store's objects",
                Some(" — protects this store"),
            ),
        };
        out.push_str(&format!("\nPIV application{piv_role}\n"));
        render_items(&mut out, &self.items(key_check_hint), hints);
        if let Some(role) = fido2_role {
            out.push_str(&format!("\nFIDO2 application{role}\n"));
            render_items(&mut out, &self.fido2_items(), hints);
        }
        out
    }

    fn management_key_item(&self) -> Item {
        const LABEL: &str = "Management key";
        let algo = match self.management_key {
            Some(md) => md.algo.to_string(),
            None => "unknown algorithm (firmware < 5.3)".to_owned(),
        };
        let (protection, mut severity) = match self.protection {
            ProtectionMode::Standard => (
                "kept on the YubiKey (PRINTED), unlocked by the PIV PIN",
                Severity::Ok,
            ),
            ProtectionMode::LegacyOrPukBlocked => (
                "ADMIN DATA flag 0x01 (key kept on the YubiKey by yb ≤ 0.4.x, or blocked PUK)",
                Severity::Warning,
            ),
            // The factory key needs no storing: "factory default" says it all.
            ProtectionMode::None if self.management_key.is_some_and(|md| md.is_default) => {
                ("", Severity::Ok)
            }
            ProtectionMode::None => ("not stored on the YubiKey", Severity::Ok),
            ProtectionMode::Derived => {
                return item(
                    LABEL,
                    format!("{algo}, PIN-derived (deprecated; yb does not support it)"),
                    Severity::Error,
                )
            }
            ProtectionMode::Invalid => {
                return item(
                    LABEL,
                    format!("{algo}, ADMIN DATA (0x5FFF00) cannot be parsed"),
                    Severity::Error,
                )
            }
        };
        // The state first, as for the PINs (spec 0051 S4).
        let mut parts = Vec::new();
        match self.management_key {
            Some(md) if md.is_default => {
                parts.push("factory default".to_owned());
                severity = severity.max(Severity::Warning);
            }
            Some(_) => parts.push("set".to_owned()),
            None => {}
        }
        parts.push(algo);
        if !protection.is_empty() {
            parts.push(protection.to_owned());
        }
        if let Some(md) = self.management_key {
            match md.touch {
                TouchPolicy::Always => {
                    parts.push("touch always required".to_owned());
                    severity = severity.max(Severity::Warning);
                }
                TouchPolicy::Cached => parts.push("touch required (cached)".to_owned()),
                TouchPolicy::Never => {}
            }
        }
        let mut item = item(LABEL, parts.join(", "), severity);
        // A key yb must be given each time: say it could keep it (spec
        // 0027 §8).  The factory key needs no keeping.
        if self.protection == ProtectionMode::None
            && self.management_key.is_some_and(|md| !md.is_default)
        {
            item.hint = vec![
                "yb store and yb remove need it each time (YB_MANAGEMENT_KEY).".to_owned(),
                "To have yb keep it on the YubiKey, unlocked by your PIN:".to_owned(),
                "yb rotate-management-key".to_owned(),
            ];
        }
        item
    }

    fn slot_item(&self) -> Item {
        const LABEL: &str = "Store key";
        let slot = format!("slot 0x{:02x}:", self.slot.slot);
        let mut parts = Vec::new();
        if let Some(key) = self.slot.key {
            parts.push(key_algorithm_name(key.algorithm));
            match key.origin {
                Some(KeyOrigin::Generated) => parts.push("generated on card".to_owned()),
                Some(KeyOrigin::Imported) => parts.push("imported".to_owned()),
                None => {}
            }
        }
        let mut severity = Severity::Ok;
        match &self.slot.certificate {
            SlotCertificate::None if self.slot.key.is_some() => {
                parts.push("no certificate".to_owned())
            }
            SlotCertificate::None => parts.push("empty".to_owned()),
            SlotCertificate::P256 { subject } => parts.push(format!("certificate {subject}")),
            SlotCertificate::NotP256 { subject } => {
                parts.push(format!(
                    "certificate {subject} does not hold an EC P-256 key"
                ));
                severity = Severity::Error;
            }
            SlotCertificate::Unparseable => {
                parts.push("the certificate cannot be parsed".to_owned());
                severity = Severity::Error;
            }
        }
        if self.slot.key.is_some_and(|k| k.algorithm != ALGO_ECCP256) {
            severity = Severity::Error;
        }
        item(LABEL, format!("{slot} {}", parts.join(", ")), severity)
    }
}

/// Items as report lines, each followed by its hint when `hints` is set.
fn render_items(out: &mut String, items: &[Item], hints: bool) {
    for i in items {
        let text = match i.severity {
            Severity::Ok => i.text.clone(),
            Severity::Warning => format!("warning: {}", i.text),
            Severity::Error => format!("ERROR: {}", i.text),
        };
        out.push_str(&format!("  {:<16} {text}\n", i.label));
        if hints {
            for line in &i.hint {
                out.push_str(&format!("  {:<16} {line}\n", ""));
            }
        }
    }
}

fn item(label: &str, text: String, severity: Severity) -> Item {
    Item {
        label: label.to_owned(),
        text,
        severity,
        hint: Vec::new(),
    }
}

/// The FIDO2 PIN's tries on a YubiKey, which CTAP 2 sets (the YubiKey does
/// not report it).
const FIDO2_MAX_TRIES: u32 = 8;

fn credential_item(label: &str, md: Option<CredentialMetadata>) -> Item {
    let Some(md) = md else {
        return item(label, "unknown (firmware < 5.3)".to_owned(), Severity::Ok);
    };
    // The state first, then the tries (spec 0051 S4).
    let tries = format!("{}/{} tries left", md.retries_left, md.retries_total);
    if md.retries_left == 0 {
        // A blocked PUK only stops PIN resets: not an error.
        let severity = if label == "PIN" {
            Severity::Error
        } else {
            Severity::Warning
        };
        return item(label, format!("blocked, {tries}"), severity);
    }
    if md.is_default {
        return item(
            label,
            format!("factory default, {tries}"),
            Severity::Warning,
        );
    }
    item(label, format!("set, {tries}"), Severity::Ok)
}

fn read_slot_certificate(reader: &str, piv: &dyn PivBackend, slot: u8) -> SlotCertificate {
    use der::Decode;
    use x509_cert::Certificate;

    let Ok(der) = piv.read_certificate(reader, slot) else {
        return SlotCertificate::None;
    };
    let Ok(cert) = Certificate::from_der(&der) else {
        return SlotCertificate::Unparseable;
    };
    let subject = cert.tbs_certificate.subject.to_string();
    if crate::context::parse_ec_public_key_from_cert_der(&der).is_ok() {
        SlotCertificate::P256 { subject }
    } else {
        SlotCertificate::NotP256 { subject }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "virtual-piv"))]
mod tests {
    use super::*;
    use crate::piv::VirtualPiv;
    use std::sync::Arc;

    const MGMT: &str = crate::auxiliaries::DEFAULT_MANAGEMENT_KEY;

    #[test]
    fn factory_card() {
        let piv: Arc<dyn PivBackend> = Arc::new(VirtualPiv::new());
        let ctx = Context::with_backend(piv, None, false).unwrap();
        let report = CardReport::build(&ctx, 0x82);
        assert!(report.has_metadata());
        let text = report.render(Some("use --check-key"), true);
        assert_eq!(
            text,
            "YubiKey 99999999 — firmware 5.4.3\n\
             \n\
             PIV application\n\
             \x20 PIN              warning: factory default, 3/3 tries left\n\
             \x20 PUK              warning: factory default, 3/3 tries left\n\
             \x20 Management key   warning: factory default, 3DES\n\
             \x20 Store key        slot 0x82: empty\n\
             \x20 Key/certificate  not checked (use --check-key)\n"
        );
        assert_eq!(report.severity(), Severity::Warning);
        assert!(!report.slot.is_occupied());
    }

    #[test]
    fn generated_key_with_certificate() {
        let piv: Arc<dyn PivBackend> = Arc::new(VirtualPiv::new());
        let reader = piv.list_devices().unwrap()[0].reader.clone();
        piv.generate_certificate(&reader, 0x82, "/CN=YBLOB ECCP256", MGMT, None)
            .unwrap();
        let ctx = Context::with_backend(piv, None, false).unwrap();
        let mut report = CardReport::build(&ctx, 0x82);
        report.key_check = Some(SlotKeyCheck::Mismatch);
        let slot = &report.items(None)[3];
        assert_eq!(
            slot.text,
            "slot 0x82: EC P-256, generated on card, certificate CN=YBLOB ECCP256"
        );
        assert_eq!(report.severity(), Severity::Error);
    }

    /// Spec 0045: a post-quantum store shows both applications, with their
    /// roles, and the FIDO2 PIN's state.
    #[test]
    fn post_quantum_roles_and_fido2_pin() {
        let piv: Arc<dyn PivBackend> = Arc::new(VirtualPiv::new());
        let ctx = Context::with_backend(piv, None, false).unwrap();
        let mut report = CardReport::build(&ctx, 0x82);
        report.store = ReportStore::PostQuantum;
        let fido2 = |state| Fido2Report {
            state,
            credential_id_len: 64,
            checked_below: false,
            unencrypted_blobs: true,
        };
        report.fido2 = Some(fido2(Fido2State::Pin { retries: 8 }));
        let text = report.render(None, true);
        assert!(
            text.contains("\nPIV application — holds the store's objects\n"),
            "{text}"
        );
        assert!(text.contains("— not used by this store"), "{text}");
        assert!(
            text.contains("\nFIDO2 application — protects this store\n"),
            "{text}"
        );
        assert!(
            text.contains("  PIN              set, 8/8 tries left\n"),
            "{text}"
        );
        assert!(
            text.contains("  Credential       the store's: 64-byte ID, not checked"),
            "{text}"
        );
        assert!(!text.contains("Store key"), "{text}");

        report.fido2 = Some(fido2(Fido2State::Pin { retries: 2 }));
        assert!(report
            .render(None, true)
            .contains("warning: set, 2/8 tries left"));
        report.fido2 = Some(fido2(Fido2State::Pin { retries: 0 }));
        let text = report.render(None, true);
        assert!(text.contains("ERROR: blocked"), "{text}");
        assert!(text.contains("yb fetch --no-check"), "{text}");
        assert_eq!(report.severity(), Severity::Error);

        report.store = ReportStore::Legacy;
        report.fido2 = None;
        let text = report.render(None, true);
        assert!(
            text.contains("\nPIV application — protects this store\n"),
            "{text}"
        );
        assert!(
            text.ends_with("\nFIDO2 application — not used by this store\n"),
            "{text}"
        );
    }

    #[test]
    fn store_presence() {
        let piv = VirtualPiv::new();
        let reader = piv.reader_name();
        assert!(matches!(
            StorePresence::probe(&reader, &piv),
            StorePresence::None
        ));
        piv.write_object(&reader, OBJECT_ID_ZERO, b"garbage", MGMT)
            .unwrap();
        assert!(matches!(
            StorePresence::probe(&reader, &piv),
            StorePresence::Unreadable(_)
        ));
        Store::format(&reader, &piv, 4, 0x82, MGMT).unwrap();
        assert!(matches!(
            StorePresence::probe(&reader, &piv),
            StorePresence::Present(_)
        ));
    }
}
