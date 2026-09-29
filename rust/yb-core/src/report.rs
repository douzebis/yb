// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Read-only report on the state of a YubiKey (spec 0023 §1), shared by
//! `yb fsck` and the guided `yb format`.
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
        match Store::from_device(reader, piv) {
            Ok(store) => Self::Present(store),
            Err(e) => match piv.object_size(reader, OBJECT_ID_ZERO) {
                Ok(Some(_)) => Self::Unreadable(format!("{e:#}")),
                _ => Self::None,
            },
        }
    }
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

    /// The report lines, in display order.  `key_check_hint` is shown on
    /// the Key/certificate line when the check did not run; `None` omits
    /// the line.
    pub fn items(&self, key_check_hint: Option<&str>) -> Vec<Item> {
        let mut items = vec![
            credential_item("PIN", self.pin),
            credential_item("PUK", self.puk),
            self.management_key_item(),
            self.slot_item(),
        ];
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

    /// The most serious severity among the items.
    pub fn severity(&self) -> Severity {
        self.items(None)
            .iter()
            .map(|i| i.severity)
            .max()
            .unwrap_or(Severity::Ok)
    }

    /// The YubiKey section (spec 0023 §2), one line per item, followed by
    /// the item's hint lines when `hints` is set.
    pub fn render(&self, key_check_hint: Option<&str>, hints: bool) -> String {
        let mut out = format!("YubiKey {} — firmware {}\n", self.serial, self.firmware);
        for i in self.items(key_check_hint) {
            let text = match i.severity {
                Severity::Ok => i.text,
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
        out
    }

    fn management_key_item(&self) -> Item {
        const LABEL: &str = "Management key";
        let algo = match self.management_key {
            Some(md) => md.algo.to_string(),
            None => "unknown algorithm (firmware < 5.3)".to_owned(),
        };
        let (protection, mut severity) = match self.protection {
            ProtectionMode::Standard => ("kept on the YubiKey, unlocked by the PIN", Severity::Ok),
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
        let mut parts = vec![algo];
        if !protection.is_empty() {
            parts.push(protection.to_owned());
        }
        if let Some(md) = self.management_key {
            if md.is_default {
                parts.push("factory default".to_owned());
                severity = severity.max(Severity::Warning);
            }
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
        let label = format!("Slot 0x{:02x}", self.slot.slot);
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
        item(&label, parts.join(", "), severity)
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

fn credential_item(label: &str, md: Option<CredentialMetadata>) -> Item {
    let Some(md) = md else {
        return item(label, "unknown (firmware < 5.3)".to_owned(), Severity::Ok);
    };
    let tries = format!("{}/{} tries left", md.retries_left, md.retries_total);
    if md.retries_left == 0 {
        // A blocked PUK only stops PIN resets: not an error.
        let severity = if label == "PIN" {
            Severity::Error
        } else {
            Severity::Warning
        };
        return item(label, format!("blocked ({tries})"), severity);
    }
    if md.is_default {
        return item(
            label,
            format!("factory default ({tries})"),
            Severity::Warning,
        );
    }
    item(label, format!("ok ({tries})"), Severity::Ok)
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
             \x20 PIN              warning: factory default (3/3 tries left)\n\
             \x20 PUK              warning: factory default (3/3 tries left)\n\
             \x20 Management key   warning: 3DES, factory default\n\
             \x20 Slot 0x82        empty\n\
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
            "EC P-256, generated on card, certificate CN=YBLOB ECCP256"
        );
        assert_eq!(report.severity(), Severity::Error);
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
