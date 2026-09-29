// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! In-memory PIV backend with real P-256 cryptography, used for unit tests.
//!
//! `VirtualPiv` implements the full `PivBackend` trait including ECDH,
//! signing, key generation, and certificate management — without any
//! hardware or PC/SC dependency.  Auth state (PIN retries, management key
//! authentication) is tracked in memory and resets when the struct is dropped.
//!
//! # WARNING
//!
//! Fixture files loaded by `VirtualPiv::from_fixture` contain **disposable
//! test key material**.  Never use these keys to protect real data and never
//! confuse them with production YubiKey credentials.

use super::{DeviceInfo, MgmtAlgo, PivBackend};
use anyhow::{anyhow, bail, Result};
use p256::{elliptic_curve::sec1::ToEncodedPoint, PublicKey, SecretKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, Mutex},
};

// ---------------------------------------------------------------------------
// Public-key point encoding helpers
// ---------------------------------------------------------------------------

fn pubkey_to_uncompressed(pk: &PublicKey) -> Vec<u8> {
    pk.to_encoded_point(false).as_bytes().to_vec()
}

// ---------------------------------------------------------------------------
// Per-slot key material
// ---------------------------------------------------------------------------

struct SlotKey {
    secret: SecretKey,
    public_point: Vec<u8>, // 65-byte uncompressed P-256 point
    cert_der: Option<Vec<u8>>,
}

impl SlotKey {
    fn from_secret(secret: SecretKey) -> Self {
        let public_point = pubkey_to_uncompressed(&secret.public_key());
        Self {
            secret,
            public_point,
            cert_der: None,
        }
    }

    fn generate() -> Self {
        Self::from_secret(SecretKey::random(&mut OsRng))
    }

    fn from_scalar_hex(hex: &str) -> Result<Self> {
        let bytes = hex::decode(hex).map_err(|e| anyhow!("slot key hex: {e}"))?;
        let secret = SecretKey::from_slice(&bytes).map_err(|e| anyhow!("slot key scalar: {e}"))?;
        Ok(Self::from_secret(secret))
    }
}

// ---------------------------------------------------------------------------
// Fault injection (spec 0022 §5)
// ---------------------------------------------------------------------------

/// A failure to inject into a [`VirtualPiv`], to test recovery paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// The Nth object write from now (1-based) is rejected; the object is
    /// left unchanged.
    WriteFails(usize),
    /// SET MANAGEMENT KEY is rejected; the key is unchanged.
    SetManagementKeyRejected,
    /// SET MANAGEMENT KEY is applied, but reported as failed (lost reply).
    SetManagementKeyLostReply,
    /// The card is lost during SET MANAGEMENT KEY, after applying the
    /// change or not.  Every later authentication fails until
    /// [`VirtualPiv::clear_faults`] (which simulates reconnecting).
    CardLostDuringSetManagementKey { applied: bool },
    /// `generate_certificate` replaces the key in the slot, then fails
    /// before writing the certificate (the old certificate remains).
    GenerateCertificateFailsAfterKey,
}

// ---------------------------------------------------------------------------
// Internal mutable state
// ---------------------------------------------------------------------------

struct VirtualState {
    reader: String,
    serial: u32,
    version: String,

    pin: String,
    puk: String,
    management_key_hex: String, // hex-encoded raw key bytes
    mgmt_algo: MgmtAlgo,
    pin_retries: u8,
    puk_retries: u8,

    pin_verified: bool,
    mgmt_authenticated: bool,

    // PIV key slots: slot byte → SlotKey
    key_slots: HashMap<u8, SlotKey>,
    // PIV data objects: object ID → raw bytes (stored as the value inside 53 wrapper)
    objects: HashMap<u32, Vec<u8>>,

    // Injected faults, and whether the card is "lost" (see `Fault`).
    faults: Vec<Fault>,
    card_lost: bool,
}

impl VirtualState {
    /// Remove and return the first injected fault matching `pred`.
    fn take_fault(&mut self, pred: impl Fn(&Fault) -> bool) -> Option<Fault> {
        let pos = self.faults.iter().position(pred)?;
        Some(self.faults.remove(pos))
    }

    /// Count one object write against a pending `WriteFails`; return true
    /// if this write must fail.
    fn write_must_fail(&mut self) -> bool {
        let Some(pos) = self
            .faults
            .iter()
            .position(|f| matches!(f, Fault::WriteFails(_)))
        else {
            return false;
        };
        if let Fault::WriteFails(n) = &mut self.faults[pos] {
            *n -= 1;
            if *n == 0 {
                self.faults.remove(pos);
                return true;
            }
        }
        false
    }
}

impl VirtualState {
    fn default_state(serial: u32, reader: String, version: String) -> Self {
        Self {
            reader,
            serial,
            version,
            pin: "123456".to_owned(),
            puk: "12345678".to_owned(),
            management_key_hex: "010203040506070801020304050607080102030405060708".to_owned(),
            mgmt_algo: MgmtAlgo::Tdes,
            pin_retries: 3,
            puk_retries: 3,
            pin_verified: false,
            mgmt_authenticated: false,
            key_slots: HashMap::new(),
            objects: HashMap::new(),
            faults: Vec::new(),
            card_lost: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Fixture deserialization
// ---------------------------------------------------------------------------

#[derive(Deserialize, Serialize)]
struct Fixture {
    #[serde(default)]
    identity: FixtureIdentity,
    #[serde(default)]
    credentials: FixtureCredentials,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    slots: HashMap<String, FixtureSlot>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    objects: HashMap<String, String>,
}

#[derive(Deserialize, Serialize, Default)]
struct FixtureIdentity {
    #[serde(default = "default_serial")]
    serial: u32,
    #[serde(default = "default_version")]
    version: String,
    #[serde(default = "default_reader")]
    reader: String,
}

fn default_serial() -> u32 {
    99_999_999
}
fn default_version() -> String {
    "5.4.3".to_owned()
}
fn default_reader() -> String {
    "Virtual YubiKey 00 00".to_owned()
}

#[derive(Deserialize, Serialize, Default)]
struct FixtureCredentials {
    #[serde(default = "default_pin")]
    pin: String,
    #[serde(default = "default_puk")]
    puk: String,
    #[serde(default = "default_mgmt_key")]
    management_key: String,
    /// `TDES` (default), `AES128`, `AES192` or `AES256`.  Firmware 5.7+
    /// YubiKeys ship with an AES-192 management key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    management_key_algorithm: Option<String>,
}

fn default_pin() -> String {
    "123456".to_owned()
}
fn default_puk() -> String {
    "12345678".to_owned()
}
fn default_mgmt_key() -> String {
    "010203040506070801020304050607080102030405060708".to_owned()
}

#[derive(Deserialize, Serialize)]
struct FixtureSlot {
    private_key_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    cert_der_hex: Option<String>,
}

// ---------------------------------------------------------------------------
// VirtualPiv
// ---------------------------------------------------------------------------

/// In-memory PIV backend for unit tests.  Implements the full `PivBackend`
/// trait with real P-256 cryptography but no hardware or PC/SC dependency.
pub struct VirtualPiv {
    state: Arc<Mutex<VirtualState>>,
}

impl VirtualPiv {
    /// Create a `VirtualPiv` with default test credentials and an empty store.
    pub fn new() -> Self {
        let id = FixtureIdentity::default();
        Self {
            state: Arc::new(Mutex::new(VirtualState::default_state(
                id.serial, id.reader, id.version,
            ))),
        }
    }

    /// Load a `VirtualPiv` from a YAML fixture file.
    ///
    /// # WARNING
    /// Fixture files contain disposable test key material.
    /// Never use them with real data.
    pub fn from_fixture(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).map_err(|e| anyhow!("reading fixture {path:?}: {e}"))?;
        let fixture: Fixture =
            serde_yaml::from_str(&text).map_err(|e| anyhow!("parsing fixture {path:?}: {e}"))?;

        let mut state = VirtualState::default_state(
            fixture.identity.serial,
            fixture.identity.reader,
            fixture.identity.version,
        );
        state.pin = fixture.credentials.pin;
        state.puk = fixture.credentials.puk;
        state.management_key_hex = fixture.credentials.management_key;
        if let Some(ref name) = fixture.credentials.management_key_algorithm {
            state.mgmt_algo = MgmtAlgo::from_name(name)
                .ok_or_else(|| anyhow!("fixture: unknown management_key_algorithm '{name}'"))?;
        }

        for (slot_str, slot_fixture) in &fixture.slots {
            let slot_byte = u8::from_str_radix(slot_str.trim_start_matches("0x"), 16)
                .map_err(|_| anyhow!("invalid slot key in fixture: {slot_str}"))?;
            let mut key = SlotKey::from_scalar_hex(&slot_fixture.private_key_hex)?;
            if let Some(ref cert_hex) = slot_fixture.cert_der_hex {
                key.cert_der = Some(
                    hex::decode(cert_hex)
                        .map_err(|e| anyhow!("fixture slot {slot_str} cert: {e}"))?,
                );
            }
            state.key_slots.insert(slot_byte, key);
        }

        for (id_str, data_hex) in &fixture.objects {
            let id = u32::from_str_radix(id_str.trim_start_matches("0x"), 16)
                .map_err(|_| anyhow!("invalid object ID in fixture: {id_str}"))?;
            let data =
                hex::decode(data_hex).map_err(|e| anyhow!("fixture object {id_str}: {e}"))?;
            state.objects.insert(id, data);
        }

        Ok(Self {
            state: Arc::new(Mutex::new(state)),
        })
    }

    /// Return the reader name this virtual device responds to.
    pub fn reader_name(&self) -> String {
        self.state.lock().unwrap().reader.clone()
    }

    /// Inject a failure (see [`Fault`]).  Faults fire once, in the order
    /// the matching operations happen.
    pub fn inject_fault(&self, fault: Fault) {
        self.state.lock().unwrap().faults.push(fault);
    }

    /// Drop pending faults and "reconnect" a lost card.
    pub fn clear_faults(&self) {
        let mut s = self.state.lock().unwrap();
        s.faults.clear();
        s.card_lost = false;
    }

    /// Serialize the current state back to a YAML fixture file.
    ///
    /// This lets subprocess tests persist state written by one `yb` invocation
    /// (e.g. `format`) so that subsequent invocations start from that state.
    fn do_save_fixture(&self, path: &Path) -> Result<()> {
        let s = self.state.lock().unwrap();
        let mut slots = HashMap::new();
        for (slot_byte, key) in &s.key_slots {
            let scalar_bytes = key.secret.to_bytes();
            slots.insert(
                format!("0x{slot_byte:02x}"),
                FixtureSlot {
                    private_key_hex: hex::encode(scalar_bytes),
                    cert_der_hex: key.cert_der.as_deref().map(hex::encode),
                },
            );
        }
        let mut objects = HashMap::new();
        for (id, data) in &s.objects {
            objects.insert(format!("0x{id:06x}"), hex::encode(data));
        }
        let fixture = Fixture {
            identity: FixtureIdentity {
                serial: s.serial,
                version: s.version.clone(),
                reader: s.reader.clone(),
            },
            credentials: FixtureCredentials {
                pin: s.pin.clone(),
                puk: s.puk.clone(),
                management_key: s.management_key_hex.clone(),
                management_key_algorithm: match s.mgmt_algo {
                    MgmtAlgo::Tdes => None,
                    MgmtAlgo::Aes128 => Some("AES128".to_owned()),
                    MgmtAlgo::Aes192 => Some("AES192".to_owned()),
                    MgmtAlgo::Aes256 => Some("AES256".to_owned()),
                },
            },
            slots,
            objects,
        };
        let yaml =
            serde_yaml::to_string(&fixture).map_err(|e| anyhow!("serializing fixture: {e}"))?;
        std::fs::write(path, yaml).map_err(|e| anyhow!("writing fixture {path:?}: {e}"))?;
        Ok(())
    }
}

impl Default for VirtualPiv {
    fn default() -> Self {
        Self::new()
    }
}

impl PivBackend for VirtualPiv {
    fn list_readers(&self) -> Result<Vec<String>> {
        Ok(vec![self.state.lock().unwrap().reader.clone()])
    }

    fn list_devices(&self) -> Result<Vec<DeviceInfo>> {
        let s = self.state.lock().unwrap();
        Ok(vec![DeviceInfo {
            serial: s.serial,
            version: s.version.clone(),
            reader: s.reader.clone(),
        }])
    }

    fn read_object(&self, reader: &str, id: u32) -> Result<Vec<u8>> {
        let s = self.state.lock().unwrap();
        check_reader(&s, reader)?;
        s.objects
            .get(&id)
            .cloned()
            .ok_or_else(|| anyhow!("virtual: object 0x{id:06x} not found"))
    }

    fn object_size(&self, reader: &str, id: u32) -> Result<Option<usize>> {
        let s = self.state.lock().unwrap();
        check_reader(&s, reader)?;
        Ok(s.objects.get(&id).map(|v| v.len()))
    }

    fn write_object(&self, reader: &str, id: u32, data: &[u8], management_key: &str) -> Result<()> {
        let mut s = self.state.lock().unwrap();
        check_reader(&s, reader)?;
        do_authenticate_management_key(&mut s, management_key)?;
        if s.write_must_fail() {
            bail!("virtual: injected failure writing object 0x{id:06x}");
        }
        if data.is_empty() {
            s.objects.remove(&id);
        } else {
            s.objects.insert(id, data.to_vec());
        }
        Ok(())
    }

    fn authenticate_management_key(&self, reader: &str, management_key: &str) -> Result<()> {
        let mut s = self.state.lock().unwrap();
        check_reader(&s, reader)?;
        do_authenticate_management_key(&mut s, management_key)
    }

    fn verify_pin(&self, reader: &str, pin: &str) -> Result<()> {
        let mut s = self.state.lock().unwrap();
        check_reader(&s, reader)?;
        do_verify_pin(&mut s, pin)
    }

    /// Emulates GET METADATA (INS 0xF7) for the management key (9B) and the
    /// PIN/PUK (80/81); every other APDU returns empty data.
    ///
    /// The "is default" flag (tag 0x05) is deliberately never reported, so
    /// that the default-credential check stays silent on virtual devices.
    fn send_apdu(&self, reader: &str, apdu: &[u8]) -> Result<Vec<u8>> {
        let s = self.state.lock().unwrap();
        check_reader(&s, reader)?;
        match apdu {
            [0x00, 0xF7, 0x00, 0x9B, ..] => {
                // Algorithm; policy (PIN n/a, touch never).
                Ok(vec![0x01, 0x01, s.mgmt_algo.id(), 0x02, 0x02, 0x00, 0x01])
            }
            [0x00, 0xF7, 0x00, 0x80, ..] => Ok(vec![0x06, 0x02, 3, s.pin_retries]),
            [0x00, 0xF7, 0x00, 0x81, ..] => Ok(vec![0x06, 0x02, 3, s.puk_retries]),
            _ => Ok(vec![]),
        }
    }

    fn ecdsa_sign(
        &self,
        reader: &str,
        slot: u8,
        digest: &[u8],
        pin: Option<&str>,
    ) -> Result<[u8; 64]> {
        use p256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
        let mut s = self.state.lock().unwrap();
        check_reader(&s, reader)?;
        if let Some(p) = pin {
            do_verify_pin(&mut s, p)?;
        }
        let slot_key = s
            .key_slots
            .get(&slot)
            .ok_or_else(|| anyhow!("virtual: no key in slot 0x{slot:02x}"))?;
        let signing_key = SigningKey::from(slot_key.secret.clone());
        // Sign the pre-computed SHA-256 digest directly (no double-hashing).
        let sig: p256::ecdsa::Signature = signing_key
            .sign_prehash(digest)
            .map_err(|e| anyhow!("virtual: ECDSA sign: {e}"))?;
        let sig_bytes = sig.to_bytes();
        Ok(sig_bytes.into())
    }

    fn ecdh(
        &self,
        reader: &str,
        slot: u8,
        peer_point: &[u8],
        pin: Option<&str>,
    ) -> Result<Vec<u8>> {
        let mut s = self.state.lock().unwrap();
        check_reader(&s, reader)?;
        if let Some(p) = pin {
            do_verify_pin(&mut s, p)?;
        }
        let slot_key = s
            .key_slots
            .get(&slot)
            .ok_or_else(|| anyhow!("virtual: no key in slot 0x{slot:02x}"))?;

        let peer = PublicKey::from_sec1_bytes(peer_point)
            .map_err(|e| anyhow!("virtual: invalid peer point: {e}"))?;

        // ECDH: scalar multiply to get the shared secret (x-coordinate, 32 bytes).
        let shared =
            p256::ecdh::diffie_hellman(slot_key.secret.to_nonzero_scalar(), peer.as_affine());
        Ok(shared.raw_secret_bytes().to_vec())
    }

    fn read_certificate(&self, reader: &str, slot: u8) -> Result<Vec<u8>> {
        let s = self.state.lock().unwrap();
        check_reader(&s, reader)?;
        s.key_slots
            .get(&slot)
            .and_then(|k| k.cert_der.clone())
            .ok_or_else(|| anyhow!("virtual: no certificate in slot 0x{slot:02x}"))
    }

    fn generate_key(
        &self,
        reader: &str,
        slot: u8,
        management_key: Option<&str>,
    ) -> Result<Vec<u8>> {
        let mut s = self.state.lock().unwrap();
        check_reader(&s, reader)?;
        if let Some(key) = management_key {
            do_authenticate_management_key(&mut s, key)?;
        } else if !s.mgmt_authenticated {
            bail!("virtual: management key authentication required for generate_key");
        }
        let key = SlotKey::generate();
        let point = key.public_point.clone();
        s.key_slots.insert(slot, key);
        Ok(point)
    }

    fn generate_certificate(
        &self,
        reader: &str,
        slot: u8,
        subject: &str,
        management_key: &str,
        pin: Option<&str>,
    ) -> Result<Vec<u8>> {
        use crate::auxiliaries::parse_subject_dn;
        use rcgen::{CertificateParams, KeyPair};

        let mut s = self.state.lock().unwrap();
        check_reader(&s, reader)?;
        if let Some(p) = pin {
            do_verify_pin(&mut s, p)?;
        }
        do_authenticate_management_key(&mut s, management_key)?;

        // Generate a fresh key in the slot.
        let slot_key = SlotKey::generate();

        // Like hardware, key generation and certificate import are separate
        // steps: the key can be replaced while the old certificate remains.
        if s.take_fault(|f| *f == Fault::GenerateCertificateFailsAfterKey)
            .is_some()
        {
            let old_cert = s.key_slots.get(&slot).and_then(|k| k.cert_der.clone());
            let mut replaced = slot_key;
            replaced.cert_der = old_cert;
            s.key_slots.insert(slot, replaced);
            bail!("virtual: injected failure writing the certificate for slot 0x{slot:02x}");
        }
        // Export as PKCS#8 DER so rcgen can build a KeyPair from it.
        use p256::pkcs8::EncodePrivateKey;
        // pkcs8_der must remain alive until key_pair is built; it is zeroed on drop.
        let pkcs8_der = slot_key
            .secret
            .to_pkcs8_der()
            .map_err(|e| anyhow!("virtual: secret to PKCS8: {e}"))?;

        // KeyPair::try_from accepts raw PKCS#8 DER bytes.
        let key_pair = KeyPair::try_from(pkcs8_der.as_bytes())
            .map_err(|e| anyhow!("virtual: rcgen KeyPair: {e}"))?;

        let mut params = CertificateParams::new(vec![])
            .map_err(|e| anyhow!("virtual: CertificateParams: {e}"))?;
        params.distinguished_name = parse_subject_dn(subject);
        params.not_before = rcgen::date_time_ymd(2000, 1, 1);
        params.not_after = rcgen::date_time_ymd(9999, 12, 31);

        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| anyhow!("virtual: self_signed: {e}"))?;
        let cert_der = cert.der().to_vec();

        // Store key + cert in the slot.
        let mut stored_key = slot_key;
        stored_key.cert_der = Some(cert_der.clone());
        s.key_slots.insert(slot, stored_key);

        Ok(cert_der)
    }

    fn read_printed_object_with_pin(&self, reader: &str, pin: &str) -> Result<Vec<u8>> {
        use crate::auxiliaries::OBJ_PRINTED;
        let mut s = self.state.lock().unwrap();
        check_reader(&s, reader)?;
        do_verify_pin(&mut s, pin)?;
        s.objects
            .get(&OBJ_PRINTED)
            .cloned()
            .ok_or_else(|| anyhow!("virtual: no PRINTED object stored"))
    }

    fn management_key_algorithm(&self, reader: &str) -> Result<MgmtAlgo> {
        let s = self.state.lock().unwrap();
        check_reader(&s, reader)?;
        Ok(s.mgmt_algo)
    }

    fn set_management_key(
        &self,
        reader: &str,
        old_key_hex: &str,
        new_key_hex: &str,
        algo: MgmtAlgo,
    ) -> Result<()> {
        let mut s = self.state.lock().unwrap();
        check_reader(&s, reader)?;
        do_authenticate_management_key(&mut s, old_key_hex)?;
        let new_bytes = hex::decode(new_key_hex).map_err(|e| anyhow!("new key hex: {e}"))?;
        algo.check_key_len(&new_bytes)?;

        let fault = s.take_fault(|f| {
            matches!(
                f,
                Fault::SetManagementKeyRejected
                    | Fault::SetManagementKeyLostReply
                    | Fault::CardLostDuringSetManagementKey { .. }
            )
        });
        let apply = !matches!(
            fault,
            Some(Fault::SetManagementKeyRejected)
                | Some(Fault::CardLostDuringSetManagementKey { applied: false })
        );
        if apply {
            s.management_key_hex = new_key_hex.to_owned();
            s.mgmt_algo = algo;
        }
        if let Some(Fault::CardLostDuringSetManagementKey { .. }) = fault {
            s.card_lost = true;
        }
        match fault {
            Some(f) => bail!("virtual: injected SET MANAGEMENT KEY failure ({f:?})"),
            None => Ok(()),
        }
    }

    fn save_fixture(&self, path: &std::path::Path) -> Result<()> {
        self.do_save_fixture(path)
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn check_reader(s: &VirtualState, reader: &str) -> Result<()> {
    if reader != s.reader {
        bail!("virtual: unknown reader '{reader}'");
    }
    Ok(())
}

fn do_verify_pin(s: &mut VirtualState, pin: &str) -> Result<()> {
    if s.pin_retries == 0 {
        bail!("virtual: PIN blocked");
    }
    if pin != s.pin {
        s.pin_retries -= 1;
        bail!("virtual: wrong PIN ({} retries remaining)", s.pin_retries);
    }
    s.pin_verified = true;
    s.pin_retries = 3;
    Ok(())
}

fn do_authenticate_management_key(s: &mut VirtualState, key_hex: &str) -> Result<()> {
    if s.card_lost {
        bail!("virtual: card not responding (injected)");
    }
    // Like the hardware path: a key of the wrong length for the card's
    // algorithm is rejected before any authentication attempt.
    let key_bytes = hex::decode(key_hex).map_err(|e| anyhow!("decoding management key: {e}"))?;
    s.mgmt_algo.check_key_len(&key_bytes)?;
    if key_hex != s.management_key_hex {
        bail!("virtual: wrong management key");
    }
    s.mgmt_authenticated = true;
    Ok(())
}
