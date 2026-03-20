// SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
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

use super::{DeviceInfo, PivBackend};
use anyhow::{anyhow, bail, Result};
use p256::{elliptic_curve::sec1::ToEncodedPoint, PublicKey, SecretKey};
use rand::rngs::OsRng;
use serde::Deserialize;
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
    fn generate() -> Self {
        let secret = SecretKey::random(&mut OsRng);
        let public_point = pubkey_to_uncompressed(&secret.public_key());
        Self {
            secret,
            public_point,
            cert_der: None,
        }
    }

    fn from_scalar_hex(hex: &str) -> Result<Self> {
        let bytes = hex::decode(hex).map_err(|e| anyhow!("slot key hex: {e}"))?;
        let secret = SecretKey::from_slice(&bytes).map_err(|e| anyhow!("slot key scalar: {e}"))?;
        let public_point = pubkey_to_uncompressed(&secret.public_key());
        Ok(Self {
            secret,
            public_point,
            cert_der: None,
        })
    }
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
    pin_retries: u8,

    pin_verified: bool,
    mgmt_authenticated: bool,

    // PIV key slots: slot byte → SlotKey
    key_slots: HashMap<u8, SlotKey>,
    // PIV data objects: object ID → raw bytes (stored as the value inside 53 wrapper)
    objects: HashMap<u32, Vec<u8>>,
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
            pin_retries: 3,
            pin_verified: false,
            mgmt_authenticated: false,
            key_slots: HashMap::new(),
            objects: HashMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Fixture deserialization
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct Fixture {
    #[serde(default)]
    identity: FixtureIdentity,
    #[serde(default)]
    credentials: FixtureCredentials,
    #[serde(default)]
    slots: HashMap<String, FixtureSlot>,
    #[serde(default)]
    objects: HashMap<String, String>,
}

#[derive(Deserialize, Default)]
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

#[derive(Deserialize, Default)]
struct FixtureCredentials {
    #[serde(default = "default_pin")]
    pin: String,
    #[serde(default = "default_puk")]
    puk: String,
    #[serde(default = "default_mgmt_key")]
    management_key: String,
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

#[derive(Deserialize)]
struct FixtureSlot {
    private_key_hex: String,
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
        Self {
            state: Arc::new(Mutex::new(VirtualState::default_state(
                default_serial(),
                default_reader(),
                default_version(),
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

        for (slot_str, slot_fixture) in &fixture.slots {
            let slot_byte = u8::from_str_radix(slot_str.trim_start_matches("0x"), 16)
                .map_err(|_| anyhow!("invalid slot key in fixture: {slot_str}"))?;
            let key = SlotKey::from_scalar_hex(&slot_fixture.private_key_hex)?;
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

    fn write_object(
        &self,
        reader: &str,
        id: u32,
        data: &[u8],
        management_key: Option<&str>,
        pin: Option<&str>,
    ) -> Result<()> {
        let mut s = self.state.lock().unwrap();
        check_reader(&s, reader)?;
        authenticate_for_write(&mut s, management_key, pin)?;
        s.objects.insert(id, data.to_vec());
        Ok(())
    }

    fn verify_pin(&self, reader: &str, pin: &str) -> Result<()> {
        let mut s = self.state.lock().unwrap();
        check_reader(&s, reader)?;
        do_verify_pin(&mut s, pin)
    }

    fn send_apdu(&self, reader: &str, _apdu: &[u8]) -> Result<Vec<u8>> {
        let s = self.state.lock().unwrap();
        check_reader(&s, reader)?;
        Ok(vec![])
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
        management_key: Option<&str>,
        pin: Option<&str>,
    ) -> Result<Vec<u8>> {
        use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};

        let mut s = self.state.lock().unwrap();
        check_reader(&s, reader)?;
        if let Some(p) = pin {
            do_verify_pin(&mut s, p)?;
        }
        if let Some(key) = management_key {
            do_authenticate_management_key(&mut s, key)?;
        } else if !s.mgmt_authenticated {
            bail!("virtual: management key authentication required");
        }

        // Generate a fresh key in the slot.
        let slot_key = SlotKey::generate();
        // Export as PKCS#8 DER so rcgen can build a KeyPair from it.
        use p256::pkcs8::EncodePrivateKey;
        let pkcs8_der = slot_key
            .secret
            .to_pkcs8_der()
            .map_err(|e| anyhow!("virtual: secret to PKCS8: {e}"))?;

        // KeyPair::try_from accepts raw PKCS#8 DER bytes.
        let key_pair = KeyPair::try_from(pkcs8_der.as_bytes())
            .map_err(|e| anyhow!("virtual: rcgen KeyPair: {e}"))?;

        let mut dn = DistinguishedName::new();
        for part in subject.split('/').filter(|s| !s.is_empty()) {
            if let Some((k, v)) = part.split_once('=') {
                match k.trim() {
                    "CN" => dn.push(DnType::CommonName, v.trim()),
                    "O" => dn.push(DnType::OrganizationName, v.trim()),
                    "OU" => dn.push(DnType::OrganizationalUnitName, v.trim()),
                    _ => {}
                }
            }
        }
        let mut params = CertificateParams::new(vec![])
            .map_err(|e| anyhow!("virtual: CertificateParams: {e}"))?;
        params.distinguished_name = dn;
        params.not_before = rcgen::date_time_ymd(2025, 1, 1);
        params.not_after = rcgen::date_time_ymd(2035, 1, 1);

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
    if key_hex != s.management_key_hex {
        bail!("virtual: wrong management key");
    }
    s.mgmt_authenticated = true;
    Ok(())
}

/// Resolve and authenticate the management key from either a direct hex value
/// or the PIN-protected PRINTED object, matching write_object behaviour.
fn authenticate_for_write(
    s: &mut VirtualState,
    management_key: Option<&str>,
    pin: Option<&str>,
) -> Result<()> {
    if let Some(key) = management_key {
        do_authenticate_management_key(s, key)
    } else if let Some(p) = pin {
        do_verify_pin(s, p)?;
        // Read PIN-protected mgmt key from PRINTED object (0x5FC109).
        const OBJ_PRINTED: u32 = 0x5F_C109;
        let raw = s
            .objects
            .get(&OBJ_PRINTED)
            .cloned()
            .ok_or_else(|| anyhow!("virtual: no PIN-protected management key stored"))?;
        let key_hex = extract_pin_protected_key(&raw)?;
        do_authenticate_management_key(s, &key_hex)
    } else {
        bail!("virtual: management_key or pin required for write");
    }
}

/// Parse `88 <len> [ 89 <len> <key_bytes> ]` from the PRINTED object value.
fn extract_pin_protected_key(raw: &[u8]) -> Result<String> {
    let outer = parse_tlv_flat(raw);
    let inner_bytes = outer
        .get(&0x88)
        .ok_or_else(|| anyhow!("PRINTED object missing tag 0x88"))?;
    let inner = parse_tlv_flat(inner_bytes);
    let key_bytes = inner
        .get(&0x89)
        .ok_or_else(|| anyhow!("PRINTED object missing tag 0x89 inside 0x88"))?;
    Ok(hex::encode(key_bytes))
}

/// Parse a flat BER-TLV sequence (single-byte tags only) into a tag→value map.
fn parse_tlv_flat(data: &[u8]) -> HashMap<u8, Vec<u8>> {
    let mut map = HashMap::new();
    let mut i = 0;
    while i < data.len() {
        let tag = data[i];
        i += 1;
        if i >= data.len() {
            break;
        }
        let (len, consumed) = decode_length(&data[i..]);
        i += consumed;
        if i + len > data.len() {
            break;
        }
        map.insert(tag, data[i..i + len].to_vec());
        i += len;
    }
    map
}

fn decode_length(data: &[u8]) -> (usize, usize) {
    if data.is_empty() {
        return (0, 0);
    }
    if data[0] & 0x80 == 0 {
        (data[0] as usize, 1)
    } else {
        let n = (data[0] & 0x7f) as usize;
        if data.len() < 1 + n {
            return (0, 1);
        }
        let mut len = 0usize;
        for b in &data[1..1 + n] {
            len = (len << 8) | (*b as usize);
        }
        (len, 1 + n)
    }
}
