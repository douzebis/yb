// SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Hardware PIV backend — communicates directly with the YubiKey PIV applet
//! via PC/SC APDUs (NIST SP 800-73-4).  No external subprocesses required.

use super::{DeviceInfo, PivBackend};
use anyhow::{bail, Context, Result};

// ---------------------------------------------------------------------------
// PcscSession — card handle + helpers for a single PC/SC connection
// ---------------------------------------------------------------------------

pub(crate) struct PcscSession {
    card: pcsc::Card,
}

impl PcscSession {
    /// Open a connection to `reader` and SELECT the PIV applet.
    pub(crate) fn open(reader: &str) -> Result<Self> {
        Self::open_with_mode(reader, pcsc::ShareMode::Shared)
    }

    /// Open with an explicit share mode.
    pub(crate) fn open_exclusive(reader: &str) -> Result<Self> {
        Self::open_with_mode(reader, pcsc::ShareMode::Exclusive)
    }

    fn open_with_mode(reader: &str, mode: pcsc::ShareMode) -> Result<Self> {
        let ctx =
            pcsc::Context::establish(pcsc::Scope::User).context("establishing PC/SC context")?;
        let card = connect_reader_mode(&ctx, reader, mode)?;

        let mut session = Self { card };
        session.select_piv()?;
        Ok(session)
    }

    /// SELECT PIV applet (AID A0 00 00 03 08).
    pub(crate) fn select_piv(&mut self) -> Result<()> {
        let apdu = &[0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08];
        self.transmit_check(apdu, "SELECT PIV")?;
        Ok(())
    }

    /// Send an APDU and return the full response (including SW).
    pub(crate) fn transmit_raw(&mut self, apdu: &[u8]) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; pcsc::MAX_BUFFER_SIZE_EXTENDED];
        let resp = self
            .card
            .transmit(apdu, &mut buf)
            .context("APDU transmit")?;
        Ok(resp.to_vec())
    }

    /// Send an APDU, handle SW=61xx chaining, check SW=9000, return data (SW stripped).
    pub(crate) fn transmit_check(&mut self, apdu: &[u8], label: &str) -> Result<Vec<u8>> {
        let mut resp = self.transmit_raw(apdu)?;
        let mut data = Vec::new();

        loop {
            let n = resp.len();
            if n < 2 {
                bail!("{label}: response too short ({n} bytes)");
            }
            let sw1 = resp[n - 2];
            let sw2 = resp[n - 1];
            data.extend_from_slice(&resp[..n - 2]);

            if sw1 == 0x90 && sw2 == 0x00 {
                break; // success
            }
            if sw1 == 0x61 {
                // More data available: issue GET RESPONSE.
                let le = if sw2 == 0x00 { 0x00u8 } else { sw2 };
                let get_resp = [0x00, 0xC0, 0x00, 0x00, le];
                resp = self.transmit_raw(&get_resp)?;
                continue;
            }
            bail!("{label} failed: SW={sw1:02x}{sw2:02x}");
        }

        Ok(data)
    }

    /// GET DATA — fetch a PIV data object by 3-byte object ID.
    pub(crate) fn get_data(&mut self, object_id: u32) -> Result<Vec<u8>> {
        let id = object_id.to_be_bytes(); // 4 bytes; we use the last 3
        let apdu = [
            0x00, 0xCB, 0x3F, 0xFF, // CLA INS P1 P2
            0x05, // Lc = 5
            0x5C, 0x03, id[1], id[2], id[3], // Tag 5C, length 3, 3-byte object ID
            0x00,  // Le
        ];
        let raw = self.transmit_check(&apdu, "GET DATA")?;
        // Response is BER-TLV: 53 <len> <data>.  Strip the outer wrapper.
        parse_tlv53(&raw)
    }

    /// PUT DATA — write a PIV data object.  Caller must authenticate management
    /// key first (call `authenticate_management_key`).
    pub(crate) fn put_data(&mut self, object_id: u32, data: &[u8]) -> Result<()> {
        let id = object_id.to_be_bytes();

        // Encode the content as BER-TLV: 53 <len> <data>.
        let mut content = encode_tlv(0x53, data);

        // Build the APDU data field: 5C 03 XX XX XX <content>.
        let mut data_field = vec![0x5C, 0x03, id[1], id[2], id[3]];
        data_field.append(&mut content);

        // yubico-piv-tool wraps every write in SCardBeginTransaction so that
        // pcsclite accepts the SCardTransmit calls.  Without a transaction,
        // pcsclite returns SCARD_E_NOT_TRANSACTED on some platforms.
        let tx = self
            .card
            .transaction()
            .context("SCardBeginTransaction for PUT DATA")?;

        // Send via command chaining (CLA |= 0x10, 255-byte chunks) — the same
        // approach used by yubico-piv-tool.  Extended-Lc APDUs are not used
        // because pcsclite / some CCID drivers reject them without a transaction.
        let mut remaining = data_field.as_slice();
        loop {
            let chunk_len = remaining.len().min(0xFF);
            let is_last = chunk_len == remaining.len();
            let cla: u8 = if is_last { 0x00 } else { 0x10 };
            let mut apdu = vec![cla, 0xDB, 0x3F, 0xFF, chunk_len as u8];
            apdu.extend_from_slice(&remaining[..chunk_len]);
            remaining = &remaining[chunk_len..];

            let resp = transmit_raw_card(&tx, &apdu)?;
            let n = resp.len();
            if n < 2 {
                bail!("PUT DATA: response too short");
            }
            let sw1 = resp[n - 2];
            let sw2 = resp[n - 1];
            if is_last {
                if sw1 != 0x90 || sw2 != 0x00 {
                    bail!("PUT DATA failed: SW={sw1:02x}{sw2:02x}");
                }
                break;
            } else if sw1 != 0x90 || sw2 != 0x00 {
                bail!("PUT DATA (chained) failed: SW={sw1:02x}{sw2:02x}");
            }
        }

        // Transaction drops here with SCARD_LEAVE_CARD (pcsc crate default).
        Ok(())
    }

    /// VERIFY PIN (P2=0x80 = user PIN reference).
    /// YubiKey PIV requires the PIN padded to 8 bytes with 0xFF.
    pub(crate) fn verify_pin(&mut self, pin: &str) -> Result<()> {
        let pin_bytes = pin.as_bytes();
        if pin_bytes.len() > 8 {
            bail!("PIN too long (max 8 bytes)");
        }
        let mut padded = [0xFFu8; 8];
        padded[..pin_bytes.len()].copy_from_slice(pin_bytes);
        let mut apdu = vec![0x00, 0x20, 0x00, 0x80, 0x08];
        apdu.extend_from_slice(&padded);
        let resp = self.transmit_raw(&apdu)?;
        let n = resp.len();
        if n < 2 {
            bail!("VERIFY PIN: response too short");
        }
        let sw1 = resp[n - 2];
        let sw2 = resp[n - 1];
        if sw1 == 0x90 && sw2 == 0x00 {
            return Ok(());
        }
        if sw1 == 0x63 {
            bail!("VERIFY PIN failed: {} retries remaining", sw2 & 0x0f);
        }
        if sw1 == 0x69 && sw2 == 0x83 {
            bail!("VERIFY PIN failed: PIN blocked");
        }
        bail!("VERIFY PIN failed: SW={:02x}{:02x}", sw1, sw2);
    }

    /// Authenticate the management key using GENERAL AUTHENTICATE (3-pass mutual auth).
    /// `key_hex` is 48 hex chars for 3DES, or 32/48/64 for AES-128/192/256.
    pub(crate) fn authenticate_management_key(&mut self, key_hex: &str) -> Result<()> {
        let key_bytes = hex::decode(key_hex).context("decoding management key")?;
        let (p1, block_size) = match key_bytes.len() {
            24 => (0x03u8, 8usize),  // 3DES
            16 => (0x08u8, 16usize), // AES-128
            32 => (0x0Eu8, 16usize), // AES-256
            n => bail!("unsupported management key length: {n} bytes"),
        };

        // Step 1: request witness (card encrypts a challenge).
        let step1 = [0x00, 0x87, p1, 0x9B, 0x04, 0x7C, 0x02, 0x80, 0x00];
        let resp1 = self.transmit_check(&step1, "MGMT AUTH step1")?;

        // Parse: 7C <len> 80 <len> <witness>
        let tlv1 = parse_tlv_flat(&resp1);
        let outer = tlv1
            .get(&0x7C)
            .ok_or_else(|| anyhow::anyhow!("MGMT AUTH step1: missing tag 7C"))?;
        let tlv_inner = parse_tlv_flat(outer);
        let witness_enc = tlv_inner
            .get(&0x80)
            .ok_or_else(|| anyhow::anyhow!("MGMT AUTH step1: missing tag 80"))?;

        // Step 2: decrypt witness, generate our own challenge, send both.
        let witness_dec = crypto_ecb_decrypt(&key_bytes, witness_enc, block_size)?;
        let challenge: Vec<u8> = (0..block_size).map(|_| rand::random::<u8>()).collect();

        // Build data: 7C <len> [ 80 <len> <decrypted-witness> 81 <len> <challenge> ]
        let mut inner2 = encode_tlv(0x80, &witness_dec);
        inner2.extend(encode_tlv(0x81, &challenge));
        let outer2 = encode_tlv(0x7C, &inner2);

        let mut step2 = vec![0x00, 0x87, p1, 0x9B];
        step2.extend(encode_length(outer2.len()));
        step2.extend(&outer2);

        let resp2 = self.transmit_check(&step2, "MGMT AUTH step2")?;

        // Step 3: verify the card encrypted our challenge correctly.
        let tlv2 = parse_tlv_flat(&resp2);
        let outer_r = tlv2
            .get(&0x7C)
            .ok_or_else(|| anyhow::anyhow!("MGMT AUTH step2: missing tag 7C"))?;
        let tlv_inner_r = parse_tlv_flat(outer_r);
        let challenge_resp = tlv_inner_r
            .get(&0x82)
            .ok_or_else(|| anyhow::anyhow!("MGMT AUTH step2: missing tag 82"))?;

        let challenge_enc = crypto_ecb_encrypt(&key_bytes, &challenge, block_size)?;
        if challenge_enc != *challenge_resp {
            bail!("management key authentication failed: card response mismatch");
        }

        Ok(())
    }

    /// GENERAL AUTHENTICATE ECDH — slot-based key agreement.
    /// Returns the raw shared secret (65-byte uncompressed EC point for P-256).
    pub(crate) fn general_authenticate_ecdh(
        &mut self,
        slot: u8,
        peer_point: &[u8],
    ) -> Result<Vec<u8>> {
        // Data: 7C <len> [ 85 <len> <peer-uncompressed-point> ]
        let inner = encode_tlv(0x85, peer_point);
        let outer = encode_tlv(0x7C, &inner);

        let mut apdu = vec![0x00, 0x87, 0x11, slot]; // P1=0x11 = ECC P-256
        apdu.extend(encode_length(outer.len()));
        apdu.extend(&outer);
        apdu.push(0x00); // Le

        let resp = self.transmit_check(&apdu, "GENERAL AUTHENTICATE ECDH")?;

        // Response: 7C <len> 82 <len> <shared-secret-x-coord>
        let tlv = parse_tlv_flat(&resp);
        let outer_r = tlv
            .get(&0x7C)
            .ok_or_else(|| anyhow::anyhow!("ECDH: missing tag 7C in response"))?;
        let tlv_inner = parse_tlv_flat(outer_r);
        let secret = tlv_inner
            .get(&0x82)
            .ok_or_else(|| anyhow::anyhow!("ECDH: missing tag 82 in response"))?
            .clone();

        Ok(secret)
    }

    /// GENERAL AUTHENTICATE SIGN — produce an EC signature over `digest`.
    /// Returns the DER-encoded signature.
    pub(crate) fn general_authenticate_sign(&mut self, slot: u8, digest: &[u8]) -> Result<Vec<u8>> {
        // Data: 7C <len> [ 82 00  81 <len> <digest> ]
        // Tag 82 = response placeholder; tag 81 = challenge (digest).
        let mut inner = vec![0x82, 0x00];
        inner.extend(encode_tlv(0x81, digest));
        let outer = encode_tlv(0x7C, &inner);

        let mut apdu = vec![0x00, 0x87, 0x11, slot]; // P1=0x11 = ECC P-256
        apdu.extend(encode_length(outer.len()));
        apdu.extend(&outer);
        apdu.push(0x00); // Le

        let resp = self.transmit_check(&apdu, "GENERAL AUTHENTICATE SIGN")?;

        // Response: 7C <len> 82 <len> <signature>
        let tlv = parse_tlv_flat(&resp);
        let outer_r = tlv
            .get(&0x7C)
            .ok_or_else(|| anyhow::anyhow!("SIGN: missing tag 7C in response"))?;
        let tlv_inner = parse_tlv_flat(outer_r);
        let sig = tlv_inner
            .get(&0x82)
            .ok_or_else(|| anyhow::anyhow!("SIGN: missing tag 82 in response"))?
            .clone();

        Ok(sig)
    }

    /// GENERATE ASYMMETRIC KEY — generate an EC P-256 key in `slot`.
    /// Returns the uncompressed public key point (65 bytes).
    /// Caller must authenticate management key first.
    pub(crate) fn generate_key(&mut self, slot: u8) -> Result<Vec<u8>> {
        // Data: AC 03 80 01 11 (algorithm = ECC P-256)
        let apdu = [
            0x00, 0x47, 0x00, slot, 0x05, 0xAC, 0x03, 0x80, 0x01, 0x11, 0x00,
        ];
        let resp = self.transmit_check(&apdu, "GENERATE ASYMMETRIC KEY")?;

        // Response: 7F 49 <len> 86 <len> <uncompressed-point>
        // Note: 7F 49 is a two-byte tag (constructed).
        let point = parse_gen_key_response(&resp)?;
        Ok(point)
    }
}

// ---------------------------------------------------------------------------
// HardwarePiv — stateless struct implementing PivBackend
// ---------------------------------------------------------------------------

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
        let ctx =
            pcsc::Context::establish(pcsc::Scope::User).context("establishing PC/SC context")?;
        let mut buf = vec![0u8; 65536];
        let readers: Vec<String> = ctx
            .list_readers(&mut buf)
            .context("listing PC/SC readers")?
            .map(|cstr| cstr.to_string_lossy().into_owned())
            .collect();
        Ok(readers)
    }

    fn list_devices(&self) -> Result<Vec<DeviceInfo>> {
        let readers = self.list_readers()?;
        let mut devices = Vec::new();
        for reader in &readers {
            if let Ok(serial) = serial_from_reader(reader) {
                let version = version_from_reader(reader).unwrap_or_else(|| "unknown".to_owned());
                devices.push(DeviceInfo {
                    serial,
                    version,
                    reader: reader.clone(),
                });
            }
        }
        Ok(devices)
    }

    fn read_object(&self, reader: &str, id: u32) -> Result<Vec<u8>> {
        let mut session = PcscSession::open(reader)?;
        session.get_data(id)
    }

    fn write_object(
        &self,
        reader: &str,
        id: u32,
        data: &[u8],
        management_key: Option<&str>,
        pin: Option<&str>,
    ) -> Result<()> {
        let mut session = PcscSession::open(reader)?;
        let key_hex: String;
        let effective_key: &str = if let Some(k) = management_key {
            k
        } else if let Some(p) = pin {
            // PIN-protected management key: VERIFY PIN then GET DATA (PRINTED)
            // — all in one session so the YubiKey accepts the subsequent PUT DATA.
            session.verify_pin(p)?;
            let raw = session.get_data(OBJ_PRINTED)?;
            key_hex = extract_pin_protected_key(&raw)?;
            &key_hex
        } else {
            bail!("write_object: management_key or pin required");
        };
        session.authenticate_management_key(effective_key)?;
        session.put_data(id, data)
    }

    fn verify_pin(&self, reader: &str, pin: &str) -> Result<()> {
        let mut session = PcscSession::open(reader)?;
        session.verify_pin(pin)
    }

    fn send_apdu(&self, reader: &str, apdu: &[u8]) -> Result<Vec<u8>> {
        let mut session = PcscSession::open(reader)?;
        session.transmit_check(apdu, "send_apdu")
    }

    fn ecdh(
        &self,
        reader: &str,
        slot: u8,
        peer_point: &[u8],
        pin: Option<&str>,
    ) -> Result<Vec<u8>> {
        let mut session = PcscSession::open(reader)?;
        if let Some(p) = pin {
            session.verify_pin(p)?;
        }
        session.general_authenticate_ecdh(slot, peer_point)
    }

    fn read_certificate(&self, reader: &str, slot: u8) -> Result<Vec<u8>> {
        let object_id = slot_to_object_id(slot)?;
        let mut session = PcscSession::open(reader)?;
        let raw = session.get_data(object_id)?;
        // Cert TLV: 53 <len> [ 70 <len> <DER cert> 71 01 00 FE 00 ]
        // get_data already stripped the outer 53 wrapper.
        // Now parse the inner TLV for tag 0x70.
        let inner = parse_tlv_flat(&raw);
        inner
            .get(&0x70)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("cert object for slot 0x{slot:02x}: missing tag 0x70"))
    }

    fn generate_key(
        &self,
        reader: &str,
        slot: u8,
        management_key: Option<&str>,
    ) -> Result<Vec<u8>> {
        let mut session = PcscSession::open(reader)?;
        if let Some(key) = management_key {
            session.authenticate_management_key(key)?;
        }
        session.generate_key(slot)
    }

    fn generate_certificate(
        &self,
        reader: &str,
        slot: u8,
        subject: &str,
        management_key: Option<&str>,
        pin: Option<&str>,
    ) -> Result<Vec<u8>> {
        use rcgen::{
            CertificateParams, DistinguishedName, DnType, KeyPair, RemoteKeyPair,
            SignatureAlgorithm, PKCS_ECDSA_P256_SHA256,
        };
        use sha2::{Digest, Sha256};
        use std::sync::Mutex;

        // ---- Step 1: resolve management key, authenticate, generate key ----
        let mut session = PcscSession::open(reader)?;
        let key_hex: String;
        let effective_key: &str = if let Some(k) = management_key {
            k
        } else if let Some(p) = pin {
            session.verify_pin(p)?;
            let raw = session.get_data(OBJ_PRINTED)?;
            key_hex = extract_pin_protected_key(&raw)?;
            &key_hex
        } else {
            bail!("generate_certificate: management_key or pin required");
        };
        session.authenticate_management_key(effective_key)?;
        let pubkey_point = session.generate_key(slot)?;
        let mgmt_key_owned = effective_key.to_owned();
        drop(session);

        // ---- Step 2: self-signed certificate via rcgen + YubiKey SIGN ----
        let reader_owned = reader.to_owned();
        let pin_owned = pin.map(|p| p.to_owned());

        struct YubikeyRemotePair {
            slot: u8,
            pubkey_point: Vec<u8>,
            session: Mutex<PcscSession>,
        }

        impl RemoteKeyPair for YubikeyRemotePair {
            fn public_key(&self) -> &[u8] {
                &self.pubkey_point
            }

            fn sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, rcgen::Error> {
                let digest = Sha256::digest(msg);
                let mut s = self.session.lock().unwrap();
                s.general_authenticate_sign(self.slot, &digest)
                    .map_err(|_| rcgen::Error::RemoteKeyError)
            }

            fn algorithm(&self) -> &'static SignatureAlgorithm {
                &PKCS_ECDSA_P256_SHA256
            }
        }

        let mut sign_session = PcscSession::open(&reader_owned)?;
        if let Some(ref p) = pin_owned {
            sign_session.verify_pin(p)?;
        }
        let remote = YubikeyRemotePair {
            slot,
            pubkey_point: pubkey_point.clone(),
            session: Mutex::new(sign_session),
        };
        let key_pair = KeyPair::from_remote(Box::new(remote))
            .map_err(|e| anyhow::anyhow!("rcgen KeyPair: {e}"))?;

        let mut params = CertificateParams::new(vec![])
            .map_err(|e| anyhow::anyhow!("CertificateParams: {e}"))?;
        let mut dn = DistinguishedName::new();
        for part in subject.split('/').filter(|s| !s.is_empty()) {
            if let Some((key, val)) = part.split_once('=') {
                match key.trim() {
                    "CN" => dn.push(DnType::CommonName, val.trim()),
                    "O" => dn.push(DnType::OrganizationName, val.trim()),
                    "OU" => dn.push(DnType::OrganizationalUnitName, val.trim()),
                    _ => {}
                }
            }
        }
        params.distinguished_name = dn;
        params.not_before = rcgen::date_time_ymd(2025, 1, 1);
        params.not_after = rcgen::date_time_ymd(2035, 1, 1);

        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| anyhow::anyhow!("self_signed: {e}"))?;
        let cert_der = cert.der().to_vec();
        drop(key_pair); // releases sign_session before opening write_session

        // ---- Step 3: import certificate ----
        let object_id = slot_to_object_id(slot)?;
        let mut write_session = PcscSession::open(&reader_owned)?;
        write_session.authenticate_management_key(&mgmt_key_owned)?;
        // Cert TLV: 53 <len> [ 70 <len> <DER> 71 01 00 FE 00 ]
        let mut inner = encode_tlv(0x70, &cert_der);
        inner.extend_from_slice(&[0x71, 0x01, 0x00, 0xFE, 0x00]);
        write_session.put_data(object_id, &inner)?;

        Ok(cert_der)
    }
}

// ---------------------------------------------------------------------------
// Low-level helpers
// ---------------------------------------------------------------------------

/// PIV object ID for the PRINTED object (holds the PIN-protected management key).
const OBJ_PRINTED: u32 = 0x5F_C109;

/// Parse the management key from the raw bytes of the PRINTED object.
/// TLV structure: 88 <len> [ 89 <len> <key_bytes> ]
fn extract_pin_protected_key(raw: &[u8]) -> Result<String> {
    let outer = parse_tlv_flat(raw);
    let inner_bytes = outer
        .get(&0x88)
        .ok_or_else(|| anyhow::anyhow!("PRINTED object missing tag 0x88"))?;
    let inner = parse_tlv_flat(inner_bytes);
    let key_bytes = inner
        .get(&0x89)
        .ok_or_else(|| anyhow::anyhow!("PRINTED object missing tag 0x89 inside 0x88"))?;
    Ok(hex::encode(key_bytes))
}

/// Transmit an APDU via a `&pcsc::Card` (or anything that derefs to it, like `Transaction`).
fn transmit_raw_card(card: &pcsc::Card, apdu: &[u8]) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; pcsc::MAX_BUFFER_SIZE_EXTENDED];
    let resp = card.transmit(apdu, &mut buf).context("APDU transmit")?;
    Ok(resp.to_vec())
}

fn connect_reader(ctx: &pcsc::Context, reader: &str) -> Result<pcsc::Card> {
    connect_reader_mode(ctx, reader, pcsc::ShareMode::Shared)
}

fn connect_reader_mode(
    ctx: &pcsc::Context,
    reader: &str,
    mode: pcsc::ShareMode,
) -> Result<pcsc::Card> {
    let mut name = reader.to_owned();
    name.push('\0');
    let cstr = std::ffi::CStr::from_bytes_with_nul(name.as_bytes())
        .map_err(|e| anyhow::anyhow!("reader name: {e}"))?;
    ctx.connect(cstr, mode, pcsc::Protocols::ANY)
        .map_err(|e| anyhow::anyhow!("connecting to reader '{reader}': {e}"))
}

fn serial_from_reader(reader: &str) -> Result<u32> {
    let ctx = pcsc::Context::establish(pcsc::Scope::User)?;
    let card = connect_reader(&ctx, reader)?;
    let mut buf = vec![0u8; 258];

    let select_piv = &[0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08];
    let _ = card.transmit(select_piv, &mut buf)?;

    let get_serial = &[0x00, 0xF8, 0x00, 0x00, 0x00];
    let resp = card.transmit(get_serial, &mut buf)?;
    if resp.len() < 6 {
        bail!("GET_SERIAL response too short");
    }
    Ok(u32::from_be_bytes(resp[0..4].try_into().unwrap()))
}

fn version_from_reader(reader: &str) -> Option<String> {
    let ctx = pcsc::Context::establish(pcsc::Scope::User).ok()?;
    let card = connect_reader(&ctx, reader).ok()?;
    let mut buf = vec![0u8; 258];

    let select_piv = &[0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08];
    let _ = card.transmit(select_piv, &mut buf).ok()?;

    let get_ver = &[0x00, 0xFD, 0x00, 0x00, 0x00];
    let resp = card.transmit(get_ver, &mut buf).ok()?;
    if resp.len() < 5 {
        return None;
    }
    Some(format!("{}.{}.{}", resp[0], resp[1], resp[2]))
}

/// Map a PIV slot byte to its data object ID (NIST SP 800-73-4 Table 3).
pub fn slot_to_object_id(slot: u8) -> Result<u32> {
    match slot {
        0x9a => Ok(0x5F_C105),
        0x9c => Ok(0x5F_C10A),
        0x9d => Ok(0x5F_C10B),
        0x9e => Ok(0x5F_C101),
        0x82 => Ok(0x5F_C10D),
        0x83 => Ok(0x5F_C10E),
        0x84 => Ok(0x5F_C10F),
        0x85 => Ok(0x5F_C110),
        0x86 => Ok(0x5F_C111),
        0x87 => Ok(0x5F_C112),
        0x88 => Ok(0x5F_C113),
        0x89 => Ok(0x5F_C114),
        0x8a => Ok(0x5F_C115),
        0x8b => Ok(0x5F_C116),
        0x8c => Ok(0x5F_C117),
        0x8d => Ok(0x5F_C118),
        0x8e => Ok(0x5F_C119),
        0x8f => Ok(0x5F_C11A),
        0x90 => Ok(0x5F_C11B),
        0x91 => Ok(0x5F_C11C),
        0x92 => Ok(0x5F_C11D),
        0x93 => Ok(0x5F_C11E),
        0x94 => Ok(0x5F_C11F),
        0x95 => Ok(0x5F_C120),
        _ => bail!("unsupported PIV slot 0x{slot:02x}"),
    }
}

// ---------------------------------------------------------------------------
// TLV encoding / decoding
// ---------------------------------------------------------------------------

/// Parse a flat BER-TLV sequence into a single-byte-tag → value map.
pub(crate) fn parse_tlv_flat(data: &[u8]) -> std::collections::HashMap<u8, Vec<u8>> {
    use std::collections::HashMap;
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

/// Encode `tag || length || value`.
pub(crate) fn encode_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(encode_length(value.len()));
    out.extend_from_slice(value);
    out
}

fn encode_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len <= 0xFF {
        vec![0x81, len as u8]
    } else if len <= 0xFFFF {
        vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
    } else {
        panic!("length too large for BER encoding: {len}");
    }
}

/// Strip the outer `53 <len>` wrapper from a GET DATA response.
fn parse_tlv53(data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    if data[0] != 0x53 {
        bail!(
            "GET DATA response: expected tag 0x53, got 0x{:02x}",
            data[0]
        );
    }
    let (len, consumed) = decode_length(&data[1..]);
    let start = 1 + consumed;
    if start + len > data.len() {
        bail!(
            "GET DATA response: truncated TLV (len={len}, available={})",
            data.len() - start
        );
    }
    Ok(data[start..start + len].to_vec())
}

/// Parse the GENERATE ASYMMETRIC KEY response to extract the public key point.
/// Response: 7F 49 <len> 86 <len> <65-byte-uncompressed-point>
fn parse_gen_key_response(data: &[u8]) -> Result<Vec<u8>> {
    // 7F 49 is a constructed two-byte tag.
    if data.len() < 2 || data[0] != 0x7F || data[1] != 0x49 {
        bail!("GENERATE KEY response: expected tag 7F 49");
    }
    let (outer_len, consumed) = decode_length(&data[2..]);
    let inner_start = 2 + consumed;
    if inner_start + outer_len > data.len() {
        bail!("GENERATE KEY response: truncated");
    }
    let inner = &data[inner_start..inner_start + outer_len];

    // Inside: 86 <len> <point>
    if inner.is_empty() || inner[0] != 0x86 {
        bail!(
            "GENERATE KEY inner: expected tag 0x86, got 0x{:02x}",
            inner.first().unwrap_or(&0)
        );
    }
    let (point_len, point_consumed) = decode_length(&inner[1..]);
    let point_start = 1 + point_consumed;
    if point_start + point_len > inner.len() {
        bail!("GENERATE KEY inner: truncated point");
    }
    Ok(inner[point_start..point_start + point_len].to_vec())
}

// ---------------------------------------------------------------------------
// Management key crypto (3DES / AES ECB for the 3-pass mutual auth)
// ---------------------------------------------------------------------------

fn crypto_ecb_decrypt(key: &[u8], data: &[u8], block_size: usize) -> Result<Vec<u8>> {
    if data.len() != block_size {
        bail!(
            "ECB decrypt: data length {} != block size {}",
            data.len(),
            block_size
        );
    }
    match key.len() {
        24 => {
            // 3DES
            use des::cipher::{BlockDecrypt, KeyInit};
            use des::TdesEde3;
            let cipher =
                TdesEde3::new_from_slice(key).map_err(|e| anyhow::anyhow!("3DES key: {e}"))?;
            let mut block = des::cipher::generic_array::GenericArray::clone_from_slice(data);
            cipher.decrypt_block(&mut block);
            Ok(block.to_vec())
        }
        16 | 32 => {
            // AES-128 or AES-256
            use aes::cipher::{BlockDecrypt, KeyInit};
            let out = if key.len() == 16 {
                let cipher = aes::Aes128::new_from_slice(key)
                    .map_err(|e| anyhow::anyhow!("AES-128 key: {e}"))?;
                let mut block = aes::cipher::generic_array::GenericArray::clone_from_slice(data);
                cipher.decrypt_block(&mut block);
                block.to_vec()
            } else {
                let cipher = aes::Aes256::new_from_slice(key)
                    .map_err(|e| anyhow::anyhow!("AES-256 key: {e}"))?;
                let mut block = aes::cipher::generic_array::GenericArray::clone_from_slice(data);
                cipher.decrypt_block(&mut block);
                block.to_vec()
            };
            Ok(out)
        }
        n => bail!("unsupported key length for ECB: {n}"),
    }
}

fn crypto_ecb_encrypt(key: &[u8], data: &[u8], block_size: usize) -> Result<Vec<u8>> {
    if data.len() != block_size {
        bail!(
            "ECB encrypt: data length {} != block size {}",
            data.len(),
            block_size
        );
    }
    match key.len() {
        24 => {
            use des::cipher::{BlockEncrypt, KeyInit};
            use des::TdesEde3;
            let cipher =
                TdesEde3::new_from_slice(key).map_err(|e| anyhow::anyhow!("3DES key: {e}"))?;
            let mut block = des::cipher::generic_array::GenericArray::clone_from_slice(data);
            cipher.encrypt_block(&mut block);
            Ok(block.to_vec())
        }
        16 | 32 => {
            use aes::cipher::{BlockEncrypt, KeyInit};
            let out = if key.len() == 16 {
                let cipher = aes::Aes128::new_from_slice(key)
                    .map_err(|e| anyhow::anyhow!("AES-128 key: {e}"))?;
                let mut block = aes::cipher::generic_array::GenericArray::clone_from_slice(data);
                cipher.encrypt_block(&mut block);
                block.to_vec()
            } else {
                let cipher = aes::Aes256::new_from_slice(key)
                    .map_err(|e| anyhow::anyhow!("AES-256 key: {e}"))?;
                let mut block = aes::cipher::generic_array::GenericArray::clone_from_slice(data);
                cipher.encrypt_block(&mut block);
                block.to_vec()
            };
            Ok(out)
        }
        n => bail!("unsupported key length for ECB: {n}"),
    }
}
