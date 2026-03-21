// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Hardware PIV backend — communicates directly with the YubiKey PIV applet
//! via PC/SC APDUs (NIST SP 800-73-4).  No external subprocesses required.

use super::{session, tlv, DeviceInfo, FlashHandle, PivBackend};
use anyhow::{bail, Context, Result};
use session::{serial_from_reader, version_from_reader, PcscSession, SELECT_PIV};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

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
        session.resolve_and_auth_management_key(management_key, pin, "write_object")?;
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
        let inner = crate::auxiliaries::parse_tlv_flat(&raw);
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

    fn read_printed_object_with_pin(&self, reader: &str, pin: &str) -> Result<Vec<u8>> {
        use crate::auxiliaries::OBJ_PRINTED;
        let mut session = PcscSession::open(reader)?;
        session.verify_pin(pin)?;
        session.get_data(OBJ_PRINTED)
    }

    fn generate_certificate(
        &self,
        reader: &str,
        slot: u8,
        subject: &str,
        management_key: Option<&str>,
        pin: Option<&str>,
    ) -> Result<Vec<u8>> {
        use crate::auxiliaries::parse_subject_dn;
        use rcgen::{
            CertificateParams, KeyPair, RemoteKeyPair, SignatureAlgorithm, PKCS_ECDSA_P256_SHA256,
        };
        use sha2::{Digest, Sha256};
        use std::sync::Mutex;

        // ---- Step 1: resolve management key, authenticate, generate key ----
        let mut session = PcscSession::open(reader)?;
        let mgmt_key_owned =
            session.resolve_and_auth_management_key(management_key, pin, "generate_certificate")?;
        let pubkey_point = session.generate_key(slot)?;
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
        params.distinguished_name = parse_subject_dn(subject);
        params.not_before = rcgen::date_time_ymd(2000, 1, 1);
        params.not_after = rcgen::date_time_ymd(9999, 12, 31);

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
        let mut inner = tlv::encode_tlv(0x70, &cert_der);
        inner.extend_from_slice(&[0x71, 0x01, 0x00, 0xFE, 0x00]);
        write_session.put_data(object_id, &inner)?;

        Ok(cert_der)
    }

    fn start_flash(&self, reader: &str, on_ms: u64, off_ms: u64) -> Box<dyn FlashHandle> {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = Arc::clone(&stop);
        let reader_owned = reader.to_owned();

        let _ = std::thread::Builder::new()
            .name("yb-flash".to_owned())
            .spawn(move || {
                flash_loop(&reader_owned, on_ms, off_ms, &stop_clone);
            });

        Box::new(HardwareFlash { stop })
    }
}

// ---------------------------------------------------------------------------
// HardwareFlash — flash handle for real YubiKey
// ---------------------------------------------------------------------------

pub struct HardwareFlash {
    stop: Arc<AtomicBool>,
}

impl FlashHandle for HardwareFlash {}

impl Drop for HardwareFlash {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Background loop: blink the LED on the YubiKey.
///
/// ## How the LED is controlled
///
/// The YubiKey has no dedicated "blink" command.  The LED lights when the card
/// processes an APDU and goes dark when power is removed.  Specifically:
///
/// - `SCardConnect` powers the card up (brief transient flash).
/// - `SELECT PIV` (00 A4 04 00 05 A0 00 00 03 08) lights the LED while the
///   card is processing — the LED stays on as long as the connection is open.
/// - `SCardDisconnect(SCARD_UNPOWER_CARD)` cuts power immediately → LED off.
/// - Keeping the connection open indefinitely leaves the LED continuously lit.
///
/// ## Cycle structure
///
/// To produce a clean blink the loop reconnects on every cycle:
///
/// ```text
/// connect (power-up transient)
/// loop:
///   SELECT_PIV → LED on
///   sleep on_ms
///   disconnect(UnpowerCard) → LED off
///   sleep off_ms
///   connect (power-up transient, absorbed into next on-period)
/// ```
///
/// The power-up transient on `connect` is brief and indistinguishable from the
/// intentional flash because it is immediately followed by SELECT_PIV.
///
/// ## Known residual noise
///
/// A faint off/on dip (~50 ms) occurs every ~3 seconds regardless of timing.
/// This is intrinsic YubiKey firmware behavior (observed on YubiKey 5 series):
/// the device performs a periodic internal housekeeping operation that briefly
/// interrupts LED state.  It cannot be suppressed from the host side; we accept
/// it as an unavoidable artifact.
///
/// Any PC/SC error (card removed, USB glitch) silently terminates the loop.
/// The thread never panics the process.
fn flash_loop(reader: &str, on_ms: u64, off_ms: u64, stop: &AtomicBool) {
    let ctx = match pcsc::Context::establish(pcsc::Scope::User) {
        Ok(c) => c,
        Err(_) => return,
    };
    let reader_cstr = match std::ffi::CString::new(reader) {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut buf = vec![0u8; pcsc::MAX_BUFFER_SIZE_EXTENDED];

    // Sleep helpers: check stop flag every 10 ms for responsiveness.
    let on_ticks = (on_ms / 10).max(1);
    let off_ticks = (off_ms / 10).max(1);

    // Initial connect before the loop.
    let mut card = match ctx.connect(&reader_cstr, pcsc::ShareMode::Shared, pcsc::Protocols::ANY) {
        Ok(c) => c,
        Err(_) => return,
    };

    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        // SELECT PIV → LED on.
        if card.transmit(SELECT_PIV, &mut buf).is_err() {
            break;
        }
        // Hold on-period.
        for _ in 0..on_ticks {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        // UnpowerCard → LED off immediately.
        if card.disconnect(pcsc::Disposition::UnpowerCard).is_err() {
            break;
        }
        // Off-period.
        for _ in 0..off_ticks {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        // Reconnect — power-up transient is absorbed into the next on-period.
        card = match ctx.connect(&reader_cstr, pcsc::ShareMode::Shared, pcsc::Protocols::ANY) {
            Ok(c) => c,
            Err(_) => return,
        };
    }
}

// ---------------------------------------------------------------------------
// PIV slot → object ID mapping
// ---------------------------------------------------------------------------

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
