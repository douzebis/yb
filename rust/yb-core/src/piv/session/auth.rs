// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! PIN verification and management-key authentication.

use super::transport::{sw_description, PcscSession};
use crate::auxiliaries::{extract_pin_protected_key, OBJ_PRINTED};
use crate::piv::mgmt::{parse_mgmt_metadata, MgmtAlgo, GET_METADATA_MGMT};
use crate::piv::tlv::{crypto_ecb, encode_length, encode_tlv, EcbDir};
use anyhow::{bail, Context, Result};
use std::sync::Once;
use subtle::ConstantTimeEq;

use super::crypto::tlv_get;

/// The touch-policy warning is printed at most once per process, however
/// many sessions authenticate.
static TOUCH_WARNING: Once = Once::new();

impl PcscSession {
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
        match (sw1, sw2) {
            (0x90, 0x00) => Ok(()),
            (0x63, n) => bail!("VERIFY PIN failed: {} retries remaining", n & 0x0f),
            (0x69, 0x83) => bail!("VERIFY PIN failed: PIN blocked"),
            (s1, s2) => bail!("VERIFY PIN failed: SW={s1:02x}{s2:02x}"),
        }
    }

    /// Return the algorithm of the card's management key.
    ///
    /// Sends GET METADATA (slot 9B) on first use and caches the result for
    /// the rest of the session.  Firmware without GET METADATA (< 5.3,
    /// SW=6D00) only supports 3DES management keys, so 3DES is assumed.
    pub(crate) fn management_key_algorithm(&mut self) -> Result<MgmtAlgo> {
        if let Some(algo) = self.mgmt_algo {
            return Ok(algo);
        }
        let resp = self.transmit_raw(&GET_METADATA_MGMT)?;
        let n = resp.len();
        if n < 2 {
            bail!("GET METADATA (management key): response too short");
        }
        let algo = match (resp[n - 2], resp[n - 1]) {
            (0x90, 0x00) => {
                let md = parse_mgmt_metadata(&resp[..n - 2])?;
                if md.touch_required {
                    TOUCH_WARNING.call_once(|| {
                        eprintln!(
                            "Warning: this YubiKey's management key requires touch; \
                             touch the key when it blinks during write operations."
                        );
                    });
                }
                md.algo
            }
            (0x6D, 0x00) => MgmtAlgo::Tdes,
            (s1, s2) => bail!(
                "GET METADATA (management key) failed: SW={s1:02x}{s2:02x} ({})",
                sw_description(s1, s2)
            ),
        };
        self.mgmt_algo = Some(algo);
        Ok(algo)
    }

    /// Record the algorithm of a management key just installed with
    /// SET MANAGEMENT KEY, keeping the session cache accurate.
    pub(crate) fn set_cached_management_key_algorithm(&mut self, algo: MgmtAlgo) {
        self.mgmt_algo = Some(algo);
    }

    /// Authenticate the management key using GENERAL AUTHENTICATE (3-pass
    /// mutual auth), with the algorithm reported by the card.
    pub(crate) fn authenticate_management_key(&mut self, key_hex: &str) -> Result<()> {
        let key_bytes = hex::decode(key_hex).context("decoding management key")?;
        let algo = self.management_key_algorithm()?;
        algo.check_key_len(&key_bytes)?;
        self.mutual_auth(algo, &key_bytes)
            .with_context(|| format!("authenticating with the {algo} management key"))
    }

    fn mutual_auth(&mut self, algo: MgmtAlgo, key_bytes: &[u8]) -> Result<()> {
        let p1 = algo.id();
        let block_size = algo.block_size();

        // Step 1: request witness (card encrypts a challenge).
        let step1 = [0x00, 0x87, p1, 0x9B, 0x04, 0x7C, 0x02, 0x80, 0x00];
        let resp1 = self.transmit_check(&step1, "MGMT AUTH step1")?;

        // Parse: 7C <len> 80 <len> <witness>
        let outer = tlv_get(&resp1, 0x7C, "MGMT AUTH step1")?;
        let witness_enc = tlv_get(&outer, 0x80, "MGMT AUTH step1")?;

        // Step 2: decrypt witness, generate our own challenge, send both.
        let witness_dec = crypto_ecb(algo, key_bytes, &witness_enc, EcbDir::Decrypt)?;
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
        let outer_r = tlv_get(&resp2, 0x7C, "MGMT AUTH step2")?;
        let challenge_resp = tlv_get(&outer_r, 0x82, "MGMT AUTH step2")?;

        let challenge_enc = crypto_ecb(algo, key_bytes, &challenge, EcbDir::Encrypt)?;
        if challenge_enc.ct_eq(&challenge_resp).unwrap_u8() == 0 {
            bail!("management key authentication failed: card response mismatch");
        }

        Ok(())
    }

    /// Resolve the management key from three sources, in priority order:
    /// 1. Explicit `management_key` argument.
    /// 2. PIN-protected object on the device (requires verifying `pin` first).
    /// 3. Fails with a helpful message if neither is available.
    ///
    /// Does **not** authenticate — call [`authenticate_management_key`] with
    /// the returned key to complete the process.
    pub(crate) fn resolve_management_key(
        &mut self,
        management_key: Option<&str>,
        pin: Option<&str>,
        caller: &str,
    ) -> Result<String> {
        if let Some(k) = management_key {
            return Ok(k.to_owned());
        }
        if let Some(p) = pin {
            self.verify_pin(p)?;
            let raw = self.get_data(OBJ_PRINTED).map_err(|_| {
                anyhow::anyhow!(
                    "management key not found on device; \
                     supply it via YB_MANAGEMENT_KEY or the --key flag"
                )
            })?;
            return extract_pin_protected_key(&raw);
        }
        bail!("{caller}: management_key or pin required");
    }

    /// Resolve the management key and authenticate in one step.
    pub(crate) fn resolve_and_auth_management_key(
        &mut self,
        management_key: Option<&str>,
        pin: Option<&str>,
        caller: &str,
    ) -> Result<String> {
        let key = self.resolve_management_key(management_key, pin, caller)?;
        self.authenticate_management_key(&key)?;
        Ok(key)
    }
}
