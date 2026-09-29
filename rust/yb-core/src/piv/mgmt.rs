// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! PIV management key algorithms and GET METADATA parsing (spec 0021).
//!
//! The management key's algorithm is read from the card (GET METADATA on
//! slot 9B) instead of being inferred from the key length: a 24-byte key
//! may be 3DES (firmware < 5.7 default) or AES-192 (firmware 5.7+ default).

use anyhow::{bail, Result};
use std::fmt;

/// GET METADATA for the management key slot (9B).  Firmware 5.3+.
pub const GET_METADATA_MGMT: [u8; 5] = [0x00, 0xF7, 0x00, 0x9B, 0x00];
/// GET METADATA for the PIN (reference 0x80).  Firmware 5.3+.
pub const GET_METADATA_PIN: [u8; 5] = [0x00, 0xF7, 0x00, 0x80, 0x00];
/// GET METADATA for the PUK (reference 0x81).  Firmware 5.3+.
pub const GET_METADATA_PUK: [u8; 5] = [0x00, 0xF7, 0x00, 0x81, 0x00];

/// GET METADATA for a key slot.  Firmware 5.3+.
pub(crate) fn get_metadata_apdu(slot: u8) -> [u8; 5] {
    [0x00, 0xF7, 0x00, slot, 0x00]
}

// GET METADATA response tags.
const TAG_ALGORITHM: u8 = 0x01;
const TAG_POLICY: u8 = 0x02;
const TAG_ORIGIN: u8 = 0x03;
const TAG_IS_DEFAULT: u8 = 0x05;
const TAG_RETRIES: u8 = 0x06;

// Touch policy values (second byte of TAG_POLICY).
const TOUCH_ALWAYS: u8 = 0x02;
const TOUCH_CACHED: u8 = 0x03;

/// Algorithm of the PIV management key (slot 9B).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MgmtAlgo {
    Tdes,
    Aes128,
    Aes192,
    Aes256,
}

impl MgmtAlgo {
    /// Map a PIV algorithm identifier to a management key algorithm.
    pub fn from_id(id: u8) -> Option<Self> {
        match id {
            0x03 => Some(Self::Tdes),
            0x08 => Some(Self::Aes128),
            0x0A => Some(Self::Aes192),
            0x0C => Some(Self::Aes256),
            _ => None,
        }
    }

    /// PIV algorithm identifier (P1 of GENERAL AUTHENTICATE, first byte of
    /// SET MANAGEMENT KEY data).
    pub fn id(self) -> u8 {
        match self {
            Self::Tdes => 0x03,
            Self::Aes128 => 0x08,
            Self::Aes192 => 0x0A,
            Self::Aes256 => 0x0C,
        }
    }

    /// Key length in bytes.
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Tdes | Self::Aes192 => 24,
            Self::Aes256 => 32,
        }
    }

    /// Cipher block size in bytes (challenge/witness length).
    pub fn block_size(self) -> usize {
        match self {
            Self::Tdes => 8,
            Self::Aes128 | Self::Aes192 | Self::Aes256 => 16,
        }
    }

    /// Parse a name as used in fixture files: `TDES`, `AES128`, `AES192`,
    /// `AES256` (case-insensitive; `3DES` and dashes are accepted).
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_uppercase().replace('-', "").as_str() {
            "TDES" | "3DES" => Some(Self::Tdes),
            "AES128" => Some(Self::Aes128),
            "AES192" => Some(Self::Aes192),
            "AES256" => Some(Self::Aes256),
            _ => None,
        }
    }

    /// Fail unless `key` has exactly this algorithm's key length.
    pub fn check_key_len(self, key: &[u8]) -> Result<()> {
        if key.len() != self.key_len() {
            bail!(
                "management key is {} bytes but the card uses {} ({} bytes)",
                key.len(),
                self,
                self.key_len()
            );
        }
        Ok(())
    }
}

impl fmt::Display for MgmtAlgo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Tdes => "3DES",
            Self::Aes128 => "AES-128",
            Self::Aes192 => "AES-192",
            Self::Aes256 => "AES-256",
        })
    }
}

/// Touch policy of a key, from GET METADATA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TouchPolicy {
    Never,
    Always,
    Cached,
}

/// Management key metadata reported by GET METADATA (slot 9B).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MgmtMetadata {
    pub algo: MgmtAlgo,
    pub touch: TouchPolicy,
    /// The key is the factory default.
    pub is_default: bool,
}

impl MgmtMetadata {
    /// Touch policy is "always" or "cached": authentication needs a touch.
    pub fn touch_required(&self) -> bool {
        self.touch != TouchPolicy::Never
    }
}

/// PIN or PUK metadata reported by GET METADATA (reference 80/81).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialMetadata {
    /// The value is the factory default.
    pub is_default: bool,
    pub retries_total: u8,
    pub retries_left: u8,
}

/// Where the key in a slot comes from, per GET METADATA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyOrigin {
    Generated,
    Imported,
}

/// Key slot metadata reported by GET METADATA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotMetadata {
    /// PIV algorithm identifier (e.g. `0x11` for EC P-256).
    pub algorithm: u8,
    pub origin: Option<KeyOrigin>,
}

/// Name of a PIV key algorithm identifier, for reports.
pub fn key_algorithm_name(id: u8) -> String {
    match id {
        0x06 => "RSA 1024".to_owned(),
        0x07 => "RSA 2048".to_owned(),
        0x05 => "RSA 3072".to_owned(),
        0x16 => "RSA 4096".to_owned(),
        0x11 => "EC P-256".to_owned(),
        0x14 => "EC P-384".to_owned(),
        0xE0 => "Ed25519".to_owned(),
        0xE1 => "X25519".to_owned(),
        other => format!("algorithm 0x{other:02x}"),
    }
}

/// PIV algorithm identifier of EC P-256.
pub const ALGO_ECCP256: u8 = 0x11;

fn is_default_flag(tlv: &std::collections::HashMap<u8, Vec<u8>>) -> bool {
    tlv.get(&TAG_IS_DEFAULT).map(Vec::as_slice) == Some(&[0x01])
}

/// Parse the data of a GET METADATA (PIN or PUK) response.
pub(crate) fn parse_credential_metadata(data: &[u8]) -> Result<CredentialMetadata> {
    let tlv = crate::auxiliaries::parse_tlv_flat(data);
    let (retries_total, retries_left) = match tlv.get(&TAG_RETRIES).map(Vec::as_slice) {
        Some([total, left]) => (*total, *left),
        _ => bail!("GET METADATA (PIN/PUK): missing retry counters"),
    };
    Ok(CredentialMetadata {
        is_default: is_default_flag(&tlv),
        retries_total,
        retries_left,
    })
}

/// Parse the data of a GET METADATA (key slot) response.
pub(crate) fn parse_slot_metadata(data: &[u8]) -> Result<SlotMetadata> {
    let tlv = crate::auxiliaries::parse_tlv_flat(data);
    let algorithm = match tlv.get(&TAG_ALGORITHM).map(Vec::as_slice) {
        Some([id]) => *id,
        _ => bail!("GET METADATA (key slot): missing algorithm"),
    };
    let origin = match tlv.get(&TAG_ORIGIN).map(Vec::as_slice) {
        Some([0x01]) => Some(KeyOrigin::Generated),
        Some([0x02]) => Some(KeyOrigin::Imported),
        _ => None,
    };
    Ok(SlotMetadata { algorithm, origin })
}

/// Parse the data of a GET METADATA (slot 9B) response.
pub(crate) fn parse_mgmt_metadata(data: &[u8]) -> Result<MgmtMetadata> {
    let tlv = crate::auxiliaries::parse_tlv_flat(data);
    let id = match tlv.get(&TAG_ALGORITHM).map(Vec::as_slice) {
        Some([id]) => *id,
        _ => bail!("GET METADATA (management key): missing algorithm"),
    };
    let algo = MgmtAlgo::from_id(id)
        .ok_or_else(|| anyhow::anyhow!("unsupported management key algorithm 0x{id:02x}"))?;
    let touch = match tlv.get(&TAG_POLICY).map(Vec::as_slice) {
        Some([_, TOUCH_ALWAYS]) => TouchPolicy::Always,
        Some([_, TOUCH_CACHED]) => TouchPolicy::Cached,
        _ => TouchPolicy::Never,
    };
    Ok(MgmtMetadata {
        algo,
        touch,
        is_default: is_default_flag(&tlv),
    })
}

/// Parse the data of a GET METADATA (PIN or PUK) response and return the
/// number of retries remaining, or `None` if the response has no retry count.
pub(crate) fn parse_retries_remaining(data: &[u8]) -> Option<u8> {
    let tlv = crate::auxiliaries::parse_tlv_flat(data);
    match tlv.get(&TAG_RETRIES).map(Vec::as_slice) {
        Some([_total, remaining]) => Some(*remaining),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_round_trip() {
        for algo in [
            MgmtAlgo::Tdes,
            MgmtAlgo::Aes128,
            MgmtAlgo::Aes192,
            MgmtAlgo::Aes256,
        ] {
            assert_eq!(MgmtAlgo::from_id(algo.id()), Some(algo));
        }
        assert_eq!(MgmtAlgo::from_id(0x07), None);
    }

    #[test]
    fn tdes_and_aes192_share_key_length() {
        // The reason the algorithm cannot be inferred from the key length.
        assert_eq!(MgmtAlgo::Tdes.key_len(), MgmtAlgo::Aes192.key_len());
        assert_ne!(MgmtAlgo::Tdes.block_size(), MgmtAlgo::Aes192.block_size());
    }

    #[test]
    fn from_name_accepts_fixture_spellings() {
        assert_eq!(MgmtAlgo::from_name("TDES"), Some(MgmtAlgo::Tdes));
        assert_eq!(MgmtAlgo::from_name("3des"), Some(MgmtAlgo::Tdes));
        assert_eq!(MgmtAlgo::from_name("AES-192"), Some(MgmtAlgo::Aes192));
        assert_eq!(MgmtAlgo::from_name("aes256"), Some(MgmtAlgo::Aes256));
        assert_eq!(MgmtAlgo::from_name("RSA2048"), None);
    }

    #[test]
    fn check_key_len_message() {
        let err = MgmtAlgo::Aes192.check_key_len(&[0u8; 16]).unwrap_err();
        assert_eq!(
            err.to_string(),
            "management key is 16 bytes but the card uses AES-192 (24 bytes)"
        );
        assert!(MgmtAlgo::Aes192.check_key_len(&[0u8; 24]).is_ok());
    }

    #[test]
    fn parse_metadata_aes192_default() {
        // As returned by a firmware 5.7 YubiKey with its factory key:
        // algorithm AES-192, policy (PIN n/a, touch never), default = yes.
        let data = [0x01, 0x01, 0x0A, 0x02, 0x02, 0x00, 0x01, 0x05, 0x01, 0x01];
        let md = parse_mgmt_metadata(&data).unwrap();
        assert_eq!(md.algo, MgmtAlgo::Aes192);
        assert!(!md.touch_required());
        assert!(md.is_default);
    }

    #[test]
    fn parse_metadata_touch_policy() {
        let always = [0x01, 0x01, 0x03, 0x02, 0x02, 0x00, 0x02];
        assert_eq!(
            parse_mgmt_metadata(&always).unwrap().touch,
            TouchPolicy::Always
        );
        let cached = [0x01, 0x01, 0x03, 0x02, 0x02, 0x00, 0x03];
        assert!(parse_mgmt_metadata(&cached).unwrap().touch_required());
    }

    #[test]
    fn parse_metadata_rejects_unknown_algorithm() {
        let data = [0x01, 0x01, 0x07];
        let err = parse_mgmt_metadata(&data).unwrap_err();
        assert!(err
            .to_string()
            .contains("unsupported management key algorithm 0x07"));
    }

    #[test]
    fn parse_metadata_requires_algorithm() {
        assert!(parse_mgmt_metadata(&[0x05, 0x01, 0x01]).is_err());
    }

    #[test]
    fn parse_credential_and_slot_metadata() {
        // PIN metadata: default, 3 tries total, 2 left.
        let md = parse_credential_metadata(&[0x05, 0x01, 0x01, 0x06, 0x02, 0x03, 0x02]).unwrap();
        assert_eq!(
            md,
            CredentialMetadata {
                is_default: true,
                retries_total: 3,
                retries_left: 2
            }
        );
        assert!(parse_credential_metadata(&[0x05, 0x01, 0x01]).is_err());
        // Slot metadata: EC P-256, generated on the card.
        let md = parse_slot_metadata(&[0x01, 0x01, 0x11, 0x03, 0x01, 0x01]).unwrap();
        assert_eq!(md.algorithm, ALGO_ECCP256);
        assert_eq!(md.origin, Some(KeyOrigin::Generated));
        assert_eq!(key_algorithm_name(0x07), "RSA 2048");
    }

    #[test]
    fn parse_retries() {
        // PUK metadata: default flag, retries total=3 remaining=0.
        let data = [0x05, 0x01, 0x00, 0x06, 0x02, 0x03, 0x00];
        assert_eq!(parse_retries_remaining(&data), Some(0));
        assert_eq!(parse_retries_remaining(&[]), None);
    }
}
