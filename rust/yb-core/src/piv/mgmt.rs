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
pub(crate) const GET_METADATA_MGMT: [u8; 5] = [0x00, 0xF7, 0x00, 0x9B, 0x00];
/// GET METADATA for the PUK (reference 0x81).  Firmware 5.3+.
pub(crate) const GET_METADATA_PUK: [u8; 5] = [0x00, 0xF7, 0x00, 0x81, 0x00];

// GET METADATA response tags.
const TAG_ALGORITHM: u8 = 0x01;
const TAG_POLICY: u8 = 0x02;
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

/// Management key metadata reported by GET METADATA (slot 9B).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MgmtMetadata {
    pub algo: MgmtAlgo,
    /// Touch policy is "always" or "cached": authentication needs a touch.
    pub touch_required: bool,
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
    let touch_required = matches!(
        tlv.get(&TAG_POLICY).map(Vec::as_slice),
        Some([_, TOUCH_ALWAYS | TOUCH_CACHED])
    );
    Ok(MgmtMetadata {
        algo,
        touch_required,
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
        assert!(!md.touch_required);
    }

    #[test]
    fn parse_metadata_touch_policy() {
        let always = [0x01, 0x01, 0x03, 0x02, 0x02, 0x00, 0x02];
        assert!(parse_mgmt_metadata(&always).unwrap().touch_required);
        let cached = [0x01, 0x01, 0x03, 0x02, 0x02, 0x00, 0x03];
        assert!(parse_mgmt_metadata(&cached).unwrap().touch_required);
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
    fn parse_retries() {
        // PUK metadata: default flag, retries total=3 remaining=0.
        let data = [0x05, 0x01, 0x00, 0x06, 0x02, 0x03, 0x00];
        assert_eq!(parse_retries_remaining(&data), Some(0));
        assert_eq!(parse_retries_remaining(&[]), None);
    }
}
