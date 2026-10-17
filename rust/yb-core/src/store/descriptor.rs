// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! The descriptor of a post-quantum store, in object `0x5F_0000` (spec
//! 0028, D13 and "Store descriptor").
//!
//! ```text
//! Offset   Size  Field
//! 0x00      4    MAGIC = 0xF2EDF0B2
//! 0x04      1    OBJECT_COUNT: number of chunks N (1-32)
//! 0x05      1    TYPE = 0x01 (descriptor)
//! 0x06      1    VERSION = 0x01
//! 0x07      1    MGMT_ALGO: PIV algorithm of the management key
//! 0x08      1    CRED_ID_LEN (1-255)
//! 0x09      L    CRED_ID: the FIDO2 credential ID (opaque)
//! 0x09+L   32    MGMT_SALT: hmac-secret salt for the management key
//! 0x29+L   12    MGMT_NONCE
//! 0x35+L    K    MGMT_WRAPPED: the management key, AES-256-GCM encrypted
//! 0x35+L+K 16    MGMT_TAG
//! ```
//!
//! No secret is stored: the management key is wrapped by a key only the
//! YubiKey's FIDO2 application can compute (`hmac-secret`).

use super::constants::PQ_MAGIC;
use crate::piv::MgmtAlgo;
use anyhow::{bail, Result};

/// `TYPE` of the descriptor (chunks have 0x00 at this offset).
pub const DESCRIPTOR_TYPE: u8 = 0x01;
/// `VERSION` of this layout.
pub const DESCRIPTOR_VERSION: u8 = 0x01;
/// The bytes of the AES-GCM nonce and tag around the wrapped key.
pub const MGMT_NONCE_LEN: usize = 12;
pub const MGMT_TAG_LEN: usize = 16;

/// A post-quantum store's descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descriptor {
    /// The number of chunks, N (objects `0x5F_0001` … `0x5F_0000 + N`).
    pub object_count: u8,
    /// The algorithm of the PIV management key.
    pub mgmt_algo: MgmtAlgo,
    /// The FIDO2 credential ID (opaque, 1-255 bytes).
    pub credential_id: Vec<u8>,
    /// The `hmac-secret` salt whose output wraps the management key.
    pub mgmt_salt: [u8; 32],
    pub mgmt_nonce: [u8; MGMT_NONCE_LEN],
    /// The wrapped management key followed by its GCM tag.
    pub mgmt_wrapped: Vec<u8>,
}

impl Descriptor {
    /// The bytes the management key's AES-GCM authenticates as associated
    /// data: everything before `MGMT_NONCE`.
    pub fn wrap_ad(&self) -> Vec<u8> {
        let mut ad = Vec::with_capacity(0x29 + self.credential_id.len());
        ad.extend_from_slice(&PQ_MAGIC.to_le_bytes());
        ad.push(self.object_count);
        ad.push(DESCRIPTOR_TYPE);
        ad.push(DESCRIPTOR_VERSION);
        ad.push(self.mgmt_algo.id());
        ad.push(self.credential_id.len() as u8);
        ad.extend_from_slice(&self.credential_id);
        ad.extend_from_slice(&self.mgmt_salt);
        ad
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.wrap_ad();
        out.extend_from_slice(&self.mgmt_nonce);
        out.extend_from_slice(&self.mgmt_wrapped);
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 0x09 {
            bail!("store descriptor too short ({} bytes)", data.len());
        }
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if magic != PQ_MAGIC {
            bail!("store descriptor: bad magic 0x{magic:08x}");
        }
        let object_count = data[4];
        if !(1..=32).contains(&object_count) {
            bail!("store descriptor: invalid object count {object_count}");
        }
        if data[5] != DESCRIPTOR_TYPE {
            bail!(
                "store descriptor: object 0 is not a descriptor (type 0x{:02x})",
                data[5]
            );
        }
        if data[6] != DESCRIPTOR_VERSION {
            bail!(
                "store descriptor version {} is not known to this yb: update yb",
                data[6]
            );
        }
        let Some(mgmt_algo) = MgmtAlgo::from_id(data[7]) else {
            bail!(
                "store descriptor: unknown management key algorithm 0x{:02x}",
                data[7]
            );
        };
        let cred_len = data[8] as usize;
        if cred_len == 0 {
            bail!("store descriptor: empty credential ID");
        }
        let wrapped_len = mgmt_algo.key_len() + MGMT_TAG_LEN;
        let expected = 0x09 + cred_len + 32 + MGMT_NONCE_LEN + wrapped_len;
        if data.len() != expected {
            bail!(
                "store descriptor: {} bytes, expected {expected}",
                data.len()
            );
        }
        let mut off = 0x09;
        let credential_id = data[off..off + cred_len].to_vec();
        off += cred_len;
        let mut mgmt_salt = [0u8; 32];
        mgmt_salt.copy_from_slice(&data[off..off + 32]);
        off += 32;
        let mut mgmt_nonce = [0u8; MGMT_NONCE_LEN];
        mgmt_nonce.copy_from_slice(&data[off..off + MGMT_NONCE_LEN]);
        off += MGMT_NONCE_LEN;
        let mgmt_wrapped = data[off..].to_vec();
        Ok(Self {
            object_count,
            mgmt_algo,
            credential_id,
            mgmt_salt,
            mgmt_nonce,
            mgmt_wrapped,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(algo: MgmtAlgo) -> Descriptor {
        Descriptor {
            object_count: 32,
            mgmt_algo: algo,
            credential_id: vec![0x5a; 64],
            mgmt_salt: [0x11; 32],
            mgmt_nonce: [0x22; 12],
            mgmt_wrapped: vec![0x33; algo.key_len() + MGMT_TAG_LEN],
        }
    }

    #[test]
    fn round_trip() {
        for algo in [
            MgmtAlgo::Tdes,
            MgmtAlgo::Aes128,
            MgmtAlgo::Aes192,
            MgmtAlgo::Aes256,
        ] {
            let d = sample(algo);
            let bytes = d.to_bytes();
            assert_eq!(bytes.len(), 0x09 + 64 + 32 + 12 + algo.key_len() + 16);
            assert_eq!(&bytes[..4], &[0xB2, 0xF0, 0xED, 0xF2]);
            assert_eq!(Descriptor::from_bytes(&bytes).unwrap(), d);
        }
    }

    #[test]
    fn the_largest_fits_in_356_bytes() {
        let mut d = sample(MgmtAlgo::Aes256);
        d.credential_id = vec![0; 255];
        assert_eq!(d.to_bytes().len(), 356);
    }

    #[test]
    fn rejects_damage() {
        let bytes = sample(MgmtAlgo::Aes192).to_bytes();
        for (offset, value) in [(0, 0x0B), (4, 0), (5, 0x00), (6, 0x02), (7, 0x99)] {
            let mut bad = bytes.clone();
            bad[offset] = value;
            assert!(Descriptor::from_bytes(&bad).is_err(), "offset {offset}");
        }
        assert!(Descriptor::from_bytes(&bytes[..bytes.len() - 1]).is_err());
    }
}
