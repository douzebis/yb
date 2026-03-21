// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Auxiliary helpers: TLV parsing, default-credential checks, PIN-protected
//! management-key retrieval.

use crate::piv::PivBackend;
use anyhow::{bail, Result};
use std::collections::HashMap;

// PIV object IDs used for metadata.
pub const OBJ_ADMIN_DATA: u32 = 0x5F_FF00;
pub const OBJ_PRINTED: u32 = 0x5F_C109;

// APDU bytes for GET_METADATA (YubiKey firmware 5.3+).
const GET_METADATA_PIN: [u8; 5] = [0x00, 0xF7, 0x00, 0x80, 0x00];
const GET_METADATA_PUK: [u8; 5] = [0x00, 0xF7, 0x00, 0x81, 0x00];
const GET_METADATA_MGMT: [u8; 5] = [0x00, 0xF7, 0x00, 0x9B, 0x00];

// TLV tag that carries the is_default flag (value 0x01 = is default).
const TAG_IS_DEFAULT: u8 = 0x05;

// ---------------------------------------------------------------------------
// TLV parser
// ---------------------------------------------------------------------------

/// Parse a flat BER-TLV sequence (single-byte tags) into a tag→value map.
pub(crate) fn parse_tlv_flat(data: &[u8]) -> HashMap<u8, Vec<u8>> {
    let mut map = HashMap::new();
    let mut i = 0;
    while i < data.len() {
        let tag = data[i];
        i += 1;
        if i >= data.len() {
            break;
        }
        let (len, consumed) = decode_tlv_length(&data[i..]);
        i += consumed;
        if i + len > data.len() {
            debug_assert!(
                false,
                "parse_tlv_flat: truncated TLV at offset {i} (tag=0x{tag:02x}, claimed len={len}, available={})",
                data.len() - i
            );
            break;
        }
        map.insert(tag, data[i..i + len].to_vec());
        i += len;
    }
    map
}

pub(crate) fn decode_tlv_length(data: &[u8]) -> (usize, usize) {
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

/// Parse `88 <len> [ 89 <len> <key_bytes> ]` from the PRINTED object value.
pub(crate) fn extract_pin_protected_key(raw: &[u8]) -> Result<String> {
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

/// Parse a `/`-separated subject string like `"CN=foo/O=bar"` into an rcgen `DistinguishedName`.
pub(crate) fn parse_subject_dn(subject: &str) -> rcgen::DistinguishedName {
    use rcgen::{DistinguishedName, DnType};
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
    dn
}

// ---------------------------------------------------------------------------
// Default-credential check
// ---------------------------------------------------------------------------

/// Check whether the YubiKey still has default (insecure) credentials.
///
/// Uses GET_METADATA APDU (firmware 5.3+).  On older firmware the check is
/// skipped with a warning.  If `allow_defaults` is false and defaults are
/// found, returns Err.
pub fn check_for_default_credentials(
    reader: &str,
    piv: &dyn PivBackend,
    allow_defaults: bool,
) -> Result<()> {
    let mut defaults_found = Vec::new();

    for (label, apdu) in [
        ("PIN", GET_METADATA_PIN.as_ref()),
        ("PUK", GET_METADATA_PUK.as_ref()),
        ("management key", GET_METADATA_MGMT.as_ref()),
    ] {
        match piv.send_apdu(reader, apdu) {
            Err(_) => {
                // Firmware < 5.3 or APDU not supported — skip silently.
                return Ok(());
            }
            Ok(resp) => {
                let tlv = parse_tlv_flat(&resp);
                if tlv.get(&TAG_IS_DEFAULT).map(|v| v.first()) == Some(Some(&0x01)) {
                    defaults_found.push(label);
                }
            }
        }
    }

    if defaults_found.is_empty() {
        return Ok(());
    }

    let msg = format!(
        "YubiKey has default credentials: {}. \
         This is insecure. Use --allow-defaults to override.",
        defaults_found.join(", ")
    );

    if allow_defaults {
        eprintln!("Warning: {msg}");
        Ok(())
    } else {
        bail!("{msg}")
    }
}

// ---------------------------------------------------------------------------
// PIN-protected management key
// ---------------------------------------------------------------------------

/// Parsed contents of the ADMIN DATA object (0x5FFF00).
#[derive(Debug, Default)]
pub struct AdminData {
    #[allow(dead_code)]
    pub puk_blocked: bool,
    pub mgmt_key_stored: bool,
    pub pin_derived: bool,
}

/// Read and parse the ADMIN DATA object.
pub fn parse_admin_data(reader: &str, piv: &dyn PivBackend) -> Result<AdminData> {
    let raw = match piv.read_object(reader, OBJ_ADMIN_DATA) {
        Err(_) => return Ok(AdminData::default()),
        Ok(r) => r,
    };

    let tlv = parse_tlv_flat(&raw);
    // Tag 0x80 contains a nested TLV; tag 0x81 inside holds the bitfield.
    // Bits 0x01/0x02: mgmt key stored in PRINTED object (PIN-protected mode).
    // Bit 0x04: PIN-derived (deprecated).
    let flags = tlv
        .get(&0x80)
        .and_then(|inner_bytes| {
            let inner = parse_tlv_flat(inner_bytes);
            inner.get(&0x81).and_then(|v| v.first()).copied()
        })
        .unwrap_or(0);

    Ok(AdminData {
        puk_blocked: flags & 0x01 != 0,
        // Bit 0x01 = key stored in PRINTED object; bit 0x02 = key stored in
        // PROTECTED object.  We treat either bit as "PIN-protected mode".
        mgmt_key_stored: flags & 0x03 != 0,
        pin_derived: flags & 0x04 != 0,
    })
}

/// Detect PIN-protected mode.
/// Returns (is_pin_protected, is_pin_derived).
pub fn detect_pin_protected_mode(reader: &str, piv: &dyn PivBackend) -> Result<(bool, bool)> {
    let admin = parse_admin_data(reader, piv)?;
    Ok((admin.mgmt_key_stored, admin.pin_derived))
}

/// Retrieve the management key stored in the PRINTED object (0x5FC109).
///
/// PIN verification and object retrieval must happen in the same PC/SC session
/// to avoid the card resetting PIN-verified state between calls.
pub fn get_pin_protected_management_key(
    reader: &str,
    piv: &dyn PivBackend,
    pin: &str,
) -> Result<String> {
    let raw = piv.read_printed_object_with_pin(reader, pin)?;
    extract_pin_protected_key(&raw)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tlv_simple() {
        // tag=0x05, len=1, value=0x01
        let data = [0x05u8, 0x01, 0x01];
        let map = parse_tlv_flat(&data);
        assert_eq!(map.get(&0x05), Some(&vec![0x01u8]));
    }

    #[test]
    fn tlv_multi_tag() {
        let data = [0x05u8, 0x01, 0x00, 0x06, 0x02, 0x03, 0x04];
        let map = parse_tlv_flat(&data);
        assert_eq!(map.get(&0x05), Some(&vec![0x00u8]));
        assert_eq!(map.get(&0x06), Some(&vec![0x03u8, 0x04u8]));
    }

    #[test]
    fn tlv_long_form_length() {
        // tag=0x01, length encoded as 0x81 0x03 (long form, 3 bytes), value=[0xAA,0xBB,0xCC]
        let data = [0x01u8, 0x81, 0x03, 0xAA, 0xBB, 0xCC];
        let map = parse_tlv_flat(&data);
        assert_eq!(map.get(&0x01), Some(&vec![0xAAu8, 0xBB, 0xCC]));
    }
}
