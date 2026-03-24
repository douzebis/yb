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

/// Factory-default credentials.
pub const DEFAULT_PIN: &str = "123456";
pub const DEFAULT_MANAGEMENT_KEY: &str = "010203040506070801020304050607080102030405060708";

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

/// Which factory-default credentials are still active on the device.
#[derive(Debug, Default)]
pub struct DefaultCredentials {
    pub pin: bool,
    pub management_key: bool,
}

impl DefaultCredentials {
    pub fn any(&self) -> bool {
        self.pin || self.management_key
    }
}

/// Check whether the YubiKey still has default (insecure) credentials.
///
/// Uses GET_METADATA APDU (firmware 5.3+).  On older firmware the check is
/// skipped with a warning.  If `allow_defaults` is false and any defaults are
/// found, returns Err.  Otherwise returns which credentials are still default.
pub fn check_for_default_credentials(
    reader: &str,
    piv: &dyn PivBackend,
    allow_defaults: bool,
) -> Result<DefaultCredentials> {
    let mut result = DefaultCredentials::default();
    let mut labels = Vec::new();

    for (label, apdu, field) in [
        ("PIN", GET_METADATA_PIN.as_ref(), 0u8),
        ("PUK", GET_METADATA_PUK.as_ref(), 1u8),
        ("management key", GET_METADATA_MGMT.as_ref(), 2u8),
    ] {
        match piv.send_apdu(reader, apdu) {
            Err(_) => {
                // Firmware < 5.3 or APDU not supported — skip silently.
                return Ok(DefaultCredentials::default());
            }
            Ok(resp) => {
                let tlv = parse_tlv_flat(&resp);
                if tlv.get(&TAG_IS_DEFAULT).map(|v| v.first()) == Some(Some(&0x01)) {
                    labels.push(label);
                    match field {
                        0 => result.pin = true,
                        2 => result.management_key = true,
                        _ => {}
                    }
                }
            }
        }
    }

    if labels.is_empty() {
        return Ok(result);
    }

    let msg = format!(
        "YubiKey has default credentials: {}. \
         This is insecure. Use --allow-defaults to override.",
        labels.join(", ")
    );

    if allow_defaults {
        eprintln!("Warning: {msg}");
        Ok(result)
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

/// Generate a random 24-byte 3DES management key, returned as a hex string.
pub fn generate_random_management_key() -> String {
    let bytes: [u8; 24] = rand::random();
    hex::encode(bytes)
}

/// Store `new_key_hex` in PIN-protected mode on the device.
///
/// Steps:
/// 1. Issue SET MANAGEMENT KEY to replace the current key with `new_key_hex`.
/// 2. Write the new key into the PRINTED object (0x5FC109) wrapped in the
///    `88 <n> [ 89 <24> <key_bytes> ]` TLV structure that
///    `extract_pin_protected_key` expects.
/// 3. Write ADMIN DATA (0x5FFF00) with the `mgmt_key_stored` bit set so that
///    `detect_pin_protected_mode` recognises PIN-protected mode.
///
/// The caller must have already verified `pin` is correct for this device.
pub fn enable_pin_protected_management_key(
    reader: &str,
    piv: &dyn PivBackend,
    old_key_hex: &str,
    new_key_hex: &str,
    pin: &str,
) -> Result<()> {
    // Step 1 — swap the management key on the card.
    piv.set_management_key(reader, old_key_hex, new_key_hex)?;

    // Step 2 — encode the new key in the PRINTED object.
    // Format: 88 <outer_len> [ 89 <24> <24 key bytes> ]
    let key_bytes = hex::decode(new_key_hex).map_err(|e| anyhow::anyhow!("key hex: {e}"))?;
    let inner_value: Vec<u8> = {
        let mut v = vec![0x89u8, key_bytes.len() as u8];
        v.extend_from_slice(&key_bytes);
        v
    };
    let printed_payload: Vec<u8> = {
        let mut v = vec![0x88u8, inner_value.len() as u8];
        v.extend(inner_value);
        v
    };
    piv.write_object(
        reader,
        OBJ_PRINTED,
        &printed_payload,
        Some(new_key_hex),
        None,
    )?;

    // Step 3 — write ADMIN DATA: tag 0x80 [ tag 0x81 <1 byte: flags> ]
    // Bit 0x01 = mgmt key stored in PRINTED object (PIN-protected mode).
    let admin_inner = [0x81u8, 0x01, 0x01];
    let admin_payload: Vec<u8> = {
        let mut v = vec![0x80u8, admin_inner.len() as u8];
        v.extend_from_slice(&admin_inner);
        v
    };
    piv.write_object(
        reader,
        OBJ_ADMIN_DATA,
        &admin_payload,
        Some(new_key_hex),
        None,
    )?;

    let _ = pin; // caller-supplied PIN acknowledged; no additional round-trip needed
    Ok(())
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
