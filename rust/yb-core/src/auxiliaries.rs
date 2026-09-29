// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Auxiliary helpers: TLV parsing, default-credential checks, PIN-protected
//! management-key retrieval.

use crate::piv::mgmt::{parse_retries_remaining, GET_METADATA_MGMT, GET_METADATA_PUK};
use crate::piv::{MgmtAlgo, PivBackend};
use anyhow::{bail, Result};
use std::collections::HashMap;

// PIV object IDs used for metadata.
pub const OBJ_ADMIN_DATA: u32 = 0x5F_FF00;
pub const OBJ_PRINTED: u32 = 0x5F_C109;

/// Factory-default credentials.
pub const DEFAULT_PIN: &str = "123456";
/// Factory-default management key: 3DES before firmware 5.7, AES-192 from
/// firmware 5.7 on (same bytes).
pub const DEFAULT_MANAGEMENT_KEY: &str = "010203040506070801020304050607080102030405060708";

// APDU bytes for GET_METADATA (YubiKey firmware 5.3+).
const GET_METADATA_PIN: [u8; 5] = [0x00, 0xF7, 0x00, 0x80, 0x00];

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

/// ADMIN DATA flag (tag 0x81): the PUK is blocked.
pub const ADMIN_FLAG_PUK_BLOCKED: u8 = 0x01;
/// ADMIN DATA flag (tag 0x81): the management key is stored in the
/// PIN-protected PRINTED object.
pub const ADMIN_FLAG_MGMT_KEY_STORED: u8 = 0x02;

const TAG_ADMIN_DATA: u8 = 0x80;
const TAG_ADMIN_FLAGS: u8 = 0x81;
const TAG_ADMIN_SALT: u8 = 0x82;

/// How the card's management key is protected, as recorded in ADMIN DATA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionMode {
    /// Not protected: the key must be supplied (or is the factory default).
    None,
    /// Key stored in PRINTED, flag `0x02` (ykman layout).
    Standard,
    /// Flag `0x01` without `0x02`: either the PUK is really blocked, or the
    /// card was protected by yb ≤ 0.4.x, which wrote `0x01` by mistake.
    /// Resolved when a management key is needed (spec 0021 §4).
    LegacyOrPukBlocked,
    /// PIN-derived management key (salt present).  Deprecated; unsupported.
    Derived,
    /// ADMIN DATA exists but cannot be parsed.  yb refuses to write.
    Invalid,
}

/// Parsed pivman ADMIN DATA object (0x5FFF00), laid out as ykman's
/// `PivmanData`: `80 L [ 81 01 <flags> | 82 L <salt> | 83 04 <timestamp> ]`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdminData {
    /// Tag 0x81 bitfield, if present.
    pub flags: Option<u8>,
    /// Tag 0x82: salt of a PIN-derived management key, if present.
    pub salt: Option<Vec<u8>>,
    /// Every other TLV (tag 0x83 PIN timestamp, unknown tags), kept in
    /// order so that a rewrite preserves it.
    pub other: Vec<(u8, Vec<u8>)>,
}

impl AdminData {
    /// Parse the ADMIN DATA object content (outer `53` wrapper removed).
    /// Empty content means "no ADMIN DATA".
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let mut admin = Self::default();
        if raw.is_empty() {
            return Ok(admin);
        }
        let inner = match parse_tlv_list(raw)?.into_iter().next() {
            Some((TAG_ADMIN_DATA, inner)) => inner,
            _ => bail!("ADMIN DATA: expected tag 0x80"),
        };
        for (tag, value) in parse_tlv_list(&inner)? {
            match tag {
                TAG_ADMIN_FLAGS => match value.as_slice() {
                    [flags] => admin.flags = Some(*flags),
                    _ => bail!("ADMIN DATA: flags (tag 0x81) must be one byte"),
                },
                TAG_ADMIN_SALT => admin.salt = Some(value),
                _ => admin.other.push((tag, value)),
            }
        }
        Ok(admin)
    }

    /// Encode as ADMIN DATA object content.
    pub fn to_bytes(&self) -> Vec<u8> {
        use crate::piv::tlv::encode_tlv;
        let mut inner = Vec::new();
        if let Some(flags) = self.flags {
            inner.extend(encode_tlv(TAG_ADMIN_FLAGS, &[flags]));
        }
        if let Some(ref salt) = self.salt {
            inner.extend(encode_tlv(TAG_ADMIN_SALT, salt));
        }
        for (tag, value) in &self.other {
            inner.extend(encode_tlv(*tag, value));
        }
        encode_tlv(TAG_ADMIN_DATA, &inner)
    }

    /// How the management key is protected, per spec 0021 §4.
    pub fn protection_mode(&self) -> ProtectionMode {
        let flags = self.flags.unwrap_or(0);
        if self.salt.is_some() {
            ProtectionMode::Derived
        } else if flags & ADMIN_FLAG_MGMT_KEY_STORED != 0 {
            ProtectionMode::Standard
        } else if flags & ADMIN_FLAG_PUK_BLOCKED != 0 {
            ProtectionMode::LegacyOrPukBlocked
        } else {
            ProtectionMode::None
        }
    }
}

/// Parse a BER-TLV sequence with single-byte tags, in order.  Unlike
/// [`parse_tlv_flat`], truncated input is an error.
fn parse_tlv_list(data: &[u8]) -> Result<Vec<(u8, Vec<u8>)>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let tag = data[i];
        i += 1;
        if i >= data.len() {
            bail!("truncated TLV: tag 0x{tag:02x} has no length");
        }
        let (len, consumed) = decode_tlv_length(&data[i..]);
        i += consumed;
        if consumed == 0 || i + len > data.len() {
            bail!("truncated TLV: tag 0x{tag:02x}");
        }
        out.push((tag, data[i..i + len].to_vec()));
        i += len;
    }
    Ok(out)
}

/// Read and parse the ADMIN DATA object.  A missing object reads as empty.
pub fn read_admin_data(reader: &str, piv: &dyn PivBackend) -> Result<AdminData> {
    match piv.read_object(reader, OBJ_ADMIN_DATA) {
        Err(_) => Ok(AdminData::default()),
        Ok(raw) => AdminData::parse(&raw),
    }
}

/// Detect how the management key is protected (read-only, no PIN).
pub fn detect_protection_mode(reader: &str, piv: &dyn PivBackend) -> ProtectionMode {
    match read_admin_data(reader, piv) {
        Ok(admin) => admin.protection_mode(),
        Err(_) => ProtectionMode::Invalid,
    }
}

/// Number of PUK retries remaining, or `None` when the card cannot say
/// (firmware < 5.3).
fn puk_retries_remaining(reader: &str, piv: &dyn PivBackend) -> Option<u8> {
    let resp = piv.send_apdu(reader, &GET_METADATA_PUK).ok()?;
    parse_retries_remaining(&resp)
}

/// Build the ADMIN DATA content recording a management key stored in
/// PRINTED, as a read-modify-write of the current object (spec 0021 §4):
///
/// - flag `0x02` is set;
/// - flag `0x01` (PUK blocked) is set from the PUK retry counter when the
///   card reports it; otherwise it is kept, or cleared when
///   `clearing_legacy_flag` (the `0x01` was written by yb ≤ 0.4.x);
/// - tag 0x83 and unknown tags/bits are preserved.
///
/// Fails, without writing anything, if ADMIN DATA cannot be parsed or
/// records a PIN-derived key.
pub fn admin_data_with_stored_key(
    reader: &str,
    piv: &dyn PivBackend,
    clearing_legacy_flag: bool,
) -> Result<Vec<u8>> {
    let mut admin = read_admin_data(reader, piv)
        .map_err(|e| anyhow::anyhow!("cannot update ADMIN DATA (0x5FFF00): {e}"))?;
    if admin.salt.is_some() {
        bail!("{PIN_DERIVED_UNSUPPORTED}");
    }
    let mut flags = admin.flags.unwrap_or(0) | ADMIN_FLAG_MGMT_KEY_STORED;
    match puk_retries_remaining(reader, piv) {
        Some(0) => flags |= ADMIN_FLAG_PUK_BLOCKED,
        Some(_) => flags &= !ADMIN_FLAG_PUK_BLOCKED,
        None if clearing_legacy_flag => flags &= !ADMIN_FLAG_PUK_BLOCKED,
        None => {}
    }
    admin.flags = Some(flags);
    Ok(admin.to_bytes())
}

/// Message for a card whose management key is PIN-derived.
pub const PIN_DERIVED_UNSUPPORTED: &str =
    "PIN-derived management key mode is deprecated and not supported. \
     Please migrate to PIN-protected mode.";

/// Rewrite the ADMIN DATA of a card protected by yb ≤ 0.4.x (flag `0x01`)
/// to the standard layout (flag `0x02`).  The management key and PRINTED
/// are unchanged.
pub fn migrate_legacy_admin_data(
    reader: &str,
    piv: &dyn PivBackend,
    management_key: Option<&str>,
    pin: Option<&str>,
) -> Result<()> {
    let payload = admin_data_with_stored_key(reader, piv, true)?;
    piv.write_object(reader, OBJ_ADMIN_DATA, &payload, management_key, pin)
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

/// Generate a random management key for `algo`, returned as a hex string.
pub fn generate_random_management_key(algo: MgmtAlgo) -> String {
    let bytes: Vec<u8> = (0..algo.key_len()).map(|_| rand::random::<u8>()).collect();
    hex::encode(bytes)
}

/// Store `new_key_hex` in PIN-protected mode on the device.
///
/// Steps:
/// 0. Prepare the new ADMIN DATA (read-only); fails before any write if
///    ADMIN DATA is unparseable or records a PIN-derived key.
/// 1. Issue SET MANAGEMENT KEY to replace the current key with `new_key_hex`
///    (algorithm `algo`).
/// 2. Write the new key into the PRINTED object (0x5FC109) wrapped in the
///    `88 <n> [ 89 <len> <key_bytes> ]` TLV structure that
///    `extract_pin_protected_key` expects.
/// 3. Write ADMIN DATA (0x5FFF00) with flag `0x02` set (ykman layout), see
///    [`admin_data_with_stored_key`].
///
/// `clearing_legacy_flag` is true when the card is known to carry the
/// legacy yb `0x01` flag.
pub fn enable_pin_protected_management_key(
    reader: &str,
    piv: &dyn PivBackend,
    old_key_hex: &str,
    new_key_hex: &str,
    algo: MgmtAlgo,
    clearing_legacy_flag: bool,
) -> Result<()> {
    // Step 0 — prepare ADMIN DATA before changing anything.
    let admin_payload = admin_data_with_stored_key(reader, piv, clearing_legacy_flag)?;

    // Step 1 — swap the management key on the card.
    piv.set_management_key(reader, old_key_hex, new_key_hex, algo)?;

    // Step 2 — encode the new key in the PRINTED object.
    // Format: 88 <outer_len> [ 89 <len> <key bytes> ]
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

    // Step 3 — write ADMIN DATA with flag 0x02 (key stored in PRINTED).
    piv.write_object(
        reader,
        OBJ_ADMIN_DATA,
        &admin_payload,
        Some(new_key_hex),
        None,
    )?;

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

    // ADMIN DATA (spec 0021 §4)

    fn mode(raw: &[u8]) -> ProtectionMode {
        AdminData::parse(raw).unwrap().protection_mode()
    }

    #[test]
    fn admin_data_protection_modes() {
        assert_eq!(mode(&[]), ProtectionMode::None);
        assert_eq!(mode(&[0x80, 0x03, 0x81, 0x01, 0x00]), ProtectionMode::None);
        // ykman: key stored in PRINTED.
        assert_eq!(
            mode(&[0x80, 0x03, 0x81, 0x01, 0x02]),
            ProtectionMode::Standard
        );
        // 0x02 wins over 0x01 (stored key and blocked PUK).
        assert_eq!(
            mode(&[0x80, 0x03, 0x81, 0x01, 0x03]),
            ProtectionMode::Standard
        );
        // yb ≤ 0.4.x, or ykman with a blocked PUK.
        assert_eq!(
            mode(&[0x80, 0x03, 0x81, 0x01, 0x01]),
            ProtectionMode::LegacyOrPukBlocked
        );
        // Salt present: PIN-derived, whatever the flags say.
        assert_eq!(
            mode(&[0x80, 0x07, 0x81, 0x01, 0x02, 0x82, 0x02, 0xAA, 0xBB]),
            ProtectionMode::Derived
        );
        // Bit 0x04 is no longer interpreted.
        assert_eq!(mode(&[0x80, 0x03, 0x81, 0x01, 0x04]), ProtectionMode::None);
    }

    #[test]
    fn admin_data_round_trip_preserves_other_tags() {
        // Flags, PIN timestamp (0x83) and an unknown tag (0x90).
        let raw = [
            0x80, 0x0C, 0x81, 0x01, 0x02, 0x83, 0x04, 0x01, 0x02, 0x03, 0x04, 0x90, 0x01, 0x7F,
        ];
        let admin = AdminData::parse(&raw).unwrap();
        assert_eq!(admin.flags, Some(0x02));
        assert_eq!(
            admin.other,
            vec![(0x83, vec![1, 2, 3, 4]), (0x90, vec![0x7F])]
        );
        assert_eq!(admin.to_bytes(), raw.to_vec());
    }

    #[test]
    fn admin_data_rejects_malformed_content() {
        // Truncated inner TLV.
        assert!(AdminData::parse(&[0x80, 0x05, 0x81]).is_err());
        // Wrong outer tag.
        assert!(AdminData::parse(&[0x53, 0x03, 0x81, 0x01, 0x02]).is_err());
        // Flags must be one byte.
        assert!(AdminData::parse(&[0x80, 0x04, 0x81, 0x02, 0x02, 0x00]).is_err());
    }

    #[cfg(feature = "virtual-piv")]
    mod admin_rewrite {
        use super::*;
        use crate::piv::VirtualPiv;

        const MGMT: &str = DEFAULT_MANAGEMENT_KEY;

        fn card_with_admin(raw: &[u8]) -> (VirtualPiv, String) {
            let piv = VirtualPiv::new();
            let reader = piv.reader_name();
            piv.write_object(&reader, OBJ_ADMIN_DATA, raw, Some(MGMT), None)
                .unwrap();
            (piv, reader)
        }

        #[test]
        fn legacy_flag_cleared_when_puk_not_blocked() {
            // The virtual card reports 3 PUK retries remaining.
            let (piv, reader) = card_with_admin(&[0x80, 0x03, 0x81, 0x01, 0x01]);
            let payload = admin_data_with_stored_key(&reader, &piv, true).unwrap();
            assert_eq!(payload, vec![0x80, 0x03, 0x81, 0x01, 0x02]);
        }

        #[test]
        fn timestamp_and_unknown_bits_preserved() {
            // Unknown flag bit 0x10 and a PIN timestamp.
            let (piv, reader) = card_with_admin(&[
                0x80, 0x09, 0x81, 0x01, 0x10, 0x83, 0x04, 0x01, 0x02, 0x03, 0x04,
            ]);
            let payload = admin_data_with_stored_key(&reader, &piv, false).unwrap();
            assert_eq!(
                payload,
                vec![0x80, 0x09, 0x81, 0x01, 0x12, 0x83, 0x04, 0x01, 0x02, 0x03, 0x04]
            );
        }

        #[test]
        fn missing_admin_data_is_created() {
            let piv = VirtualPiv::new();
            let reader = piv.reader_name();
            let payload = admin_data_with_stored_key(&reader, &piv, false).unwrap();
            assert_eq!(payload, vec![0x80, 0x03, 0x81, 0x01, 0x02]);
        }

        #[test]
        fn pin_derived_is_refused() {
            let (piv, reader) =
                card_with_admin(&[0x80, 0x07, 0x81, 0x01, 0x00, 0x82, 0x02, 0xAA, 0xBB]);
            assert!(admin_data_with_stored_key(&reader, &piv, false).is_err());
        }
    }
}
