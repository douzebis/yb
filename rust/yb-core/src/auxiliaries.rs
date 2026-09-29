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

// ---------------------------------------------------------------------------
// PRINTED object: PIN-protected management key storage
// ---------------------------------------------------------------------------

const TAG_PRINTED: u8 = 0x88;
const TAG_PRINTED_KEY: u8 = 0x89;
const TAG_PRINTED_PREVIOUS_KEY: u8 = 0x8A;

/// Management keys held in the PIN-protected PRINTED object (0x5FC109),
/// laid out as ykman's `PivmanProtectedData` — `88 { 89 <key> }` — plus
/// tag `8A`, which keeps the previous key while a key switch is in
/// progress (spec 0022 §2, B1a).  ykman and older yb read only tag `89`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrintedKeys {
    /// Tag `89`: the stored management key, hex-encoded.
    pub current: Option<String>,
    /// Tag `8A`: the previous key, present only after an interrupted
    /// key switch.
    pub previous: Option<String>,
}

impl PrintedKeys {
    /// Parse PRINTED object content (outer `53` wrapper removed).  Content
    /// that does not start with tag `88` (e.g. NIST printed information)
    /// holds no keys.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let mut keys = Self::default();
        if raw.first() != Some(&TAG_PRINTED) {
            return Ok(keys);
        }
        let Some((_, inner)) = parse_tlv_list(raw)?.into_iter().next() else {
            return Ok(keys);
        };
        for (tag, value) in parse_tlv_list(&inner)? {
            match tag {
                TAG_PRINTED_KEY => keys.current = Some(hex::encode(value)),
                TAG_PRINTED_PREVIOUS_KEY => keys.previous = Some(hex::encode(value)),
                _ => {}
            }
        }
        Ok(keys)
    }
}

/// Encode PRINTED object content holding `current_hex` and, while a key
/// switch is in progress, `previous_hex`.
pub fn encode_printed(current_hex: &str, previous_hex: Option<&str>) -> Result<Vec<u8>> {
    use crate::piv::tlv::encode_tlv;
    let key = |h: &str| hex::decode(h).map_err(|e| anyhow::anyhow!("management key hex: {e}"));
    let mut inner = encode_tlv(TAG_PRINTED_KEY, &key(current_hex)?);
    if let Some(p) = previous_hex {
        inner.extend(encode_tlv(TAG_PRINTED_PREVIOUS_KEY, &key(p)?));
    }
    Ok(encode_tlv(TAG_PRINTED, &inner))
}

/// Read the management keys stored in PRINTED.  The backend verifies `pin`
/// in the same session; a missing object holds no keys.  Callers verify the
/// PIN beforehand, so that a wrong PIN is not mistaken for "no keys".
pub fn read_printed_keys(reader: &str, piv: &dyn PivBackend, pin: &str) -> Result<PrintedKeys> {
    match piv.read_printed_object_with_pin(reader, pin) {
        Ok(raw) => PrintedKeys::parse(&raw),
        Err(_) => Ok(PrintedKeys::default()),
    }
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DefaultCredentials {
    pub pin: bool,
    pub puk: bool,
    pub management_key: bool,
}

impl DefaultCredentials {
    pub fn any(&self) -> bool {
        self.pin || self.puk || self.management_key
    }
}

/// Detect which credentials are still at their factory values, with GET
/// METADATA (firmware 5.3+).  Enforces nothing: the policy is applied per
/// command (spec 0024).  On firmware without GET METADATA nothing can be
/// detected, and every credential is reported as not default.
pub fn detect_default_credentials(reader: &str, piv: &dyn PivBackend) -> DefaultCredentials {
    let is_default = |apdu: &[u8]| -> Option<bool> {
        let resp = piv.send_apdu(reader, apdu).ok()?;
        Some(
            parse_tlv_flat(&resp)
                .get(&TAG_IS_DEFAULT)
                .map(Vec::as_slice)
                == Some(&[0x01]),
        )
    };
    match (
        is_default(&GET_METADATA_PIN),
        is_default(&GET_METADATA_PUK),
        is_default(&GET_METADATA_MGMT),
    ) {
        (Some(pin), Some(puk), Some(management_key)) => DefaultCredentials {
            pin,
            puk,
            management_key,
        },
        // Firmware < 5.3 or APDU not supported — skip silently.
        _ => DefaultCredentials::default(),
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

/// Generate a random management key for `algo`, returned as a hex string.
pub fn generate_random_management_key(algo: MgmtAlgo) -> String {
    let bytes: Vec<u8> = (0..algo.key_len()).map(|_| rand::random::<u8>()).collect();
    hex::encode(bytes)
}

/// A switch to a new, PIN-protected management key (spec 0022 §2, B1).
pub struct KeySwitch<'a> {
    /// The card's current management key.
    pub old_key: &'a str,
    /// Whether `old_key` was read from PRINTED (the card was protected).
    pub old_key_in_printed: bool,
    /// The new key, `algo.key_len()` bytes, hex-encoded.
    pub new_key: &'a str,
    pub algo: MgmtAlgo,
    /// The card carries the legacy yb `0x01` flag (spec 0021 §4).
    pub clearing_legacy_flag: bool,
}

/// Switch to a new management key stored in PIN-protected mode, so that the
/// card's key is never known only to the card (spec 0022 §2, B1):
///
/// - B1a: PRINTED = `88 { 89 <new>, 8A <old> }` (old key authenticates);
/// - B1b: SET MANAGEMENT KEY; if it reports a failure, find out which key
///   the card holds instead of guessing;
/// - B1c: ADMIN DATA with flag `0x02` (new key authenticates);
/// - B1d: PRINTED = `88 { 89 <new> }` (a failure is only a warning).
///
/// ADMIN DATA is prepared before any write, so an unparseable or
/// PIN-derived ADMIN DATA fails with nothing changed.  Errors describe the
/// resulting card state and never contain key material.
pub fn enable_pin_protected_management_key(
    reader: &str,
    piv: &dyn PivBackend,
    sw: &KeySwitch<'_>,
) -> Result<()> {
    use anyhow::Context as _;

    let admin_payload = admin_data_with_stored_key(reader, piv, sw.clearing_legacy_flag)?;

    // B1a — save the new key, keeping the old one until the switch is done.
    let both = encode_printed(sw.new_key, Some(sw.old_key))?;
    if let Err(e) = piv.write_object(reader, OBJ_PRINTED, &both, sw.old_key) {
        return Err(e).context(restored_or_not(
            reader,
            piv,
            sw,
            "saving the new management key in PRINTED failed",
        ));
    }

    // B1b — switch the card to the new key.
    if let Err(e) = piv.set_management_key(reader, sw.old_key, sw.new_key, sw.algo) {
        if piv.authenticate_management_key(reader, sw.old_key).is_ok() {
            return Err(e).context(restored_or_not(
                reader,
                piv,
                sw,
                "the YubiKey rejected the new management key",
            ));
        }
        if piv.authenticate_management_key(reader, sw.new_key).is_err() {
            return Err(e).context(
                "the management key switch was interrupted and its outcome is unknown \
                 (was the YubiKey removed?).  PRINTED holds both the previous and the \
                 new key: once the YubiKey is reconnected, any yb write command or \
                 `yb format --protect` recovers",
            );
        }
        // The card accepts the new key: the switch happened, only the reply
        // was lost.  Carry on.
    }

    // B1c — record the stored key in ADMIN DATA.
    piv.write_object(reader, OBJ_ADMIN_DATA, &admin_payload, sw.new_key)
        .context(
            "the management key was changed and saved in PRINTED, but ADMIN DATA could \
             not be updated; any yb write command or `yb format --protect` repairs it",
        )?;

    // B1d — drop the old key from PRINTED.
    if let Err(e) = encode_printed(sw.new_key, None)
        .and_then(|only_new| piv.write_object(reader, OBJ_PRINTED, &only_new, sw.new_key))
    {
        eprintln!(
            "Warning: could not remove the previous management key from PRINTED ({e:#}); \
             the next yb write command removes it"
        );
    }
    Ok(())
}

/// Put PRINTED back as it was before a key switch — `88 { 89 <old> }` if the
/// old key came from PRINTED, otherwise no object — and describe the
/// outcome for an error message.
fn restored_or_not(reader: &str, piv: &dyn PivBackend, sw: &KeySwitch<'_>, what: &str) -> String {
    let previous = if sw.old_key_in_printed {
        encode_printed(sw.old_key, None)
    } else {
        Ok(Vec::new())
    };
    let restored = previous
        .and_then(|data| piv.write_object(reader, OBJ_PRINTED, &data, sw.old_key))
        .is_ok();
    if restored {
        format!("{what}; nothing was changed")
    } else {
        format!(
            "{what}; the management key is unchanged, but PRINTED could not be \
             restored: run `yb format --protect` again"
        )
    }
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
            piv.write_object(&reader, OBJ_ADMIN_DATA, raw, MGMT)
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
