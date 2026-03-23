// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! NVM free-space measurement.
//!
//! [`measure_free_nvm`] is an idempotent probe: it fills every empty PIV slot
//! to its maximum capacity via binary search, sums the totals, then restores
//! all probe slots to empty.  The device is left in exactly the state it was
//! found in (only empty slots are touched).

use crate::piv::session::PcscSession;
use crate::piv::PivBackend;
use crate::store::constants::OBJECT_ID_ZERO;
use anyhow::Result;

/// Maximum number of 3-byte PIV object IDs in the range 0x5F0000..0x5F00FF.
const MAX_SLOTS: usize = 256;

/// Upper bound for binary-search probing — above the empirically measured
/// maximum (3063) to be safe across firmware versions.
const PROBE_MAX: usize = 4095;

/// Measure total free NVM on the device without altering its state.
///
/// Only slots that GET DATA reports as empty (SW 6A82 → size 0) are touched.
/// Each empty slot is filled to its maximum capacity via binary search, the
/// total is summed, and all probe slots are then freed (0-byte PUT DATA).
///
/// Returns the total number of bytes available for new allocations.
///
/// If `verbose` is true, prints per-slot progress to stderr.  Stops as soon
/// as the first probe yields 0 bytes (NVM already full).
pub fn measure_free_nvm(reader: &str, mgmt_key: &str, verbose: bool) -> Result<usize> {
    let mut session = PcscSession::open(reader)?;

    // Identify empty slots.
    let mut empty_slots = Vec::new();
    for i in 0..MAX_SLOTS {
        let id = OBJECT_ID_ZERO + i as u32;
        if session.try_get_data_size(id)?.unwrap_or(0) == 0 {
            empty_slots.push(i);
        }
    }
    if verbose {
        eprintln!(
            "  measure_free_nvm: {} empty slots out of {MAX_SLOTS}.",
            empty_slots.len()
        );
    }

    // Fill each empty slot to maximum via binary search.
    let mut total = 0usize;
    let mut filled: Vec<usize> = Vec::new();
    for &slot in &empty_slots {
        let id = OBJECT_ID_ZERO + slot as u32;
        let size = dichotomy_fill(&mut session, mgmt_key, id)?;
        if verbose {
            eprintln!("    slot {slot:3}: {size} bytes");
        }
        if size == 0 {
            if verbose {
                eprintln!("    NVM full — stopping early.");
            }
            break;
        }
        total += size;
        filled.push(slot);
    }

    // Restore all probe slots to empty.
    for &slot in &filled {
        let id = OBJECT_ID_ZERO + slot as u32;
        session.authenticate_management_key(mgmt_key)?;
        session.try_put_data(id, &[])?;
    }

    if verbose {
        eprintln!("  measure_free_nvm: total free = {total} bytes.");
    }
    Ok(total)
}

/// Fill slot `id` to the largest payload that fits using binary search.
///
/// The slot must be empty on entry.  On return the slot holds `committed`
/// bytes (the largest size that succeeded).  A failed PUT DATA clears the
/// slot on the YubiKey, so after each failure we re-commit the last known
/// good size before narrowing the search.
fn dichotomy_fill(session: &mut PcscSession, mgmt_key: &str, id: u32) -> Result<usize> {
    let mut lo = 1usize;
    let mut hi = PROBE_MAX;
    let mut committed = 0usize;

    while lo <= hi {
        let mid = (lo + hi) / 2;
        session.authenticate_management_key(mgmt_key)?;
        if session.try_put_data(id, &vec![0xEEu8; mid])? {
            committed = mid;
            lo = mid + 1;
        } else {
            // Failed write cleared the slot — re-commit last known good size.
            if committed > 0 {
                session.authenticate_management_key(mgmt_key)?;
                session.try_put_data(id, &vec![0xEEu8; committed])?;
            }
            hi = mid - 1;
        }
    }
    Ok(committed)
}

// ---------------------------------------------------------------------------
// NVM usage scan
// ---------------------------------------------------------------------------

/// Total NVM budget of the YubiKey 5 PIV application (bytes).
/// Used only as the denominator for the "free" estimate.
const YUBIKEY_NVM_BYTES: usize = 51_200;

/// NVM usage broken down into three buckets.
pub struct NvmUsage {
    /// Bytes consumed by yb store objects (the `0x5F_00xx` range).
    pub store_bytes: usize,
    /// Bytes consumed by other PIV objects (certificates, printed info, etc.).
    pub other_bytes: usize,
    /// Estimated free bytes (total budget minus store and other).
    pub free_bytes: usize,
}

/// Well-known PIV data object IDs outside the `0x5F_00xx` yb store range.
/// Sources: NIST SP 800-73-4 Table 3, Yubico extensions.
const KNOWN_PIV_OBJECTS: &[u32] = &[
    0x5F_C102, // Card Capability Container
    0x5F_C100, // Card Holder Unique Identifier (CHUID)
    0x5F_C101, // Card Authentication certificate
    0x5F_C105, // PIV Authentication certificate (slot 9A)
    0x5F_C10A, // Digital Signature certificate (slot 9C)
    0x5F_C10B, // Key Management certificate (slot 9D)
    0x5F_C10C, // Secure Messaging certificate
    0x5F_C103, // Cardholder Fingerprints
    0x5F_C106, // Security Object
    0x5F_C108, // Cardholder Facial Image
    0x5F_C109, // Printed Information (PIN-protected mgmt key)
    0x5F_C10D, // Retired Key Management 1 certificate (slot 82)
    0x5F_C10E, // Retired Key Management 2 certificate (slot 83)
    0x5F_C10F, // Retired Key Management 3 certificate (slot 84)
    0x5F_C110, // Retired Key Management 4 certificate (slot 85)
    0x5F_C111, // Retired Key Management 5 certificate (slot 86)
    0x5F_C112, // Retired Key Management 6 certificate (slot 87)
    0x5F_C113, // Retired Key Management 7 certificate (slot 88)
    0x5F_C114, // Retired Key Management 8 certificate (slot 89)
    0x5F_C115, // Retired Key Management 9 certificate (slot 8A)
    0x5F_C116, // Retired Key Management 10 certificate (slot 8B)
    0x5F_C117, // Retired Key Management 11 certificate (slot 8C)
    0x5F_C118, // Retired Key Management 12 certificate (slot 8D)
    0x5F_C119, // Retired Key Management 13 certificate (slot 8E)
    0x5F_C11A, // Retired Key Management 14 certificate (slot 8F)
    0x5F_C11B, // Retired Key Management 15 certificate (slot 90)
    0x5F_C11C, // Retired Key Management 16 certificate (slot 91)
    0x5F_C11D, // Retired Key Management 17 certificate (slot 92)
    0x5F_C11E, // Retired Key Management 18 certificate (slot 93)
    0x5F_C11F, // Retired Key Management 19 certificate (slot 94)
    0x5F_C120, // Retired Key Management 20 certificate (slot 95)
    0x5F_C121, // Attestation certificate (Yubico extension)
];

/// Scan all known PIV object IDs and return NVM usage broken down by bucket.
///
/// Probes all 256 slots in `0x5F_0000..0x5F_00FF` (yb store range) plus the
/// fixed set of well-known PIV object IDs.  No credentials required — only
/// GET DATA (read-only) APDUs are issued.
///
/// The `store_object_ids` set identifies which `0x5F_00xx` slots belong to
/// the yb store; any occupied slot outside that set is counted as "other".
pub fn scan_nvm(
    reader: &str,
    piv: &dyn PivBackend,
    store_object_ids: &std::collections::HashSet<u32>,
) -> Result<NvmUsage> {
    let mut store_bytes = 0usize;
    let mut other_bytes = 0usize;

    // Scan the full yb store range: 0x5F_0000..0x5F_00FF.
    for i in 0u32..256 {
        let id = OBJECT_ID_ZERO + i;
        if let Some(size) = piv.object_size(reader, id)? {
            if store_object_ids.contains(&id) {
                store_bytes += size;
            } else {
                other_bytes += size;
            }
        }
    }

    // Scan well-known PIV objects outside the yb store range.
    for &id in KNOWN_PIV_OBJECTS {
        if let Some(size) = piv.object_size(reader, id)? {
            other_bytes += size;
        }
    }

    let used = store_bytes + other_bytes;
    let free_bytes = YUBIKEY_NVM_BYTES.saturating_sub(used);

    Ok(NvmUsage {
        store_bytes,
        other_bytes,
        free_bytes,
    })
}
