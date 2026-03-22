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
