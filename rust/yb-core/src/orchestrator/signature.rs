// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
// SPDX-FileCopyrightText: 2025 - 2026 Thales Cloud Sécurisé
//
// SPDX-License-Identifier: MIT

//! Blob integrity signature trailer (spec 0017) and chain assembly.

use crate::piv::PivBackend;
use crate::store::{Object, ObjectParams, Store};
use sha2::{Digest, Sha256};

/// Compute SHA-256(payload) and ask the PIV key to sign it.  Append the
/// 65-byte trailer `[SIG_VERSION=0x01 || r (32 bytes) || s (32 bytes)]`
/// after the last payload byte in the assembled chain.
///
/// If signing fails for any reason the trailer is silently omitted and a
/// warning is printed, as required by spec §3.
pub(super) fn append_signature_trailer(
    store: &mut Store,
    piv: &dyn PivBackend,
    payload: &[u8],
    pin: Option<&str>,
) {
    let digest = Sha256::digest(payload);

    let raw_sig = match piv.ecdsa_sign(&store.reader, store.store_key_slot, &digest, pin) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "yb: warning: ECDSA sign failed, storing blob without integrity signature: {e}"
            );
            return;
        }
    };

    // Build the 65-byte trailer.
    let mut trailer = [0u8; 65];
    trailer[0] = 0x01; // SIG_VERSION
    trailer[1..33].copy_from_slice(&raw_sig[0..32]); // r
    trailer[33..65].copy_from_slice(&raw_sig[32..64]); // s

    // Find the last chunk in the chain by walking from the head we just built.
    // The head is the object with the highest age (just allocated).
    let last_idx = find_last_chunk_idx(store);

    let last_obj = &store.objects[last_idx as usize];
    let last_max_payload = if last_obj.chunk_pos == 0 {
        Object::head_payload_capacity(store.object_size, last_obj.blob_name.len())
    } else {
        Object::continuation_payload_capacity(store.object_size)
    };
    let last_payload_len = last_obj.payload.len();
    let space_in_last = last_max_payload.saturating_sub(last_payload_len);

    if space_in_last >= trailer.len() {
        // Trailer fits in the last slot's padding region.
        store.objects[last_idx as usize]
            .payload
            .extend_from_slice(&trailer);
        store.objects[last_idx as usize].dirty = true;
    } else {
        // Need a spill slot.  Check there is a free slot available.
        if store.free_count() == 0 {
            eprintln!("yb: warning: store full, cannot add signature spill slot — storing blob without integrity signature");
            return;
        }
        // Fill the remaining space in the last slot.
        store.objects[last_idx as usize]
            .payload
            .extend_from_slice(&trailer[..space_in_last]);
        store.objects[last_idx as usize].dirty = true;

        // Allocate a new continuation slot for the overflow bytes.
        let spill_idx = store.alloc_free().unwrap();
        let age = store.next_age();
        let chunk_pos = store.objects[last_idx as usize].chunk_pos + 1;
        let mut spill_obj = store.make_object(ObjectParams {
            index: spill_idx,
            age,
            chunk_pos,
            next_chunk: spill_idx, // self-reference = last chunk
        });
        spill_obj.payload = trailer[space_in_last..].to_vec();
        store.objects[spill_idx as usize] = spill_obj;
        // Point the previous last chunk at the spill slot.
        store.objects[last_idx as usize].next_chunk = spill_idx;
        store.objects[last_idx as usize].dirty = true;
    }
}

/// Walk the chunk chain and return the index of the last slot.
///
/// The last slot is the one whose `next_chunk` equals its own index.
/// We locate the head (chunk_pos == 0) with the maximum age, then follow
/// the chain to its terminus.
pub(super) fn find_last_chunk_idx(store: &Store) -> u8 {
    // Find the head with the highest age (the one we just wrote).
    let head = store
        .objects
        .iter()
        .filter(|o| o.is_head())
        .max_by_key(|o| o.age)
        .expect("store must have at least one head after store_blob");

    let chain = store.chunk_chain(head.index);
    *chain.last().expect("chain must be non-empty")
}

/// Assemble the payload, trailing bytes, and supernumerary-slot flag for a blob.
///
/// Returns `(payload, trailing, has_supernumerary_slot)` where:
/// - `payload` — exactly `blob_size` bytes of blob data
/// - `trailing` — bytes stored in the chain beyond `blob_size` (empty for
///   yb0/yb1; 65-byte signature trailer for yb2; possibly garbage if corrupt)
/// - `has_supernumerary_slot` — true if the last slot in the chain was not
///   needed to hold byte `#blob_size` (i.e. the chain covers `blob_size`
///   bytes without it)
pub fn collect_blob_chain(
    head: &crate::store::Object,
    store: &crate::store::Store,
) -> (Vec<u8>, Vec<u8>, bool) {
    let blob_size = head.blob_size as usize;
    let chain = store.chunk_chain(head.index);

    // Accumulate per-slot payload lengths to determine the supernumerary flag,
    // then concatenate all bytes.
    let mut all_bytes: Vec<u8> = Vec::new();
    let mut combined_without_last = 0usize;
    for (i, &idx) in chain.iter().enumerate() {
        let slot_bytes = &store.objects[idx as usize].payload;
        if i + 1 < chain.len() {
            combined_without_last += slot_bytes.len();
        }
        all_bytes.extend_from_slice(slot_bytes);
    }

    let has_supernumerary_slot = combined_without_last >= blob_size;

    let payload = all_bytes[..blob_size.min(all_bytes.len())].to_vec();
    let trailing = if all_bytes.len() > blob_size {
        all_bytes[blob_size..].to_vec()
    } else {
        vec![]
    };

    (payload, trailing, has_supernumerary_slot)
}
