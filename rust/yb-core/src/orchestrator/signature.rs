// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Blob integrity signature trailer (spec 0017) and chain assembly.

use super::protection::BlobMeta;
use crate::store::{Object, ObjectParams, Store};
use sha2::{Digest, Sha256};

/// Length of the signature trailer appended after a blob's data (spec 0017).
pub const SIG_TRAILER_LEN: usize = 65;

/// Append `trailer` (spec 0017: a signature; spec 0028: a checksum and
/// seal) after the last payload byte of the blob just built, in a spill
/// chunk if needed.  `objects_needed` counts that chunk (spec 0031).
pub(super) fn append_trailer(store: &mut Store, trailer: &[u8]) -> anyhow::Result<()> {
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
            .extend_from_slice(trailer);
        store.objects[last_idx as usize].dirty = true;
    } else {
        // Need a spill slot.  Check there is a free slot available.
        // objects_needed counts this chunk (spec 0031); a missing one is a bug.
        if store.free_count() == 0 {
            anyhow::bail!("no room for the blob's trailer; nothing was stored");
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
    Ok(())
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

// ---------------------------------------------------------------------------
// Signature verdicts (specs 0017, 0033)
// ---------------------------------------------------------------------------

/// Signature trailer of spec 0017: SHA-256 of the stored bytes only.
const SIG_V1: u8 = 0x01;
/// Signature trailer of spec 0033: SHA-256 of the metadata and the stored
/// bytes ([`signed_digest_v2`]).
pub(super) const SIG_V2: u8 = 0x02;
/// Domain separation for version 2 signatures.
const SIG_V2_TAG: &[u8] = b"yb-blob-sig-v2\0";

/// What a blob's signature trailer says (specs 0017, 0033).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigVerdict {
    /// A valid signature (version 1 or 2).
    Verified,
    /// No signature: written by a yb version before spec 0017.
    Unsigned,
    /// Signed, but the slot has no certificate to check it against.
    Unverifiable,
    /// Signed with a signature version this yb does not know: written by a
    /// newer yb.  Not checkable here, and not taken for corruption, so that
    /// a new version does not raise false alarms on older installations.
    NewerVersion,
    /// A signature that does not verify, or a damaged chain.
    Corrupted,
}

impl std::fmt::Display for SigVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SigVerdict::Verified => "VERIFIED",
            SigVerdict::Unsigned => "UNSIGNED",
            SigVerdict::Unverifiable | SigVerdict::NewerVersion => "UNVERIFIABLE",
            SigVerdict::Corrupted => "CORRUPTED",
        })
    }
}

/// The digest a version 2 signature signs: the blob's metadata and its
/// stored (possibly compressed, possibly encrypted) bytes, so that a blob
/// cannot be renamed, or its metadata altered, without breaking it.
pub(super) fn signed_digest_v2(meta: &BlobMeta, stored: &[u8]) -> [u8; 32] {
    let name = meta.name.as_bytes();
    let mut h = Sha256::new();
    h.update(SIG_V2_TAG);
    h.update([name.len() as u8]); // names are at most 255 bytes
    h.update(name);
    h.update([meta.key_byte, u8::from(meta.compressed)]);
    h.update(meta.plain_size.to_le_bytes());
    h.update(meta.stored_size.to_le_bytes());
    h.update(meta.mtime.to_le_bytes());
    h.update(stored);
    h.finalize().into()
}

/// Check the signature of the blob whose head is `head`, with the public
/// key of the store slot's certificate (no PIN needed).
pub fn check_blob_signature(
    head: &Object,
    store: &Store,
    verifying_key: Option<&p256::ecdsa::VerifyingKey>,
) -> SigVerdict {
    use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature};

    let blob_size = head.blob_size as usize;
    let (payload, trailing, has_supernumerary) = collect_blob_chain(head, store);
    if payload.len() + trailing.len() < blob_size {
        return SigVerdict::Corrupted;
    }
    // No trailer, or zero padding (yb0 fixed-size slots): unsigned, unless
    // the padding is not zeros or occupies a slot of its own.
    let zero_padding = trailing.iter().all(|&b| b == 0);
    if trailing.is_empty() || trailing.len() != SIG_TRAILER_LEN || trailing[0] == 0x00 {
        return if trailing.is_empty() || (zero_padding && !has_supernumerary) {
            SigVerdict::Unsigned
        } else {
            SigVerdict::Corrupted
        };
    }
    let digest: [u8; 32] = match trailing[0] {
        SIG_V1 => Sha256::digest(&payload).into(),
        SIG_V2 => signed_digest_v2(&BlobMeta::from_head(head), &payload),
        _ => return SigVerdict::NewerVersion,
    };
    let Some(vk) = verifying_key else {
        return SigVerdict::Unverifiable;
    };
    let mut raw = [0u8; 64];
    raw.copy_from_slice(&trailing[1..SIG_TRAILER_LEN]);
    let Ok(sig) = Signature::from_der(&crate::crypto::raw_ecdsa_to_der(&raw)) else {
        return SigVerdict::Corrupted;
    };
    match vk.verify_prehash(&digest, &sig) {
        Ok(()) => SigVerdict::Verified,
        Err(_) => SigVerdict::Corrupted,
    }
}
