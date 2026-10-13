// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! High-level blob operations: store, fetch, remove, list.
//!
//! Sub-modules:
//! - [`types`]       — `Encryption`, `Compression`, `StoreOptions`, `BlobInfo`, constants
//! - [`compression`] — compress/decompress/encrypt pipeline
//! - [`signature`]   — signature trailer (spec 0017) and chain assembly
//! - this module     — `store_blob`, `fetch_blob`, `remove_blob`, `list_blobs`

mod compression;
mod signature;
mod types;

pub use signature::{check_blob_signature, collect_blob_chain, SigVerdict, SIG_TRAILER_LEN};
pub(crate) use types::BLOB_SIZE_C_BIT;
pub use types::{BlobInfo, Compression, Encryption, StoreOptions};

use crate::crypto;
use crate::piv::PivBackend;
use crate::store::{constants::MAX_NAME_LEN, Object, ObjectParams, Store};
use anyhow::{bail, Context, Result};

use compression::{compress_and_encrypt, decompress_payload};
use signature::append_signature_trailer;

// ---------------------------------------------------------------------------
// chunks_needed
// ---------------------------------------------------------------------------

/// Calculate how many objects a blob of `data_len` bytes with a name of
/// `name_len` bytes needs in a store with `object_size`-byte objects.
pub fn chunks_needed(data_len: usize, name_len: usize, object_size: usize) -> usize {
    let head_cap = Object::head_payload_capacity(object_size, name_len);
    let cont_cap = Object::continuation_payload_capacity(object_size);
    if data_len <= head_cap {
        1
    } else {
        1 + (data_len - head_cap).div_ceil(cont_cap)
    }
}

/// How many objects a stored blob of `data_len` bytes may occupy: its data
/// plus the signature trailer, which can need an extra chunk (spec 0017).
/// Both capacity checks use it, so they cannot disagree (spec 0031).
pub fn objects_needed(data_len: usize, name_len: usize, object_size: usize) -> usize {
    chunks_needed(data_len + SIG_TRAILER_LEN, name_len, object_size)
}

// ---------------------------------------------------------------------------
// store_blob
// ---------------------------------------------------------------------------

/// Store a blob on the YubiKey.
///
/// Returns `false` if the store is full.
pub fn store_blob(
    store: &mut Store,
    piv: &dyn PivBackend,
    name: &str,
    payload: &[u8],
    options: StoreOptions<'_>,
    management_key: &str,
    pin: Option<&str>,
) -> Result<bool> {
    validate_name(name)?;

    // blob_plain_size is a u24 field whose bit 23 is the C flag;
    // the size must not touch that bit or any higher bit.
    if payload.len() & BLOB_SIZE_C_BIT != 0 {
        anyhow::bail!(
            "blob '{}': plaintext too large ({} bytes, max 0x7FFFFF)",
            name,
            payload.len()
        );
    }

    let (data, blob_key_slot, is_compressed) =
        compress_and_encrypt(name, payload, &options, store.store_key_slot)?;

    let plain_size = payload.len() as u32;
    let blob_size = data.len() as u32;
    let name_len = name.len();

    // Calculate how many chunks we need.
    let head_cap = Object::head_payload_capacity(store.object_size, name_len);
    let cont_cap = Object::continuation_payload_capacity(store.object_size);

    let chunks_needed = chunks_needed(data.len(), name_len, store.object_size);

    // The old copy, if any, stays occupied until the new one is written
    // (spec 0031): the new copy, signature trailer included, goes into
    // objects that are free now, so a YubiKey pulled out mid-write leaves
    // the old copy intact.
    let needed = objects_needed(data.len(), name_len, store.object_size);
    if store.free_count() < needed {
        return Ok(false);
    }
    store.ensure_age_room(needed)?;
    let old_chain: Vec<u8> = store
        .find_head(name)
        .map(|head| store.chunk_chain(head.index))
        .unwrap_or_default();

    // Allocate chunks and fill them.
    let mtime = Store::now_unix();
    let mut chunk_indices: Vec<u8> = Vec::with_capacity(chunks_needed);
    for _ in 0..chunks_needed {
        let idx = store.alloc_free().unwrap();
        chunk_indices.push(idx);
        // Mark as provisionally occupied so alloc_free doesn't pick it again.
        store.objects[idx as usize].age = 1; // temporary marker
    }

    // Head chunk.
    let head_idx = chunk_indices[0];
    let head_payload_end = head_cap.min(data.len());
    let age = store.next_age();
    let next = if chunks_needed == 1 {
        head_idx
    } else {
        chunk_indices[1]
    };
    let mut head_obj = store.make_object(ObjectParams {
        index: head_idx,
        age,
        chunk_pos: 0,
        next_chunk: next,
    });
    head_obj.blob_mtime = mtime;
    head_obj.blob_size = blob_size;
    head_obj.blob_key_slot = blob_key_slot;
    head_obj.blob_plain_size = plain_size;
    head_obj.is_compressed = is_compressed;
    head_obj.blob_name = name.to_owned();
    head_obj.payload = data[..head_payload_end].to_vec();
    store.objects[head_idx as usize] = head_obj;

    // Continuation chunks.
    let mut offset = head_payload_end;
    for (i, &idx) in chunk_indices[1..].iter().enumerate() {
        let chunk_num = i + 1;
        let end = (offset + cont_cap).min(data.len());
        let age = store.next_age();
        let next = if chunk_num + 1 < chunks_needed {
            chunk_indices[chunk_num + 1]
        } else {
            idx // self-reference = last chunk
        };
        let mut cont_obj = store.make_object(ObjectParams {
            index: idx,
            age,
            chunk_pos: chunk_num as u8,
            next_chunk: next,
        });
        cont_obj.payload = data[offset..end].to_vec();
        store.objects[idx as usize] = cont_obj;
        offset = end;
    }

    // Append the 65-byte signature trailer (specs 0017, 0033); a failure
    // stores nothing.
    append_signature_trailer(store, piv, &data, pin)?;

    // Write the new copy: its continuation chunks (and signature spill
    // chunk) first, its head last, so that the head never reaches the card
    // before its chain is complete (spec 0031).
    let mut order = store.chunk_chain(head_idx);
    order.rotate_left(1);
    store.sync_ordered(piv, management_key, &order)?;

    // Only now free the old copy.  If this is interrupted, the new copy is
    // complete and newer, and the leftovers go at the next write.
    for idx in old_chain {
        store.objects[idx as usize].reset();
    }
    store.sync(piv, management_key)?;
    Ok(true)
}

// ---------------------------------------------------------------------------
// fetch_blob
// ---------------------------------------------------------------------------

/// Whether the blob of `head` is encrypted with the legacy, unauthenticated
/// AES-CBC scheme (before spec 0006); its first stored bytes are in the head.
pub fn uses_legacy_encryption(head: &Object) -> bool {
    head.is_encrypted() && crypto::is_legacy_ciphertext(head.payload())
}

/// Fetch a blob by name.  Returns None if not found.
pub fn fetch_blob(
    store: &Store,
    piv: &dyn PivBackend,
    reader: &str,
    name: &str,
    pin: Option<&str>,
    debug: bool,
) -> Result<Option<Vec<u8>>> {
    let head = match store.find_head(name) {
        None => return Ok(None),
        Some(h) => h,
    };

    let is_encrypted = head.is_encrypted();
    let is_compressed = head.is_compressed;
    let key_slot = head.blob_key_slot;

    // Concatenate all chunk payloads.
    let chain = store.chunk_chain(head.index);
    let mut data: Vec<u8> = Vec::new();
    for idx in chain {
        data.extend_from_slice(&store.objects[idx as usize].payload);
    }
    // Trim to blob_size (payload region may have trailing zeros).
    data.truncate(head.blob_size as usize);

    let payload = if is_encrypted {
        if pin.is_none() {
            bail!("blob '{name}' is encrypted but no PIN was provided");
        }
        crypto::hybrid_decrypt(piv, reader, key_slot, &data, pin, debug)
            .with_context(|| format!("decrypting blob '{name}'"))?
    } else {
        data
    };

    if is_compressed {
        let plaintext = decompress_payload(name, &payload)?;
        Ok(Some(plaintext))
    } else {
        Ok(Some(payload))
    }
}

// ---------------------------------------------------------------------------
// remove_blob
// ---------------------------------------------------------------------------

/// Remove a blob by name.  Returns false if not found.
pub fn remove_blob(
    store: &mut Store,
    piv: &dyn PivBackend,
    name: &str,
    management_key: &str,
) -> Result<bool> {
    Ok(remove_blobs(store, piv, &[name], management_key)? == 1)
}

/// Remove blobs by name in one write pass, and return how many were found.
///
/// All heads are written first: once a head is gone, the rest of its chain
/// is a leftover, so an interruption leaves each blob either whole or gone
/// (spec 0031).
pub fn remove_blobs<S: AsRef<str>>(
    store: &mut Store,
    piv: &dyn PivBackend,
    names: &[S],
    management_key: &str,
) -> Result<usize> {
    let mut heads: Vec<u8> = Vec::new();
    for name in names {
        let Some(head) = store.find_head(name.as_ref()) else {
            continue;
        };
        let head_idx = head.index;
        for idx in store.chunk_chain(head_idx) {
            store.objects[idx as usize].reset();
        }
        heads.push(head_idx);
    }
    if !heads.is_empty() {
        store.sync_ordered(piv, management_key, &heads)?;
    }
    Ok(heads.len())
}

// ---------------------------------------------------------------------------
// list_blobs
// ---------------------------------------------------------------------------

/// Return metadata for all blobs, sorted by name.
pub fn list_blobs(store: &Store) -> Vec<BlobInfo> {
    let mut blobs: Vec<BlobInfo> = store
        .objects
        .iter()
        .filter(|o| o.is_head())
        .map(|head| {
            let chain = store.chunk_chain(head.index);
            BlobInfo {
                name: head.blob_name.clone(),
                encrypted_size: head.blob_size,
                plain_size: head.blob_plain_size,
                is_encrypted: head.is_encrypted(),
                is_legacy_encryption: uses_legacy_encryption(head),
                mtime: head.blob_mtime,
                chunk_count: chain.len(),
            }
        })
        .collect();

    blobs.sort_by(|a, b| a.name.cmp(&b.name));
    blobs
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("blob name must not be empty");
    }
    if name.len() > MAX_NAME_LEN {
        bail!("blob name too long ({} > {MAX_NAME_LEN} bytes)", name.len());
    }
    if name.contains('\0') || name.contains('/') {
        bail!("blob name must not contain null bytes or '/'");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_name_invalid_chars() {
        // Null byte and slash are forbidden.
        assert!(validate_name("foo\0bar").is_err());
        assert!(validate_name("foo/bar").is_err());
        assert!(validate_name("/leading").is_err());
        assert!(validate_name("trailing/").is_err());

        // Everything else is fine: spaces, Unicode, emoji, other punctuation.
        assert!(validate_name("hello world").is_ok());
        assert!(validate_name("café").is_ok());
        assert!(validate_name("blob-name_v2.bin").is_ok());
        assert!(validate_name("密钥").is_ok());
        assert!(validate_name("🔑").is_ok());
        assert!(validate_name("tab\there").is_ok());
    }

    /// T6: validate_name length boundaries — empty, max-length, and one over max.
    #[test]
    fn validate_name_length_boundaries() {
        assert!(validate_name("").is_err(), "empty name must be rejected");
        assert!(
            validate_name(&"x".repeat(MAX_NAME_LEN)).is_ok(),
            "max-length name must be accepted"
        );
        assert!(
            validate_name(&"x".repeat(MAX_NAME_LEN + 1)).is_err(),
            "name one byte over max must be rejected"
        );
    }

    /// T14: store_blob returns false (not an error) when the store is full,
    /// and leaves the store unchanged.
    #[test]
    fn store_blob_returns_false_when_full() {
        use crate::piv::VirtualPiv;
        use crate::store::Store;
        use std::path::Path;

        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/with_key.yaml");
        let piv = VirtualPiv::from_fixture(&fixture).unwrap();
        let mgmt = "010203040506070801020304050607080102030405060708";
        let reader = piv.reader_name();

        // Format a tiny store: 2 objects.
        let mut store = Store::format(&reader, &piv, 2, 0x82, mgmt).unwrap();

        // Fill both slots with single-chunk blobs.
        let ok1 = store_blob(
            &mut store,
            &piv,
            "a",
            b"aaa",
            StoreOptions {
                encryption: Encryption::None,
                compression: Compression::None,
            },
            mgmt,
            None,
        )
        .unwrap();
        assert!(ok1, "first blob should fit");
        let ok2 = store_blob(
            &mut store,
            &piv,
            "b",
            b"bbb",
            StoreOptions {
                encryption: Encryption::None,
                compression: Compression::None,
            },
            mgmt,
            None,
        )
        .unwrap();
        assert!(ok2, "second blob should fit");

        assert_eq!(store.free_count(), 0, "store should be full");

        // Attempt to store a third blob — must return false, not an error.
        let result = store_blob(
            &mut store,
            &piv,
            "c",
            b"ccc",
            StoreOptions {
                encryption: Encryption::None,
                compression: Compression::None,
            },
            mgmt,
            None,
        );
        assert!(result.is_ok(), "full store must not error");
        assert!(!result.unwrap(), "full store must return false");

        // Store must be unchanged — still two blobs.
        assert_eq!(list_blobs(&store).len(), 2, "store must be unmodified");
    }
}
