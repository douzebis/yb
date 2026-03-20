// SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! High-level blob operations: store, fetch, remove, list.

use crate::crypto;
use crate::piv::PivBackend;
use crate::store::{constants::MAX_NAME_LEN, Object, Store};
use anyhow::{bail, Context, Result};
use p256::PublicKey;

/// Metadata returned by list_blobs.
#[derive(Debug, Clone)]
pub struct BlobInfo {
    pub name: String,
    pub encrypted_size: u32,
    pub plain_size: u32,
    pub is_encrypted: bool,
    /// Modification time as a Unix timestamp (seconds since epoch).
    pub mtime: u32,
    pub chunk_count: usize,
}

#[cfg(feature = "chrono")]
impl BlobInfo {
    /// Return `mtime` as a local [`chrono::DateTime`].
    pub fn mtime_local(&self) -> chrono::DateTime<chrono::Local> {
        use chrono::TimeZone as _;
        chrono::Local
            .timestamp_opt(self.mtime as i64, 0)
            .single()
            .unwrap_or_else(chrono::Local::now)
    }
}

// ---------------------------------------------------------------------------
// store_blob
// ---------------------------------------------------------------------------

/// Store a blob on the YubiKey.
///
/// `peer_public_key` must be `Some` when `encrypted` is true.
/// Returns `false` if the store is full.
pub fn store_blob(
    store: &mut Store,
    piv: &dyn PivBackend,
    name: &str,
    payload: &[u8],
    encrypted: bool,
    peer_public_key: Option<&PublicKey>,
    management_key: Option<&str>,
    pin: Option<&str>,
) -> Result<bool> {
    validate_name(name)?;

    // Encrypt if requested.
    let (data, blob_key_slot) = if encrypted {
        let pk = peer_public_key
            .ok_or_else(|| anyhow::anyhow!("peer_public_key required for encrypted store"))?;
        let enc = crypto::hybrid_encrypt(payload, pk).context("encrypting blob")?;
        (enc, store.store_key_slot)
    } else {
        (payload.to_vec(), 0u8)
    };

    let plain_size = payload.len() as u32;
    let blob_size = data.len() as u32;
    let name_len = name.len();

    // Calculate how many chunks we need.
    let head_cap = Object::head_payload_capacity(store.object_size, name_len);
    let cont_cap = Object::continuation_payload_capacity(store.object_size);

    let chunks_needed = if data.len() <= head_cap {
        1
    } else {
        1 + (data.len() - head_cap).div_ceil(cont_cap)
    };

    if store.free_count() < chunks_needed {
        return Ok(false);
    }

    // Remove any existing blob with the same name.
    if let Some(head) = store.find_head(name) {
        let chain = store.chunk_chain(head.index);
        for idx in chain {
            store.objects[idx as usize].reset();
        }
    }

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
    store.objects[head_idx as usize] = Object {
        index: head_idx,
        object_size: store.object_size,
        yblob_magic: crate::store::constants::YBLOB_MAGIC,
        object_count: store.object_count,
        store_key_slot: store.store_key_slot,
        age,
        chunk_pos: 0,
        next_chunk: next,
        blob_mtime: mtime,
        blob_size,
        blob_key_slot,
        blob_plain_size: plain_size,
        blob_name: name.to_owned(),
        payload: data[..head_payload_end].to_vec(),
        dirty: true,
    };

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
        store.objects[idx as usize] = Object {
            index: idx,
            object_size: store.object_size,
            yblob_magic: crate::store::constants::YBLOB_MAGIC,
            object_count: store.object_count,
            store_key_slot: store.store_key_slot,
            age,
            chunk_pos: chunk_num as u8,
            next_chunk: next,
            blob_mtime: 0,
            blob_size: 0,
            blob_key_slot: 0,
            blob_plain_size: 0,
            blob_name: String::new(),
            payload: data[offset..end].to_vec(),
            dirty: true,
        };
        offset = end;
    }

    store.sync(piv, management_key, pin)?;
    Ok(true)
}

// ---------------------------------------------------------------------------
// fetch_blob
// ---------------------------------------------------------------------------

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
    let key_slot = head.blob_key_slot;

    // Concatenate all chunk payloads.
    let chain = store.chunk_chain(head.index);
    let mut data: Vec<u8> = Vec::new();
    for idx in chain {
        data.extend_from_slice(&store.objects[idx as usize].payload);
    }
    // Trim to blob_size (payload region may have trailing zeros).
    data.truncate(head.blob_size as usize);

    if is_encrypted {
        if pin.is_none() {
            bail!("blob '{name}' is encrypted but no PIN was provided");
        }
        let plaintext = crypto::hybrid_decrypt(piv, reader, key_slot, &data, pin, debug)
            .with_context(|| format!("decrypting blob '{name}'"))?;
        Ok(Some(plaintext))
    } else {
        Ok(Some(data))
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
    management_key: Option<&str>,
    pin: Option<&str>,
) -> Result<bool> {
    let head_idx = match store.find_head(name) {
        None => return Ok(false),
        Some(h) => h.index,
    };

    let chain = store.chunk_chain(head_idx);
    for idx in chain {
        store.objects[idx as usize].reset();
    }
    store.sync(piv, management_key, pin)?;
    Ok(true)
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
}
