// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! High-level blob operations: store, fetch, remove, list.

use crate::crypto;
use crate::piv::PivBackend;
use crate::store::{constants::MAX_NAME_LEN, Object, Store};
use anyhow::{bail, Context, Result};
use p256::PublicKey;

/// Encryption mode for `store_blob`.
pub enum Encryption<'a> {
    /// Store the blob in plaintext.
    None,
    /// Encrypt the blob to the given P-256 public key.
    Encrypted(&'a PublicKey),
}

/// Compression mode for `store_blob`.
#[derive(Clone, Copy)]
pub enum Compression {
    /// Try brotli level 11 and xz preset 9; store whichever is smaller,
    /// or uncompressed if compression makes no progress.
    Auto,
    /// Never compress.
    None,
}

/// Options for `store_blob`.
pub struct StoreOptions<'a> {
    pub encryption: Encryption<'a>,
    pub compression: Compression,
}

/// Magic prefix prepended to brotli-compressed payloads ("YBr\x01").
const BROTLI_MAGIC: &[u8; 4] = b"\x59\x42\x72\x01";

/// Standard xz stream magic.
const XZ_MAGIC: &[u8; 6] = b"\xfd7zXZ\x00";

/// Bit 23 of the u24 `blob_plain_size` / `blob_size` wire fields.
/// Used as the compression flag (C-bit) in `blob_plain_size`, and as a
/// mask to verify that a size value fits in the remaining 23 bits.
pub(crate) const BLOB_SIZE_C_BIT: usize = 0x80_0000;

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
    management_key: Option<&str>,
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

    // Compress if requested.
    let (candidate, is_compressed) = match options.compression {
        Compression::None => (payload.to_vec(), false),
        Compression::Auto => compress_payload(name, payload)?,
    };

    // Encrypt if requested.
    let (data, blob_key_slot) = match options.encryption {
        Encryption::Encrypted(pk) => {
            let enc = crypto::hybrid_encrypt(&candidate, pk).context("encrypting blob")?;
            (enc, store.store_key_slot)
        }
        Encryption::None => (candidate, 0u8),
    };

    // blob_size is also a u24 field with the same C-bit constraint.
    if data.len() & BLOB_SIZE_C_BIT != 0 {
        anyhow::bail!(
            "blob '{}': stored size too large ({} bytes, max 0x7FFFFF)",
            name,
            data.len()
        );
    }

    let plain_size = payload.len() as u32;
    let blob_size = data.len() as u32;
    let name_len = name.len();

    // Calculate how many chunks we need.
    let head_cap = Object::head_payload_capacity(store.object_size, name_len);
    let cont_cap = Object::continuation_payload_capacity(store.object_size);

    let chunks_needed = chunks_needed(data.len(), name_len, store.object_size);

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
        is_compressed,
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
            is_compressed: false,
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
// Compression helpers
// ---------------------------------------------------------------------------

/// Compress `payload` with both brotli and xz; return the better candidate
/// and whether compression was applied.
fn compress_payload(name: &str, payload: &[u8]) -> Result<(Vec<u8>, bool)> {
    use std::io::Write as _;

    // Brotli level 11.
    let mut brotli_body = Vec::new();
    {
        let mut enc = brotli::CompressorWriter::new(&mut brotli_body, 4096, 11, 22);
        enc.write_all(payload)
            .with_context(|| format!("brotli compress blob '{name}'"))?;
    }
    // Prepend YBr\x01 magic.
    let mut brotli_out = Vec::with_capacity(BROTLI_MAGIC.len() + brotli_body.len());
    brotli_out.extend_from_slice(BROTLI_MAGIC);
    brotli_out.extend_from_slice(&brotli_body);

    // xz preset 9.
    let mut xz_out = Vec::new();
    {
        let mut enc = lzma_rust2::XzWriter::new(&mut xz_out, lzma_rust2::XzOptions::with_preset(9))
            .with_context(|| format!("xz compress blob '{name}'"))?;
        enc.write_all(payload)
            .with_context(|| format!("xz compress blob '{name}'"))?;
        enc.finish()
            .with_context(|| format!("xz compress blob '{name}'"))?;
    }

    if !xz_out.starts_with(XZ_MAGIC) {
        anyhow::bail!("xz output for blob '{name}' has unexpected magic — library bug");
    }

    // Pick the smaller candidate.
    let pick = if brotli_out.len() <= xz_out.len() {
        brotli_out
    } else {
        xz_out
    };

    if pick.len() < payload.len() {
        Ok((pick, true))
    } else {
        Ok((payload.to_vec(), false))
    }
}

/// Decompress a payload whose C-bit was set.  Dispatches on magic bytes.
fn decompress_payload(name: &str, payload: &[u8]) -> Result<Vec<u8>> {
    use std::io::Read as _;

    if payload.starts_with(XZ_MAGIC) {
        let mut out = Vec::new();
        let mut dec = lzma_rust2::XzReader::new(payload, false);
        dec.read_to_end(&mut out)
            .with_context(|| format!("decompressing blob '{name}'"))?;
        return Ok(out);
    }

    if payload.starts_with(BROTLI_MAGIC) {
        let compressed = &payload[BROTLI_MAGIC.len()..];
        let mut dec = brotli::Decompressor::new(compressed, 4096);
        let mut out = Vec::new();
        dec.read_to_end(&mut out)
            .with_context(|| format!("decompressing blob '{name}'"))?;
        return Ok(out);
    }

    anyhow::bail!("unknown compression format in blob '{name}'")
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
        let mut store = Store::format(&reader, &piv, 2, 0x82, Some(mgmt), None).unwrap();

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
            Some(mgmt),
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
            Some(mgmt),
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
            Some(mgmt),
            None,
        );
        assert!(result.is_ok(), "full store must not error");
        assert_eq!(result.unwrap(), false, "full store must return false");

        // Store must be unchanged — still two blobs.
        assert_eq!(list_blobs(&store).len(), 2, "store must be unmodified");
    }
}
