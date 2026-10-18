// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! High-level blob operations: store, fetch, remove, list.
//!
//! Sub-modules:
//! - [`types`]       — `Encryption`, `Compression`, `StoreOptions`, `BlobInfo`, constants
//! - [`compression`] — compression before encryption
//! - [`protection`]  — what a store kind does to protect blobs (spec 0028)
//! - [`signature`]   — trailers (spec 0017), signatures and chain assembly
//! - this module     — `store_blob`, `fetch_blob`, `remove_blob`, `list_blobs`

mod compression;
// Post-quantum stores need the FIDO2 module, not built on Windows.
#[cfg(not(windows))]
pub mod post_quantum;
mod protection;
mod signature;
mod types;

pub use protection::{BlobMeta, LegacyProtection, Protected, Protection};
pub use signature::{check_blob_signature, collect_blob_chain, SigVerdict, SIG_TRAILER_LEN};
pub(crate) use types::BLOB_SIZE_C_BIT;
pub use types::{BlobInfo, Compression, Encryption, StoreOptions};

use crate::crypto;
use crate::piv::PivBackend;
use crate::store::{constants::MAX_NAME_LEN, Object, ObjectParams, Store};
use anyhow::{bail, Result};

use compression::{compress, decompress_payload};
use signature::append_trailer;

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

/// Store a blob on the YubiKey, in a legacy store (PIV encryption and
/// signature, with `pin`).
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
    store_blob_checked(
        store,
        piv,
        name,
        payload,
        options,
        management_key,
        pin,
        None,
    )
}

/// [`store_blob`], with `before_write` checked on the store read under the
/// card lock (see [`store_blob_with_checked`]).
#[allow(clippy::too_many_arguments)]
pub fn store_blob_checked(
    store: &mut Store,
    piv: &dyn PivBackend,
    name: &str,
    payload: &[u8],
    options: StoreOptions<'_>,
    management_key: &str,
    pin: Option<&str>,
    before_write: Option<BeforeWrite<'_>>,
) -> Result<bool> {
    let (encrypt, encryption_key) = match options.encryption {
        Encryption::None => (false, None),
        Encryption::Encrypted(pk) => (true, Some(pk)),
    };
    let reader = store.reader.clone();
    let protection = LegacyProtection {
        piv,
        reader: &reader,
        slot: store.store_key_slot,
        encryption_key,
        verifying_key: None,
        pin,
        debug: false,
    };
    store_blob_with_checked(
        store,
        piv,
        &protection,
        name,
        payload,
        encrypt,
        options.compression,
        Some(management_key),
        before_write,
    )
}

/// Store a blob on the YubiKey, protected by `protection` (spec 0028).
///
/// Returns `false` if the store is full, found before anything else.  The
/// blob is compressed, then protected (which may ask for the PIN), and only
/// then written: a failure before the writes stores nothing.  The writes
/// use the management key the protection provides (post-quantum stores),
/// else `management_key`.
#[allow(clippy::too_many_arguments)]
pub fn store_blob_with(
    store: &mut Store,
    piv: &dyn PivBackend,
    protection: &dyn Protection,
    name: &str,
    payload: &[u8],
    encrypt: bool,
    compression: Compression,
    management_key: Option<&str>,
) -> Result<bool> {
    store_blob_with_checked(
        store,
        piv,
        protection,
        name,
        payload,
        encrypt,
        compression,
        management_key,
        None,
    )
}

/// What a write checks on the store it reads under the card lock, before
/// writing anything: an error stops the write (spec 0049, S4).
pub type BeforeWrite<'a> = &'a dyn Fn(&Store) -> Result<()>;

/// The blob changed on the YubiKey since the snapshot a write was asked
/// to check against (spec 0049, S4): the write wrote nothing.
#[derive(Debug)]
pub struct BlobChanged(pub String);

impl std::fmt::Display for BlobChanged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "'{}' changed on the YubiKey since it was read; nothing was written",
            self.0
        )
    }
}

impl std::error::Error for BlobChanged {}

/// A [`BeforeWrite`] check (spec 0049, S4): fails with [`BlobChanged`] if
/// the blob `name` in the store read under the lock (its head object,
/// bytes and age) differs from the blob in `snapshot`: rewritten, removed,
/// or created since.
pub fn unchanged_since<'a>(snapshot: &Store, name: &'a str) -> impl Fn(&Store) -> Result<()> + 'a {
    let head = |store: &Store| store.find_head(name).map(|h| (h.index(), h.to_bytes()));
    let before = head(snapshot);
    move |now: &Store| {
        if head(now) == before {
            Ok(())
        } else {
            Err(BlobChanged(name.to_owned()).into())
        }
    }
}

/// Read the whole store again, under the card lock the caller holds, and
/// plan from that read (spec 0048, S2): `store` becomes the store as it is.
/// Fails, writing nothing, if it is no longer the same store (formatted
/// again since `store` was read).
fn reload_for_write(store: &mut Store, piv: &dyn PivBackend) -> Result<()> {
    let fresh = Store::from_device(&store.reader, piv)?;
    let identity = |s: &Store| {
        (
            s.kind.is_post_quantum(),
            s.object_count,
            s.store_key_slot,
            s.descriptor().map(|d| d.to_bytes()),
        )
    };
    if identity(&fresh) != identity(store) {
        bail!("the store was formatted again meanwhile; nothing was written");
    }
    *store = fresh;
    Ok(())
}

/// [`store_blob_with`], with `before_write` checked on the store read
/// under the card lock.
///
/// The order (spec 0048, S2): the room, from `store` as the caller read
/// it; the protection, which may wait for the user (PIN, touch); then,
/// under the card lock, a whole read of the store, `before_write`, the
/// room again, and the writes.  `store` is left as that read found it,
/// with this write applied.
#[allow(clippy::too_many_arguments)]
pub fn store_blob_with_checked(
    store: &mut Store,
    piv: &dyn PivBackend,
    protection: &dyn Protection,
    name: &str,
    payload: &[u8],
    encrypt: bool,
    compression: Compression,
    management_key: Option<&str>,
    before_write: Option<BeforeWrite<'_>>,
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

    let (candidate, is_compressed) = compress(name, payload, compression)?;
    let (encryption_overhead, trailer_len) = protection.overhead(encrypt);
    let data_len = candidate.len() + encryption_overhead;
    // blob_size is a u24 field; bit 23 is the C flag and must not be set.
    if data_len & BLOB_SIZE_C_BIT != 0 {
        anyhow::bail!("blob '{name}': stored size too large ({data_len} bytes, max 0x7FFFFF)");
    }

    let name_len = name.len();

    // The old copy, if any, stays occupied until the new one is written
    // (spec 0031): the new copy, trailer included, goes into objects that
    // are free now, so a YubiKey pulled out mid-write leaves the old copy
    // intact.
    let needed = chunks_needed(data_len + trailer_len, name_len, store.object_size);
    if store.free_count() < needed {
        return Ok(false);
    }
    store.ensure_age_room(needed)?;

    // Protect before any write (spec 0028): signing or sealing may fail
    // (PIN, touch), and then nothing is written, not even the cleanup.
    let mtime = Store::now_unix();
    let plain_size = payload.len() as u32;
    let protected =
        protection.protect(name, &candidate, encrypt, is_compressed, plain_size, mtime)?;
    if protected.stored.len() != data_len || protected.trailer.len() != trailer_len {
        bail!("blob '{name}': protected size differs from the announced overhead (bug)");
    }
    let protected_key = protected.management_key;
    let Some(management_key) = protected_key
        .as_deref()
        .map(String::as_str)
        .or(management_key)
    else {
        bail!("blob '{name}': no management key to write it");
    };
    let data = protected.stored;
    let blob_key_slot = protected.key_byte;
    let blob_size = data.len() as u32;

    // Under the card lock, plan from the store as it is (spec 0048): the
    // protection above does not depend on where the blob goes.
    let _lock = piv.exclusive(&store.reader)?;
    reload_for_write(store, piv)?;
    if let Some(check) = before_write {
        check(store)?;
    }
    if store.free_count() < needed {
        return Ok(false);
    }
    store.ensure_age_room(needed)?;

    // Clean up first (spec 0038): the leftovers loading reset, and objects
    // a card out of memory deleted, are written before any new data, so
    // that the memory they held is free for it.
    store.sync(piv, management_key)?;
    let old_chain: Vec<u8> = store
        .find_head(name)
        .map(|head| store.chunk_chain(head.index))
        .unwrap_or_default();

    // Calculate how many chunks we need.
    let head_cap = Object::head_payload_capacity(store.object_size, name_len);
    let cont_cap = Object::continuation_payload_capacity(store.object_size);

    let chunks_needed = chunks_needed(data.len(), name_len, store.object_size);

    // Allocate chunks and fill them.
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

    // Append the trailer (specs 0017, 0033: the signature), in a spill
    // chunk if needed.
    append_trailer(store, &protected.trailer)?;

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

/// Fetch a blob by name from a legacy store (`pin` decrypts).  Returns
/// None if not found.
pub fn fetch_blob(
    store: &Store,
    piv: &dyn PivBackend,
    reader: &str,
    name: &str,
    pin: Option<&str>,
    debug: bool,
) -> Result<Option<Vec<u8>>> {
    let protection = LegacyProtection {
        piv,
        reader,
        slot: store.store_key_slot,
        encryption_key: None,
        verifying_key: None,
        pin,
        debug,
    };
    fetch_blob_with(store, &protection, name)
}

/// Why a fetch without PIN refused a blob (spec 0044).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NoPinFetchError {
    /// Encrypted blobs need the PIN; nothing was returned.
    #[error("'{0}' is encrypted: it cannot be read without the PIN")]
    Encrypted(String),
    /// A legacy blob whose signature does not verify.
    #[error("'{0}' is corrupted or was tampered with: its signature does not verify")]
    Corrupted(String),
}

/// Fetch an unencrypted blob without any PIN (spec 0044), with the check
/// that needs none:
/// - legacy stores: its signature, against the slot's certificate;
/// - post-quantum stores: its checksum only, not its seal nor the
///   management key, so corruption is detected, not forgery.
///
/// Encrypted blobs are refused ([`NoPinFetchError::Encrypted`]).  Returns
/// the content and the verdict, or None if not found.  Writes nothing.
pub fn fetch_unencrypted(
    store: &Store,
    piv: &dyn PivBackend,
    reader: &str,
    name: &str,
) -> Result<Option<(Vec<u8>, SigVerdict)>> {
    let Some(head) = store.find_head(name) else {
        return Ok(None);
    };
    if head.is_encrypted() {
        return Err(NoPinFetchError::Encrypted(name.to_owned()).into());
    }
    if store.kind.is_post_quantum() {
        #[cfg(not(windows))]
        {
            let data = fetch_blob_with(store, &post_quantum::ChecksumOnly, name)?;
            return Ok(data.map(|d| (d, SigVerdict::ChecksumOk)));
        }
        #[cfg(windows)]
        bail!("post-quantum stores are not supported on Windows");
    }
    let verifying_key = piv
        .read_certificate(reader, store.store_key_slot)
        .ok()
        .and_then(|der| crate::parse_ec_public_key_from_cert_der(&der).ok())
        .map(|pk| p256::ecdsa::VerifyingKey::from(&pk));
    let verdict = check_blob_signature(head, store, verifying_key.as_ref());
    if verdict == SigVerdict::Corrupted {
        return Err(NoPinFetchError::Corrupted(name.to_owned()).into());
    }
    let data = fetch_blob(store, piv, reader, name, None, false)?;
    Ok(data.map(|d| (d, verdict)))
}

/// Fetch a blob by name, opened by `protection` (spec 0028).  Returns None
/// if not found.
pub fn fetch_blob_with(
    store: &Store,
    protection: &dyn Protection,
    name: &str,
) -> Result<Option<Vec<u8>>> {
    let Some(head) = store.find_head(name) else {
        return Ok(None);
    };
    let meta = BlobMeta::from_head(head);
    let (stored, trailer, _) = collect_blob_chain(head, store);
    let payload = protection.open(&meta, &stored, &trailer)?;
    if meta.compressed {
        Ok(Some(decompress_payload(name, &payload)?))
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
    remove_blobs_checked(store, piv, names, management_key, None)
}

/// [`remove_blobs`], under the card lock from a whole read of the store
/// (spec 0048), with `before_write` checked on that read.  `store` is left
/// as that read found it, with the removal applied.
pub fn remove_blobs_checked<S: AsRef<str>>(
    store: &mut Store,
    piv: &dyn PivBackend,
    names: &[S],
    management_key: &str,
    before_write: Option<BeforeWrite<'_>>,
) -> Result<usize> {
    let _lock = piv.exclusive(&store.reader)?;
    reload_for_write(store, piv)?;
    if let Some(check) = before_write {
        check(store)?;
    }
    let heads: Vec<u8> = names
        .iter()
        .filter_map(|name| store.find_head(name.as_ref()).map(|h| h.index))
        .collect();
    if heads.is_empty() {
        return Ok(0);
    }
    // Clean up first (spec 0038), as in `store_blob`.
    store.sync(piv, management_key)?;
    for &head_idx in &heads {
        for idx in store.chunk_chain(head_idx) {
            store.objects[idx as usize].reset();
        }
    }
    store.sync_ordered(piv, management_key, &heads)?;
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
