// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! What a store kind does to protect its blobs (spec 0028): encryption,
//! signature or seal, and the checks that go with them.
//!
//! The orchestrator keeps the chunk logic, the same for every store kind,
//! and asks a [`Protection`] for the rest.  [`LegacyProtection`] is the
//! PIV design of yb 0.6: ECDH encryption to the store slot's key, and an
//! ECDSA signature by the same key (specs 0006, 0017, 0033).

use super::signature::{
    check_blob_signature, signed_digest_v2, SigVerdict, SIG_TRAILER_LEN, SIG_V2,
};
use crate::crypto;
use crate::piv::PivBackend;
use crate::store::{Object, Store};
use anyhow::{bail, Context, Result};
use p256::ecdsa::VerifyingKey;
use p256::PublicKey;

/// A blob's metadata, as its head chunk records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobMeta {
    pub name: String,
    /// `BLOB_KEY_SLOT`: 0 for an unencrypted blob, else the PIV slot used.
    pub key_byte: u8,
    /// The C-bit: the payload was compressed before encryption.
    pub compressed: bool,
    pub plain_size: u32,
    /// `BLOB_SIZE`: the stored (possibly compressed, possibly encrypted)
    /// bytes, without the trailer.
    pub stored_size: u32,
    pub mtime: u32,
}

impl BlobMeta {
    /// The metadata recorded in `head`.
    pub fn from_head(head: &Object) -> Self {
        Self {
            name: head.blob_name.clone(),
            key_byte: head.blob_key_slot,
            compressed: head.is_compressed,
            plain_size: head.blob_plain_size,
            stored_size: head.blob_size,
            mtime: head.blob_mtime,
        }
    }

    pub fn is_encrypted(&self) -> bool {
        self.key_byte != 0
    }
}

/// A blob ready to be written: its stored bytes, the `BLOB_KEY_SLOT` byte
/// of its head, and the trailer that follows the stored bytes in its chain.
pub struct Protected {
    pub stored: Vec<u8>,
    pub key_byte: u8,
    pub trailer: Vec<u8>,
}

/// What a store kind does to protect blobs (spec 0028, "Code structure").
pub trait Protection {
    /// The bytes encryption adds to a payload, and the trailer's length:
    /// what a blob of a given size needs, known before [`Self::protect`]
    /// (which may ask for the PIN), so that a full store is found first.
    fn overhead(&self, encrypt: bool) -> (usize, usize);

    /// Encrypt `payload` (already compressed, if it is) when `encrypt`, and
    /// build the trailer that signs or seals it with `name`, `compressed`,
    /// `plain_size` and `mtime`.  Nothing is written to the card: a failure
    /// here stores nothing.
    fn protect(
        &self,
        name: &str,
        payload: &[u8],
        encrypt: bool,
        compressed: bool,
        plain_size: u32,
        mtime: u32,
    ) -> Result<Protected>;

    /// Decrypt a blob's stored bytes (unchanged if it is not encrypted).
    fn open(&self, meta: &BlobMeta, stored: &[u8], trailer: &[u8]) -> Result<Vec<u8>>;

    /// The integrity check that needs no PIN (`yb ls`, `yb fsck`, and
    /// `yb fetch` before decrypting).
    fn quick_check(&self, head: &Object, store: &Store) -> SigVerdict;
}

/// The PIV protection of yb 0.6 (legacy stores).
pub struct LegacyProtection<'a> {
    pub piv: &'a dyn PivBackend,
    pub reader: &'a str,
    /// The store's key slot: ECDH decryption and ECDSA signing.
    pub slot: u8,
    /// The slot's public key, to encrypt to; only needed to store
    /// encrypted blobs.
    pub encryption_key: Option<&'a PublicKey>,
    /// The slot certificate's key, to check signatures without the PIN.
    pub verifying_key: Option<&'a VerifyingKey>,
    /// The PIV PIN, for signing and decrypting.
    pub pin: Option<&'a str>,
    pub debug: bool,
}

impl Protection for LegacyProtection<'_> {
    fn overhead(&self, encrypt: bool) -> (usize, usize) {
        let encryption = if encrypt { crypto::GCM_OVERHEAD } else { 0 };
        (encryption, SIG_TRAILER_LEN)
    }

    fn protect(
        &self,
        name: &str,
        payload: &[u8],
        encrypt: bool,
        compressed: bool,
        plain_size: u32,
        mtime: u32,
    ) -> Result<Protected> {
        let (stored, key_byte) = if encrypt {
            let Some(pk) = self.encryption_key else {
                bail!("blob '{name}': no key to encrypt to");
            };
            let enc = crypto::hybrid_encrypt(payload, pk).context("encrypting blob")?;
            (enc, self.slot)
        } else {
            (payload.to_vec(), 0u8)
        };

        let meta = BlobMeta {
            name: name.to_owned(),
            key_byte,
            compressed,
            plain_size,
            stored_size: stored.len() as u32,
            mtime,
        };
        let digest = signed_digest_v2(&meta, &stored);

        // A blob is never stored unsigned (spec 0033): signing fails the
        // store, before anything is written.
        let raw_sig = self
            .piv
            .ecdsa_sign(self.reader, self.slot, &digest, self.pin)
            .map_err(|e| anyhow::anyhow!("signing the blob failed; nothing was stored: {e:#}"))?;

        let mut trailer = Vec::with_capacity(SIG_TRAILER_LEN);
        trailer.push(SIG_V2);
        trailer.extend_from_slice(&raw_sig[0..64]); // r ‖ s
        Ok(Protected {
            stored,
            key_byte,
            trailer,
        })
    }

    fn open(&self, meta: &BlobMeta, stored: &[u8], _trailer: &[u8]) -> Result<Vec<u8>> {
        if !meta.is_encrypted() {
            return Ok(stored.to_vec());
        }
        let name = &meta.name;
        if self.pin.is_none() {
            bail!("blob '{name}' is encrypted but no PIN was provided");
        }
        crypto::hybrid_decrypt(
            self.piv,
            self.reader,
            meta.key_byte,
            stored,
            self.pin,
            self.debug,
        )
        .with_context(|| format!("decrypting blob '{name}'"))
    }

    fn quick_check(&self, head: &Object, store: &Store) -> SigVerdict {
        check_blob_signature(head, store, self.verifying_key)
    }
}
