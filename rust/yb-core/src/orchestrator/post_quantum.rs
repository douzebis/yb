// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! The protection of post-quantum stores (spec 0028): every key comes from
//! the YubiKey's FIDO2 `hmac-secret`, K2, computed on the card with the
//! FIDO2 PIN and a touch; no asymmetric cryptography (D3).
//!
//! Per blob, one assertion with two salts gives the blob's K2 and the
//! management key's K2.  The management key is unwrapped and checked
//! against the card before anything else (D11), then the blob is encrypted
//! (AES-256-GCM, its tag is the seal) or sealed (HMAC-SHA256), and its
//! checksum (SHA-256, for the checks without PIN) goes in the trailer (D5,
//! D6).  Formats: spec 0028, "Blob bytes and trailer".

use super::protection::{BlobMeta, Protected, Protection};
use super::signature::{collect_blob_chain, SigVerdict};
use crate::fido2::{self, SALT_LEN};
use crate::piv::{MgmtAlgo, PivBackend};
use crate::store::descriptor::{Descriptor, MGMT_NONCE_LEN};
use crate::store::{Object, Store};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{bail, Context, Result};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// The version byte of encrypted payloads and of trailers.
pub const PQ_VERSION: u8 = 0x03;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// What encryption adds to a payload: version, nonce, GCM tag.
pub const PQ_ENCRYPTION_OVERHEAD: usize = 1 + NONCE_LEN + TAG_LEN;
/// Trailer: version, salt, checksum; and the seal of an unencrypted blob.
pub const PQ_TRAILER_LEN_ENCRYPTED: usize = 1 + SALT_LEN + 32;
pub const PQ_TRAILER_LEN_PLAIN: usize = PQ_TRAILER_LEN_ENCRYPTED + 32;
/// `BLOB_FLAGS` bit 0: the blob is encrypted.
pub const FLAG_ENCRYPTED: u8 = 0x01;

const LABEL_CHECKSUM: &[u8] = b"yb-pq-v1 checksum\0";
const LABEL_BLOB_AD: &[u8] = b"yb-pq-v1 blob\0";
const LABEL_ENCRYPTION: &[u8] = b"yb-pq-v1 blob encryption";
const LABEL_SEAL: &[u8] = b"yb-pq-v1 blob seal";
const LABEL_MANAGEMENT_KEY: &[u8] = b"yb-pq-v1 management key";

/// A failed integrity check of a post-quantum store (spec 0028, D5, D6,
/// D11): `yb` exits with status 4.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IntegrityError {
    #[error("blob '{0}' is corrupted: its checksum does not match")]
    Corrupted(String),
    #[error(
        "blob '{0}' was not written by yb with this YubiKey: its seal does not verify \
         (it may have been tampered with)"
    )]
    SealFailed(String),
    #[error(
        "the PIV management key does not match: the PIV application may have been reset, \
         and the store may have been tampered with.  If you changed the key yourself, run \
         `yb management-key set`"
    )]
    ManagementKeyMismatch,
}

/// HKDF-SHA256 of `ikm` with no salt, `info` = `label`, 32 bytes.
fn derive(ikm: &[u8], label: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut okm = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, ikm)
        .expand(label, okm.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 length");
    okm
}

/// `META` of spec 0028: what the checksum and the seal bind to the bytes.
fn meta_bytes(meta: &BlobMeta, salt: &[u8; SALT_LEN]) -> Vec<u8> {
    let name = meta.name.as_bytes();
    let mut m = Vec::with_capacity(1 + name.len() + 14 + SALT_LEN);
    m.push(name.len() as u8);
    m.extend_from_slice(name);
    m.push(meta.key_byte);
    m.push(u8::from(meta.compressed));
    m.extend_from_slice(&meta.plain_size.to_le_bytes());
    m.extend_from_slice(&meta.stored_size.to_le_bytes());
    m.extend_from_slice(&meta.mtime.to_le_bytes());
    m.extend_from_slice(salt);
    m
}

fn checksum(meta: &[u8], stored: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(LABEL_CHECKSUM);
    h.update(meta);
    h.update(stored);
    h.finalize().into()
}

fn seal(k2: &[u8], checksum: &[u8; 32]) -> [u8; 32] {
    let key = derive(k2, LABEL_SEAL);
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key.as_ref()).expect("any key length");
    mac.update(checksum);
    mac.finalize().into_bytes().into()
}

/// A parsed post-quantum trailer.
struct Trailer {
    salt: [u8; SALT_LEN],
    checksum: [u8; 32],
    seal: Option<[u8; 32]>,
}

fn parse_trailer(trailer: &[u8], encrypted: bool) -> Option<Trailer> {
    let expected = if encrypted {
        PQ_TRAILER_LEN_ENCRYPTED
    } else {
        PQ_TRAILER_LEN_PLAIN
    };
    if trailer.len() != expected || trailer[0] != PQ_VERSION {
        return None;
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&trailer[1..1 + SALT_LEN]);
    let mut checksum = [0u8; 32];
    checksum.copy_from_slice(&trailer[1 + SALT_LEN..1 + SALT_LEN + 32]);
    let seal = (!encrypted).then(|| {
        let mut s = [0u8; 32];
        s.copy_from_slice(&trailer[PQ_TRAILER_LEN_ENCRYPTED..]);
        s
    });
    Some(Trailer {
        salt,
        checksum,
        seal,
    })
}

/// Wrap `key` (the management key) with the management key's K2: returns
/// the nonce and the wrapped key followed by its tag (spec 0028, "Store
/// descriptor").  `ad` is the descriptor's bytes before the nonce.
pub fn wrap_management_key(
    k2: &[u8],
    ad: &[u8],
    key: &[u8],
) -> Result<([u8; MGMT_NONCE_LEN], Vec<u8>)> {
    let kek = derive(k2, LABEL_MANAGEMENT_KEY);
    let nonce: [u8; MGMT_NONCE_LEN] = rand::random();
    let wrapped = Aes256Gcm::new_from_slice(kek.as_ref())
        .expect("32-byte key")
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: key, aad: ad })
        .map_err(|_| anyhow::anyhow!("wrapping the management key failed"))?;
    Ok((nonce, wrapped))
}

/// Unwrap the descriptor's management key with its K2, as hex.  A failure
/// means a K2 from another credential or a damaged descriptor.
pub fn unwrap_management_key(descriptor: &Descriptor, k2: &[u8]) -> Result<Zeroizing<String>> {
    let kek = derive(k2, LABEL_MANAGEMENT_KEY);
    let key = Zeroizing::new(
        Aes256Gcm::new_from_slice(kek.as_ref())
            .expect("32-byte key")
            .decrypt(
                Nonce::from_slice(&descriptor.mgmt_nonce),
                Payload {
                    msg: &descriptor.mgmt_wrapped,
                    aad: &descriptor.wrap_ad(),
                },
            )
            .map_err(|_| IntegrityError::ManagementKeyMismatch)?,
    );
    Ok(Zeroizing::new(hex::encode(key.as_slice())))
}

/// The protection of a post-quantum store, for one command: the open FIDO2
/// device, the FIDO2 PIN, and what to do before each touch.
pub struct PostQuantumProtection<'a> {
    pub piv: &'a dyn PivBackend,
    pub reader: &'a str,
    pub descriptor: &'a Descriptor,
    pub fido2: &'a fido2::Device,
    pub pin: &'a str,
    /// Called before each assertion (the "Touch your YubiKey" message).
    pub on_touch: &'a dyn Fn(),
}

impl PostQuantumProtection<'_> {
    /// One assertion (one touch): the K2 of `salt` and the management key,
    /// checked against the card (D11).
    fn assert(&self, salt: &[u8; SALT_LEN]) -> Result<(Zeroizing<[u8; 32]>, Zeroizing<String>)> {
        (self.on_touch)();
        let mut outputs = self.fido2.hmac_secret(
            &self.descriptor.credential_id,
            &[*salt, self.descriptor.mgmt_salt],
            self.pin,
        )?;
        let k2_mgmt = outputs.pop().expect("two outputs");
        let k2 = outputs.pop().expect("two outputs");
        let management_key = self.checked_management_key(k2_mgmt.as_ref())?;
        Ok((k2, management_key))
    }

    /// The management key unwrapped with `k2_mgmt`, after the card accepts
    /// it: else the PIV application was reset or the key changed (D11).
    fn checked_management_key(&self, k2_mgmt: &[u8]) -> Result<Zeroizing<String>> {
        let key = unwrap_management_key(self.descriptor, k2_mgmt)?;
        self.piv
            .authenticate_management_key(self.reader, &key)
            .map_err(|_| IntegrityError::ManagementKeyMismatch)?;
        Ok(key)
    }

    /// The management key alone (`yb rm`, `yb fsck`): one assertion, one
    /// touch, checked against the card.
    pub fn management_key(&self) -> Result<Zeroizing<String>> {
        (self.on_touch)();
        let outputs = self.fido2.hmac_secret(
            &self.descriptor.credential_id,
            &[self.descriptor.mgmt_salt],
            self.pin,
        )?;
        self.checked_management_key(outputs[0].as_ref())
    }
}

impl Protection for PostQuantumProtection<'_> {
    fn overhead(&self, encrypt: bool) -> (usize, usize) {
        if encrypt {
            (PQ_ENCRYPTION_OVERHEAD, PQ_TRAILER_LEN_ENCRYPTED)
        } else {
            (0, PQ_TRAILER_LEN_PLAIN)
        }
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
        let salt: [u8; SALT_LEN] = rand::random();
        let (k2, management_key) = self.assert(&salt)?;
        let key_byte = if encrypt { FLAG_ENCRYPTED } else { 0 };
        let stored_size = if encrypt {
            payload.len() + PQ_ENCRYPTION_OVERHEAD
        } else {
            payload.len()
        };
        let meta = BlobMeta {
            name: name.to_owned(),
            key_byte,
            compressed,
            plain_size,
            stored_size: stored_size as u32,
            mtime,
        };
        let meta = meta_bytes(&meta, &salt);

        let stored = if encrypt {
            let key = derive(k2.as_ref(), LABEL_ENCRYPTION);
            let nonce: [u8; NONCE_LEN] = rand::random();
            let mut ad = LABEL_BLOB_AD.to_vec();
            ad.extend_from_slice(&meta);
            let ciphertext = Aes256Gcm::new_from_slice(key.as_ref())
                .expect("32-byte key")
                .encrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: payload,
                        aad: &ad,
                    },
                )
                .map_err(|_| anyhow::anyhow!("encrypting blob '{name}' failed"))?;
            let mut stored = Vec::with_capacity(stored_size);
            stored.push(PQ_VERSION);
            stored.extend_from_slice(&nonce);
            stored.extend_from_slice(&ciphertext);
            stored
        } else {
            payload.to_vec()
        };
        debug_assert_eq!(stored.len(), stored_size);

        let sum = checksum(&meta, &stored);
        let mut trailer = Vec::with_capacity(PQ_TRAILER_LEN_PLAIN);
        trailer.push(PQ_VERSION);
        trailer.extend_from_slice(&salt);
        trailer.extend_from_slice(&sum);
        if !encrypt {
            trailer.extend_from_slice(&seal(k2.as_ref(), &sum));
        }
        Ok(Protected {
            stored,
            key_byte,
            trailer,
            management_key: Some(management_key),
        })
    }

    fn open(&self, meta: &BlobMeta, stored: &[u8], trailer: &[u8]) -> Result<Vec<u8>> {
        let name = &meta.name;
        let encrypted = meta.key_byte & FLAG_ENCRYPTED != 0;
        // 1. The checksum, without the card (corruption).
        let Some(t) = parse_trailer(trailer, encrypted) else {
            return Err(IntegrityError::Corrupted(name.clone()).into());
        };
        let meta_b = meta_bytes(meta, &t.salt);
        if checksum(&meta_b, stored).ct_eq(&t.checksum).unwrap_u8() != 1 {
            return Err(IntegrityError::Corrupted(name.clone()).into());
        }
        // 2. The management key, then the seal (PIN, touch).
        let (k2, _management_key) = self.assert(&t.salt)?;
        if !encrypted {
            let expected = seal(k2.as_ref(), &t.checksum);
            let ok = t.seal.is_some_and(|s| expected.ct_eq(&s).unwrap_u8() == 1);
            if !ok {
                return Err(IntegrityError::SealFailed(name.clone()).into());
            }
            return Ok(stored.to_vec());
        }
        if stored.len() < PQ_ENCRYPTION_OVERHEAD || stored[0] != PQ_VERSION {
            return Err(IntegrityError::SealFailed(name.clone()).into());
        }
        let key = derive(k2.as_ref(), LABEL_ENCRYPTION);
        let mut ad = LABEL_BLOB_AD.to_vec();
        ad.extend_from_slice(&meta_b);
        Aes256Gcm::new_from_slice(key.as_ref())
            .expect("32-byte key")
            .decrypt(
                Nonce::from_slice(&stored[1..1 + NONCE_LEN]),
                Payload {
                    msg: &stored[1 + NONCE_LEN..],
                    aad: &ad,
                },
            )
            .map_err(|_| IntegrityError::SealFailed(name.clone()).into())
    }

    fn quick_check(&self, head: &Object, store: &Store) -> SigVerdict {
        quick_check(head, store)
    }
}

/// The checksum of a post-quantum blob (spec 0028, D5).  Public: anyone
/// can compute it, which is why it is not a proof of authorship (the seal
/// is).
pub fn blob_checksum(meta: &BlobMeta, salt: &[u8; SALT_LEN], stored: &[u8]) -> [u8; 32] {
    checksum(&meta_bytes(meta, salt), stored)
}

/// The check without PIN of a post-quantum blob: its checksum (D5).
pub fn quick_check(head: &Object, store: &Store) -> SigVerdict {
    let meta = BlobMeta::from_head(head);
    let (stored, trailer, _) = collect_blob_chain(head, store);
    if stored.len() != meta.stored_size as usize {
        return SigVerdict::Corrupted;
    }
    let encrypted = meta.key_byte & FLAG_ENCRYPTED != 0;
    match parse_trailer(&trailer, encrypted) {
        Some(t) if checksum(&meta_bytes(&meta, &t.salt), &stored) == t.checksum => {
            SigVerdict::ChecksumOk
        }
        _ => SigVerdict::Corrupted,
    }
}

/// Wrap a new management key into the store's descriptor (`yb
/// management-key set`, spec 0028, D7): one assertion (one touch) for the
/// management key's K2, a fresh nonce, the card's current algorithm; the
/// descriptor is rewritten with the new key, which the card must accept.
/// Returns the new descriptor.
#[allow(clippy::too_many_arguments)]
pub fn rewrap_management_key(
    piv: &dyn PivBackend,
    reader: &str,
    descriptor: &Descriptor,
    fido2: &fido2::Device,
    pin: &str,
    new_key: &str,
    algo: MgmtAlgo,
    on_touch: &dyn Fn(),
) -> Result<Descriptor> {
    piv.authenticate_management_key(reader, new_key)
        .context("the YubiKey rejects this management key")?;
    let key_bytes = Zeroizing::new(hex::decode(new_key).context("management key hex")?);
    if key_bytes.len() != algo.key_len() {
        bail!("the management key does not fit its algorithm");
    }
    on_touch();
    let k2 = fido2.hmac_secret(&descriptor.credential_id, &[descriptor.mgmt_salt], pin)?;
    let mut updated = descriptor.clone();
    updated.mgmt_algo = algo;
    let (nonce, wrapped) = wrap_management_key(k2[0].as_ref(), &updated.wrap_ad(), &key_bytes)?;
    updated.mgmt_nonce = nonce;
    updated.mgmt_wrapped = wrapped;
    piv.write_object(
        reader,
        crate::store::constants::OBJECT_ID_ZERO,
        &updated.to_bytes(),
        new_key,
    )
    .context("writing the store descriptor")?;
    Ok(updated)
}

/// Create a post-quantum store's credential and descriptor, then format
/// it (spec 0028, D13): the credential (one touch), the management key
/// wrapped by its K2 (one touch), then `Store::format_post_quantum`, which
/// writes the descriptor last.  `management_key` must be the card's
/// current key (hex), checked against the card first.
#[allow(clippy::too_many_arguments)]
pub fn create_post_quantum_store(
    piv: &dyn PivBackend,
    reader: &str,
    fido2: &fido2::Device,
    pin: &str,
    management_key: &str,
    mgmt_algo: MgmtAlgo,
    object_count: u8,
    on_touch: &dyn Fn(),
) -> Result<Store> {
    piv.authenticate_management_key(reader, management_key)
        .context("the management key is not the card's")?;
    let key_bytes = Zeroizing::new(hex::decode(management_key).context("management key hex")?);
    if key_bytes.len() != mgmt_algo.key_len() {
        bail!("the management key does not fit its algorithm");
    }
    on_touch();
    let credential = fido2.make_credential(pin)?;
    let mut descriptor = Descriptor {
        object_count,
        mgmt_algo,
        credential_id: credential.id,
        mgmt_salt: rand::random(),
        mgmt_nonce: [0; MGMT_NONCE_LEN],
        mgmt_wrapped: Vec::new(),
    };
    on_touch();
    let k2 = fido2.hmac_secret(&descriptor.credential_id, &[descriptor.mgmt_salt], pin)?;
    let (nonce, wrapped) = wrap_management_key(k2[0].as_ref(), &descriptor.wrap_ad(), &key_bytes)?;
    descriptor.mgmt_nonce = nonce;
    descriptor.mgmt_wrapped = wrapped;
    Store::format_post_quantum(reader, piv, descriptor, management_key)
}
