// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
// SPDX-FileCopyrightText: 2025 - 2026 Thales Cloud Sécurisé
//
// SPDX-License-Identifier: MIT

//! Hybrid encryption/decryption (ECDH + HKDF + AES-256-GCM).
//!
//! ## Wire format (v2, GCM)
//!
//! ```text
//! 0x02                           (1 byte  — version tag)
//! ephemeral_pubkey               (65 bytes — X9.62 uncompressed P-256 point)
//! nonce                          (12 bytes — random, from OsRng)
//! GCM ciphertext + authentication tag  (plaintext_len + 16 bytes)
//! ```
//!
//! Total overhead: 1 + 65 + 12 + 16 = 94 bytes.
//!
//! ## Legacy wire format (v1, CBC — read-only)
//!
//! Old blobs written by earlier versions start with `0x04` (the X9.62
//! uncompressed-point byte) and have no version prefix:
//!
//! ```text
//! ephemeral_pubkey               (65 bytes — first byte is always 0x04)
//! IV                             (16 bytes)
//! AES-256-CBC+PKCS7 ciphertext   (padded to 16-byte blocks)
//! ```
//!
//! `hybrid_decrypt` detects the format by inspecting the first byte:
//! - `0x02` → GCM
//! - `0x04` → legacy CBC
//! - anything else → error
//!
//! Encryption always produces the GCM format.  No new CBC blobs are written.

use crate::piv::PivBackend;
use anyhow::{bail, Context, Result};
use hkdf::Hkdf;
use p256::{ecdh::EphemeralSecret, elliptic_curve::sec1::ToEncodedPoint, PublicKey};
use rand::rngs::OsRng;
use sha2::Sha256;

const HKDF_INFO: &[u8] = b"hybrid-encryption";

// GCM format constants
const VERSION_GCM: u8 = 0x02;
const VERSION_LEN: usize = 1;
const EPHEMERAL_PK_LEN: usize = 65;
const NONCE_LEN: usize = 12;
const GCM_TAG_LEN: usize = 16;
const GCM_HEADER_LEN: usize = VERSION_LEN + EPHEMERAL_PK_LEN + NONCE_LEN; // 78

/// Total overhead added by `hybrid_encrypt`: version(1) + EPK(65) + nonce(12) + GCM tag(16).
pub const GCM_OVERHEAD: usize = GCM_HEADER_LEN + GCM_TAG_LEN; // = 94

// Legacy CBC format constants (decryption only)
const LEGACY_VERSION: u8 = 0x04; // X9.62 uncompressed-point prefix byte
const IV_LEN: usize = 16;
const LEGACY_HEADER_LEN: usize = EPHEMERAL_PK_LEN + IV_LEN; // 81

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` to the YubiKey's public key using AES-256-GCM.
///
/// Returns `version(1) || ephemeral_pubkey(65) || nonce(12) || ciphertext+tag(N+16)`.
pub fn hybrid_encrypt(plaintext: &[u8], peer_public_key: &PublicKey) -> Result<Vec<u8>> {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };

    // 1. Ephemeral EC P-256 key pair.
    let ephemeral_secret = EphemeralSecret::random(&mut OsRng);
    let ephemeral_pubkey = p256::PublicKey::from(&ephemeral_secret);

    // 2. ECDH → shared secret.
    let shared_secret = ephemeral_secret.diffie_hellman(peer_public_key);

    // 3. HKDF-SHA256 → AES-256 key.
    let aes_key = hkdf_expand(shared_secret.raw_secret_bytes())?;

    // 4. Random 96-bit nonce.
    let nonce_bytes: [u8; NONCE_LEN] = rand::random();

    // 5. AES-256-GCM encrypt.  AAD is empty; the ephemeral public key is
    //    implicitly authenticated by ECDH — any tampering changes the shared
    //    secret and causes decryption to fail.
    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|e| anyhow::anyhow!("AES-GCM key init: {e}"))?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|e| anyhow::anyhow!("AES-GCM encrypt: {e}"))?;

    // 6. Serialise: 0x02 || epk || nonce || ciphertext+tag.
    let epk_bytes = ephemeral_pubkey.to_encoded_point(false).as_bytes().to_vec();

    let mut out = Vec::with_capacity(GCM_HEADER_LEN + ciphertext.len());
    out.push(VERSION_GCM);
    out.extend_from_slice(&epk_bytes);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a blob produced by `hybrid_encrypt` (GCM) or a legacy CBC blob.
///
/// `piv` and `reader` identify the backend and device; `slot` is the PIV slot
/// whose private key performs ECDH via GENERAL AUTHENTICATE.
pub fn hybrid_decrypt(
    piv: &dyn PivBackend,
    reader: &str,
    slot: u8,
    encrypted: &[u8],
    pin: Option<&str>,
    _debug: bool,
) -> Result<Vec<u8>> {
    if encrypted.is_empty() {
        bail!("encrypted blob is empty");
    }

    match encrypted[0] {
        VERSION_GCM => decrypt_gcm(piv, reader, slot, encrypted, pin),
        LEGACY_VERSION => decrypt_cbc_legacy(piv, reader, slot, encrypted, pin),
        v => bail!("encrypted blob has unknown version byte 0x{v:02x}"),
    }
}

// ---------------------------------------------------------------------------
// GCM decryption
// ---------------------------------------------------------------------------

fn decrypt_gcm(
    piv: &dyn PivBackend,
    reader: &str,
    slot: u8,
    encrypted: &[u8],
    pin: Option<&str>,
) -> Result<Vec<u8>> {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };

    if encrypted.len() < GCM_HEADER_LEN + GCM_TAG_LEN {
        bail!("GCM blob too short ({} bytes)", encrypted.len());
    }

    // Layout: [0x02][epk 65][nonce 12][ciphertext+tag]
    let epk_bytes = &encrypted[VERSION_LEN..VERSION_LEN + EPHEMERAL_PK_LEN];
    let nonce_bytes = &encrypted[VERSION_LEN + EPHEMERAL_PK_LEN..GCM_HEADER_LEN];
    let ciphertext = &encrypted[GCM_HEADER_LEN..];

    let shared_secret = piv
        .ecdh(reader, slot, epk_bytes, pin)
        .context("ECDH with YubiKey (GCM)")?;

    let aes_key = hkdf_expand(&shared_secret)?;

    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|e| anyhow::anyhow!("AES-GCM key init: {e}"))?;
    cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|_| {
            anyhow::anyhow!("AES-GCM authentication failed — blob may be corrupted or tampered")
        })
}

// ---------------------------------------------------------------------------
// Legacy CBC decryption (read-only, backward compatibility)
// ---------------------------------------------------------------------------

fn decrypt_cbc_legacy(
    piv: &dyn PivBackend,
    reader: &str,
    slot: u8,
    encrypted: &[u8],
    pin: Option<&str>,
) -> Result<Vec<u8>> {
    use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
    type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

    if encrypted.len() < LEGACY_HEADER_LEN {
        bail!("legacy CBC blob too short ({} bytes)", encrypted.len());
    }

    // Layout: [epk 65][iv 16][ciphertext] — no version byte
    let epk_bytes = &encrypted[..EPHEMERAL_PK_LEN];
    let iv: [u8; IV_LEN] = encrypted[EPHEMERAL_PK_LEN..LEGACY_HEADER_LEN]
        .try_into()
        .unwrap();
    let ciphertext = &encrypted[LEGACY_HEADER_LEN..];

    let shared_secret = piv
        .ecdh(reader, slot, epk_bytes, pin)
        .context("ECDH with YubiKey (legacy CBC)")?;

    let aes_key = hkdf_expand(&shared_secret)?;
    let dec = Aes256CbcDec::new(&aes_key.into(), &iv.into());
    dec.decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|e| anyhow::anyhow!("legacy CBC decrypt failed: {e}"))
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn hkdf_expand(ikm: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = [0u8; 32];
    hk.expand(HKDF_INFO, &mut okm)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
    Ok(okm)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::piv::PivBackend;
    use p256::ecdh::EphemeralSecret;
    use rand::rngs::OsRng;

    // Mock whose ecdh() returns a pre-set shared secret (T3 + CBC test).
    struct MockPiv {
        shared_secret: Vec<u8>,
    }
    impl PivBackend for MockPiv {
        fn list_readers(&self) -> Result<Vec<String>> {
            Ok(vec!["mock".to_owned()])
        }
        fn list_devices(&self) -> Result<Vec<crate::piv::DeviceInfo>> {
            Ok(vec![crate::piv::DeviceInfo {
                serial: 1,
                version: "5.4.3".to_owned(),
                reader: "mock".to_owned(),
            }])
        }
        fn read_object(&self, _r: &str, _id: u32) -> Result<Vec<u8>> {
            bail!("mock")
        }
        fn write_object(
            &self,
            _r: &str,
            _id: u32,
            _d: &[u8],
            _mk: Option<&str>,
            _pin: Option<&str>,
        ) -> Result<()> {
            bail!("mock")
        }
        fn verify_pin(&self, _r: &str, _pin: &str) -> Result<()> {
            bail!("mock")
        }
        fn send_apdu(&self, _r: &str, _apdu: &[u8]) -> Result<Vec<u8>> {
            bail!("mock")
        }
        fn ecdh(&self, _r: &str, _slot: u8, _peer: &[u8], _pin: Option<&str>) -> Result<Vec<u8>> {
            Ok(self.shared_secret.clone())
        }
        fn read_certificate(&self, _r: &str, _slot: u8) -> Result<Vec<u8>> {
            bail!("mock")
        }
        fn generate_key(&self, _r: &str, _slot: u8, _mk: Option<&str>) -> Result<Vec<u8>> {
            bail!("mock")
        }
        fn generate_certificate(
            &self,
            _r: &str,
            _slot: u8,
            _subj: &str,
            _mk: Option<&str>,
            _pin: Option<&str>,
        ) -> Result<Vec<u8>> {
            bail!("mock")
        }
        fn read_printed_object_with_pin(&self, _r: &str, _pin: &str) -> Result<Vec<u8>> {
            bail!("mock")
        }
    }

    // Mock whose ecdh() always errors (T4/T5 which never reach ECDH).
    struct EcdhErrMock;
    impl PivBackend for EcdhErrMock {
        fn list_readers(&self) -> Result<Vec<String>> {
            Ok(vec!["r".to_owned()])
        }
        fn list_devices(&self) -> Result<Vec<crate::piv::DeviceInfo>> {
            Ok(vec![crate::piv::DeviceInfo {
                serial: 1,
                version: "5.4.3".to_owned(),
                reader: "r".to_owned(),
            }])
        }
        fn read_object(&self, _r: &str, _id: u32) -> Result<Vec<u8>> {
            bail!("mock")
        }
        fn write_object(
            &self,
            _r: &str,
            _id: u32,
            _d: &[u8],
            _mk: Option<&str>,
            _pin: Option<&str>,
        ) -> Result<()> {
            bail!("mock")
        }
        fn verify_pin(&self, _r: &str, _pin: &str) -> Result<()> {
            bail!("mock")
        }
        fn send_apdu(&self, _r: &str, _apdu: &[u8]) -> Result<Vec<u8>> {
            bail!("mock")
        }
        fn ecdh(&self, _r: &str, _slot: u8, _peer: &[u8], _pin: Option<&str>) -> Result<Vec<u8>> {
            bail!("ecdh not available in mock")
        }
        fn read_certificate(&self, _r: &str, _slot: u8) -> Result<Vec<u8>> {
            bail!("mock")
        }
        fn generate_key(&self, _r: &str, _slot: u8, _mk: Option<&str>) -> Result<Vec<u8>> {
            bail!("mock")
        }
        fn generate_certificate(
            &self,
            _r: &str,
            _slot: u8,
            _subj: &str,
            _mk: Option<&str>,
            _pin: Option<&str>,
        ) -> Result<Vec<u8>> {
            bail!("mock")
        }
        fn read_printed_object_with_pin(&self, _r: &str, _pin: &str) -> Result<Vec<u8>> {
            bail!("mock")
        }
    }

    /// Round-trip encrypt/decrypt using the GCM format (no YubiKey).
    #[test]
    fn encrypt_decrypt_roundtrip() {
        let plaintext = b"hello from the test suite";

        let device_secret = EphemeralSecret::random(&mut OsRng);
        let device_pubkey = p256::PublicKey::from(&device_secret);

        let encrypted = hybrid_encrypt(plaintext, &device_pubkey).unwrap();

        // Check version byte.
        assert_eq!(encrypted[0], VERSION_GCM);
        assert!(encrypted.len() >= GCM_HEADER_LEN + GCM_TAG_LEN);

        // Decrypt manually (simulate YubiKey ECDH).
        let epk_bytes = &encrypted[VERSION_LEN..VERSION_LEN + EPHEMERAL_PK_LEN];
        let nonce_bytes = &encrypted[VERSION_LEN + EPHEMERAL_PK_LEN..GCM_HEADER_LEN];
        let ciphertext = &encrypted[GCM_HEADER_LEN..];

        let epk = PublicKey::from_sec1_bytes(epk_bytes).unwrap();
        let shared = device_secret.diffie_hellman(&epk);
        let aes_key = hkdf_expand(shared.raw_secret_bytes()).unwrap();

        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };
        let cipher = Aes256Gcm::new_from_slice(&aes_key).unwrap();
        let decrypted = cipher
            .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    /// Backward-compatibility: a hand-crafted legacy CBC blob must still decrypt.
    #[test]
    fn encrypt_decrypt_legacy_cbc() {
        use cbc::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
        type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

        let plaintext = b"legacy cbc blob";

        // Ephemeral sender key pair (simulates what the old encrypt did).
        let ephemeral_secret = EphemeralSecret::random(&mut OsRng);
        let ephemeral_pubkey = p256::PublicKey::from(&ephemeral_secret);

        // Device key pair — use a regular SecretKey so we can extract the
        // shared secret and hand it to the mock backend.
        use p256::SecretKey;
        let device_sk = SecretKey::random(&mut OsRng);
        let device_pk = device_sk.public_key();

        // Compute shared secret (ephemeral × device_pk) — same as what ECDH does.
        let shared = ephemeral_secret.diffie_hellman(&device_pk);
        let aes_key = hkdf_expand(shared.raw_secret_bytes()).unwrap();

        // Build legacy CBC blob: [epk 65][iv 16][ciphertext] — no version byte.
        let iv: [u8; IV_LEN] = rand::random();
        let enc = Aes256CbcEnc::new(&aes_key.into(), &iv.into());
        let ciphertext = enc.encrypt_padded_vec_mut::<Pkcs7>(plaintext);

        let epk_bytes = ephemeral_pubkey.to_encoded_point(false).as_bytes().to_vec();
        assert_eq!(epk_bytes[0], LEGACY_VERSION, "epk must start with 0x04");

        let mut legacy_blob = Vec::new();
        legacy_blob.extend_from_slice(&epk_bytes);
        legacy_blob.extend_from_slice(&iv);
        legacy_blob.extend_from_slice(&ciphertext);

        // Use the module-level MockPiv.
        let mock = MockPiv {
            shared_secret: shared.raw_secret_bytes().to_vec(),
        };

        // decrypt_cbc_legacy should recover the plaintext.
        let decrypted = decrypt_cbc_legacy(&mock, "mock", 0x9e, &legacy_blob, None).unwrap();
        assert_eq!(decrypted, plaintext);

        // hybrid_decrypt should also route to CBC via the 0x04 first byte.
        let decrypted2 = hybrid_decrypt(&mock, "mock", 0x9e, &legacy_blob, None, false).unwrap();
        assert_eq!(decrypted2, plaintext);
    }

    /// T3: flipping a byte in the GCM ciphertext fails authentication.
    #[test]
    fn tampered_ciphertext_fails_authentication() {
        let plaintext = b"sensitive data";

        let device_secret = EphemeralSecret::random(&mut OsRng);
        let device_pubkey = p256::PublicKey::from(&device_secret);

        let mut encrypted = hybrid_encrypt(plaintext, &device_pubkey).unwrap();

        // Flip a byte in the ciphertext region (after the GCM header).
        let tamper_offset = GCM_HEADER_LEN + 1;
        encrypted[tamper_offset] ^= 0xFF;

        // Build a mock that returns the correct shared secret so only the GCM
        // authentication check can fail.
        let epk_bytes = &encrypted[VERSION_LEN..VERSION_LEN + EPHEMERAL_PK_LEN];
        let epk = p256::PublicKey::from_sec1_bytes(epk_bytes).unwrap();
        let shared = device_secret.diffie_hellman(&epk);
        let secret_bytes = shared.raw_secret_bytes().to_vec();

        let mock = MockPiv {
            shared_secret: secret_bytes,
        };

        let result = hybrid_decrypt(&mock, "mock", 0x82, &encrypted, None, false);
        assert!(
            result.is_err(),
            "tampered ciphertext must fail authentication"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("authentication failed") || msg.contains("tampered"),
            "error message should mention authentication: {msg}"
        );
    }

    /// T4: unknown version byte (not 0x02 or 0x04) is rejected immediately.
    #[test]
    fn unknown_version_byte_rejected() {
        let mock = EcdhErrMock;
        let blob = vec![0x03u8, 0x00, 0x00]; // unknown version
        let result = hybrid_decrypt(&mock, "r", 0x82, &blob, None, false);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("unknown version byte"),
            "expected 'unknown version byte' in error: {msg}"
        );
    }

    /// T5: empty input is rejected before any field access.
    #[test]
    fn empty_blob_rejected() {
        let mock = EcdhErrMock;
        let result = hybrid_decrypt(&mock, "r", 0x82, &[], None, false);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("empty"),
            "expected 'empty' in error message: {msg}"
        );
    }
}
