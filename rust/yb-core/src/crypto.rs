// SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Hybrid encryption/decryption (ECDH + HKDF + AES-256-CBC).
//!
//! Encryption is fully in-process (RustCrypto).
//! Decryption delegates the YubiKey ECDH step to the PIV backend via
//! GENERAL AUTHENTICATE, then completes HKDF + AES in Rust.

use crate::piv::PivBackend;
use anyhow::{bail, Context, Result};
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hkdf::Hkdf;
use p256::{ecdh::EphemeralSecret, elliptic_curve::sec1::ToEncodedPoint, PublicKey};
use rand::rngs::OsRng;
use sha2::Sha256;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

const HKDF_INFO: &[u8] = b"hybrid-encryption";
const EPHEMERAL_PK_LEN: usize = 65; // X9.62 uncompressed P-256 point
const IV_LEN: usize = 16;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` to the YubiKey's public key.
///
/// Returns `ephemeral_pubkey(65) || IV(16) || ciphertext`.
pub fn hybrid_encrypt(plaintext: &[u8], peer_public_key: &PublicKey) -> Result<Vec<u8>> {
    // 1. Ephemeral EC P-256 key pair.
    let ephemeral_secret = EphemeralSecret::random(&mut OsRng);
    let ephemeral_pubkey = p256::PublicKey::from(&ephemeral_secret);

    // 2. ECDH → shared secret.
    let shared_secret = ephemeral_secret.diffie_hellman(peer_public_key);

    // 3. HKDF-SHA256 → AES-256 key.
    let aes_key = hkdf_expand(shared_secret.raw_secret_bytes())?;

    // 4. AES-256-CBC encrypt with random IV.
    let iv: [u8; IV_LEN] = rand::random();
    let ciphertext = aes256_cbc_encrypt(&aes_key, &iv, plaintext)?;

    // 5. Serialise: ephemeral_pubkey || IV || ciphertext.
    let epk_bytes = ephemeral_pubkey
        .to_encoded_point(false) // uncompressed = 65 bytes
        .as_bytes()
        .to_vec();

    let mut out = Vec::with_capacity(EPHEMERAL_PK_LEN + IV_LEN + ciphertext.len());
    out.extend_from_slice(&epk_bytes);
    out.extend_from_slice(&iv);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a blob produced by `hybrid_encrypt`.
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
    if encrypted.len() < EPHEMERAL_PK_LEN + IV_LEN {
        bail!("encrypted blob too short");
    }

    let epk_bytes = &encrypted[..EPHEMERAL_PK_LEN];
    let iv: [u8; IV_LEN] = encrypted[EPHEMERAL_PK_LEN..EPHEMERAL_PK_LEN + IV_LEN]
        .try_into()
        .unwrap();
    let ciphertext = &encrypted[EPHEMERAL_PK_LEN + IV_LEN..];

    // ECDH on the YubiKey: pass the ephemeral public key as an uncompressed point.
    let shared_secret = piv
        .ecdh(reader, slot, epk_bytes, pin)
        .context("ECDH with YubiKey")?;

    // HKDF → AES key, then decrypt.
    let aes_key = hkdf_expand(&shared_secret)?;
    aes256_cbc_decrypt(&aes_key, &iv, ciphertext)
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

fn aes256_cbc_encrypt(key: &[u8; 32], iv: &[u8; IV_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    let enc = Aes256CbcEnc::new(key.into(), iv.into());
    Ok(enc.encrypt_padded_vec_mut::<Pkcs7>(plaintext))
}

fn aes256_cbc_decrypt(key: &[u8; 32], iv: &[u8; IV_LEN], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let dec = Aes256CbcDec::new(key.into(), iv.into());
    dec.decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|e| anyhow::anyhow!("AES decrypt failed: {e}"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdh::EphemeralSecret;
    use rand::rngs::OsRng;

    /// Round-trip encrypt/decrypt using a locally-generated key pair (no YubiKey).
    #[test]
    fn encrypt_decrypt_roundtrip() {
        let plaintext = b"hello from the test suite";

        // Generate a "device" key pair in software.
        let device_secret = EphemeralSecret::random(&mut OsRng);
        let device_pubkey = p256::PublicKey::from(&device_secret);

        // Encrypt.
        let encrypted = hybrid_encrypt(plaintext, &device_pubkey).unwrap();
        assert!(encrypted.len() > EPHEMERAL_PK_LEN + IV_LEN);

        // Decrypt manually (simulating what the YubiKey does).
        let epk_bytes = &encrypted[..EPHEMERAL_PK_LEN];
        let iv: [u8; IV_LEN] = encrypted[EPHEMERAL_PK_LEN..EPHEMERAL_PK_LEN + IV_LEN]
            .try_into()
            .unwrap();
        let ciphertext = &encrypted[EPHEMERAL_PK_LEN + IV_LEN..];

        let epk = PublicKey::from_sec1_bytes(epk_bytes).unwrap();
        // Simulate YubiKey ECDH: device_secret × ephemeral_pubkey.
        let shared = device_secret.diffie_hellman(&epk);
        let aes_key = hkdf_expand(shared.raw_secret_bytes()).unwrap();
        let decrypted = aes256_cbc_decrypt(&aes_key, &iv, ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
