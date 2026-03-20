// SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Hybrid encryption/decryption (ECDH + HKDF + AES-256-CBC).
//!
//! Encryption is fully in-process (RustCrypto).
//! Decryption delegates the YubiKey ECDH step to pkcs11-tool subprocess,
//! then completes HKDF + AES in Rust.  This matches the Phase 1 plan
//! (Phase 2 will replace pkcs11-tool with the cryptoki crate).

use anyhow::{bail, Context, Result};
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hkdf::Hkdf;
use p256::{
    ecdh::EphemeralSecret, elliptic_curve::sec1::ToEncodedPoint, pkcs8::EncodePublicKey, PublicKey,
};
use rand::rngs::OsRng;
use sha2::Sha256;
use std::io::Write as _;
use std::process::{Command, Stdio};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

const HKDF_INFO: &[u8] = b"hybrid-encryption";
const EPHEMERAL_PK_LEN: usize = 65; // X9.62 uncompressed P-256 point
const IV_LEN: usize = 16;

// ---------------------------------------------------------------------------
// Slot ID mapping (PIV slot byte → PKCS#11 object ID)
// Mirrors the table in Python's crypto.py perform_ecdh_with_yubikey().
// ---------------------------------------------------------------------------
fn slot_to_pkcs11_id(slot: u8) -> Result<&'static str> {
    match slot {
        0x9a => Ok("01"),
        0x9c => Ok("03"),
        0x9d => Ok("04"),
        0x9e => Ok("04"),
        0x82 => Ok("05"),
        0x83 => Ok("06"),
        0x84 => Ok("07"),
        0x85 => Ok("08"),
        0x86 => Ok("09"),
        0x87 => Ok("0a"),
        0x88 => Ok("0b"),
        0x89 => Ok("0c"),
        0x8a => Ok("0d"),
        0x8b => Ok("0e"),
        0x8c => Ok("0f"),
        0x8d => Ok("10"),
        0x8e => Ok("11"),
        0x8f => Ok("12"),
        0x90 => Ok("13"),
        0x91 => Ok("14"),
        0x92 => Ok("15"),
        0x93 => Ok("16"),
        0x94 => Ok("17"),
        0x95 => Ok("18"),
        _ => bail!("unsupported PIV slot 0x{slot:02x}"),
    }
}

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
/// `serial` and `slot` identify the YubiKey and the PIV slot whose private
/// key will perform ECDH (via pkcs11-tool subprocess).
pub fn hybrid_decrypt(
    serial: u32,
    slot: u8,
    encrypted: &[u8],
    pin: Option<&str>,
    debug: bool,
) -> Result<Vec<u8>> {
    if encrypted.len() < EPHEMERAL_PK_LEN + IV_LEN {
        bail!("encrypted blob too short");
    }

    let epk_bytes = &encrypted[..EPHEMERAL_PK_LEN];
    let iv: [u8; IV_LEN] = encrypted[EPHEMERAL_PK_LEN..EPHEMERAL_PK_LEN + IV_LEN]
        .try_into()
        .unwrap();
    let ciphertext = &encrypted[EPHEMERAL_PK_LEN + IV_LEN..];

    // Reconstruct ephemeral public key and encode as SPKI DER for pkcs11-tool.
    let epk = PublicKey::from_sec1_bytes(epk_bytes).context("parsing ephemeral public key")?;
    let spki_der = epk
        .to_public_key_der()
        .context("encoding ephemeral key as SPKI DER")?;

    // Perform ECDH on the YubiKey.
    let shared_secret = perform_ecdh_with_yubikey(serial, slot, spki_der.as_bytes(), pin, debug)
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

/// Shell out to pkcs11-tool to perform ECDH on the YubiKey.
/// Returns the raw shared secret bytes.
fn perform_ecdh_with_yubikey(
    serial: u32,
    slot: u8,
    spki_der: &[u8],
    pin: Option<&str>,
    debug: bool,
) -> Result<Vec<u8>> {
    let pkcs11_id = slot_to_pkcs11_id(slot)?;
    let token_label = format!("YubiKey PIV #{serial}");

    // Write the SPKI DER to a temp file (pkcs11-tool reads from file).
    let mut epk_file = tempfile::NamedTempFile::new().context("creating temp file for EPK")?;
    epk_file
        .write_all(spki_der)
        .context("writing EPK to temp file")?;

    let out_file = tempfile::NamedTempFile::new().context("creating temp file for output")?;

    // Resolve PKCS#11 module path from environment (set in shell.nix).
    let module =
        std::env::var("PKCS11_MODULE_PATH").unwrap_or_else(|_| "/usr/lib/libykcs11.so".to_owned());

    let mut args = vec![
        "--module".to_owned(),
        module,
        "--token-label".to_owned(),
        token_label,
        "-l".to_owned(),
        "--derive".to_owned(),
        "-m".to_owned(),
        "ECDH1-DERIVE".to_owned(),
        "--id".to_owned(),
        pkcs11_id.to_owned(),
        "-i".to_owned(),
        epk_file.path().to_str().unwrap().to_owned(),
        "-o".to_owned(),
        out_file.path().to_str().unwrap().to_owned(),
    ];

    if let Some(p) = pin {
        args.extend(["--pin".to_owned(), p.to_owned()]);
    }

    if debug {
        eprintln!("[debug] pkcs11-tool {}", args.join(" "));
    }

    let out = Command::new("pkcs11-tool")
        .args(&args)
        .stdin(Stdio::null())
        .output()
        .context("running pkcs11-tool")?;

    if !out.status.success() {
        bail!(
            "pkcs11-tool failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    std::fs::read(out_file.path()).context("reading pkcs11-tool output")
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

    #[test]
    fn slot_mapping_known_values() {
        assert_eq!(slot_to_pkcs11_id(0x82).unwrap(), "05");
        assert_eq!(slot_to_pkcs11_id(0x9e).unwrap(), "04");
        assert!(slot_to_pkcs11_id(0x00).is_err());
    }
}
