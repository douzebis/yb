// SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Tier-1 unit tests for `VirtualPiv` and the orchestrator functions.
//!
//! All tests run without hardware — `VirtualPiv` provides an in-memory PIV
//! backend with real P-256 cryptography.  Key material used here is
//! **disposable test material** and must never protect real data.

use std::path::Path;
use std::sync::Arc;
use yb_core::{
    orchestrator::{fetch_blob, list_blobs, remove_blob, store_blob},
    piv::PivBackend,
    store::Store,
    Context, VirtualPiv,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn default_piv() -> VirtualPiv {
    VirtualPiv::from_fixture(&fixture("default.yaml")).unwrap()
}

fn with_key_piv() -> VirtualPiv {
    VirtualPiv::from_fixture(&fixture("with_key.yaml")).unwrap()
}

// ---------------------------------------------------------------------------
// VirtualPiv basic operations
// ---------------------------------------------------------------------------

/// list_readers and list_devices return the virtual device.
#[test]
fn test_list_devices() {
    let piv = default_piv();
    let readers = piv.list_readers().unwrap();
    assert_eq!(readers, vec!["Virtual YubiKey 00 00"]);

    let devices = piv.list_devices().unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].serial, 99_999_999);
    assert_eq!(devices[0].version, "5.4.3");
}

/// read_object returns an error for an unknown object.
#[test]
fn test_read_object_missing() {
    let piv = default_piv();
    let reader = piv.reader_name();
    let result = piv.read_object(&reader, 0x5F_C105);
    assert!(result.is_err());
}

/// write_object with direct management key, then read_object round-trips.
#[test]
fn test_write_read_object() {
    let piv = default_piv();
    let reader = piv.reader_name();
    let mgmt = "010203040506070801020304050607080102030405060708";
    let data = b"hello world";

    piv.write_object(&reader, 0x5F_C105, data, Some(mgmt), None)
        .unwrap();

    let result = piv.read_object(&reader, 0x5F_C105).unwrap();
    assert_eq!(result, data);
}

/// write_object with wrong management key is rejected.
#[test]
fn test_write_wrong_mgmt_key() {
    let piv = default_piv();
    let reader = piv.reader_name();
    let result = piv.write_object(&reader, 0x5F_C105, b"x", Some("aabbccdd"), None);
    assert!(result.is_err());
}

/// verify_pin succeeds with correct PIN, fails with wrong PIN.
#[test]
fn test_verify_pin() {
    let piv = default_piv();
    let reader = piv.reader_name();
    assert!(piv.verify_pin(&reader, "123456").is_ok());
    assert!(piv.verify_pin(&reader, "wrong").is_err());
}

/// PIN retry counter decrements and blocks at zero.
#[test]
fn test_pin_retry_and_block() {
    let piv = default_piv();
    let reader = piv.reader_name();

    // 3 wrong attempts exhaust retries.
    for _ in 0..3 {
        let _ = piv.verify_pin(&reader, "badpin");
    }
    // Now blocked.
    let err = piv.verify_pin(&reader, "123456").unwrap_err();
    assert!(
        err.to_string().contains("blocked"),
        "expected blocked: {err}"
    );
}

/// PIN retry counter resets after a successful verify.
#[test]
fn test_pin_retry_resets_on_success() {
    let piv = default_piv();
    let reader = piv.reader_name();

    let _ = piv.verify_pin(&reader, "badpin");
    let _ = piv.verify_pin(&reader, "badpin");
    // Correct PIN resets the counter.
    piv.verify_pin(&reader, "123456").unwrap();
    // Two more wrong attempts should still work (counter reset to 3).
    let _ = piv.verify_pin(&reader, "badpin");
    let _ = piv.verify_pin(&reader, "badpin");
    assert!(piv.verify_pin(&reader, "123456").is_ok());
}

/// generate_key requires management key auth and returns a 65-byte point.
#[test]
fn test_generate_key() {
    let piv = default_piv();
    let reader = piv.reader_name();
    let mgmt = "010203040506070801020304050607080102030405060708";
    let point = piv.generate_key(&reader, 0x82, Some(mgmt)).unwrap();
    assert_eq!(point.len(), 65);
    assert_eq!(point[0], 0x04, "should be uncompressed point");
}

/// generate_key without management key auth is rejected.
#[test]
fn test_generate_key_no_auth() {
    let piv = default_piv();
    let reader = piv.reader_name();
    assert!(piv.generate_key(&reader, 0x82, None).is_err());
}

/// ECDH with a generated key produces a 32-byte shared secret.
#[test]
fn test_ecdh() {
    let piv = with_key_piv();
    let reader = piv.reader_name();

    // Generate an ephemeral P-256 key pair in software for the "sender".
    use p256::{ecdh::EphemeralSecret, elliptic_curve::sec1::ToEncodedPoint, PublicKey};
    use rand::rngs::OsRng;
    let ephemeral = EphemeralSecret::random(&mut OsRng);
    let epk: PublicKey = (&ephemeral).into();
    let epk_bytes = epk.to_encoded_point(false).as_bytes().to_vec();

    let secret = piv.ecdh(&reader, 0x82, &epk_bytes, Some("123456")).unwrap();
    assert_eq!(secret.len(), 32);
}

/// read_certificate returns an error when no cert is stored.
#[test]
fn test_read_certificate_missing() {
    let piv = default_piv();
    let reader = piv.reader_name();
    assert!(piv.read_certificate(&reader, 0x82).is_err());
}

/// generate_certificate stores a cert that can be read back.
#[test]
fn test_generate_certificate() {
    let piv = default_piv();
    let reader = piv.reader_name();
    let mgmt = "010203040506070801020304050607080102030405060708";

    let cert_der = piv
        .generate_certificate(&reader, 0x82, "CN=Test", Some(mgmt), None)
        .unwrap();
    assert!(!cert_der.is_empty());

    let read_back = piv.read_certificate(&reader, 0x82).unwrap();
    assert_eq!(cert_der, read_back);
}

/// Unknown reader name is rejected for all operations.
#[test]
fn test_wrong_reader() {
    let piv = default_piv();
    assert!(piv.read_object("no-such-reader", 0x5F_C105).is_err());
    assert!(piv.verify_pin("no-such-reader", "123456").is_err());
}

// ---------------------------------------------------------------------------
// Fixture loading
// ---------------------------------------------------------------------------

/// from_fixture loads the with_key fixture and the slot key is usable.
#[test]
fn test_fixture_with_key_loaded() {
    let piv = with_key_piv();
    let devices = piv.list_devices().unwrap();
    assert_eq!(devices[0].serial, 88_888_888);
    assert_eq!(devices[0].reader, "Virtual YubiKey 00 01");

    // The pre-loaded slot 0x82 should be available for ECDH.
    use p256::{ecdh::EphemeralSecret, elliptic_curve::sec1::ToEncodedPoint, PublicKey};
    use rand::rngs::OsRng;
    let eph = EphemeralSecret::random(&mut OsRng);
    let epk: PublicKey = (&eph).into();
    let epk_bytes = epk.to_encoded_point(false).as_bytes().to_vec();
    let reader = piv.reader_name();
    let secret = piv.ecdh(&reader, 0x82, &epk_bytes, None).unwrap();
    assert_eq!(secret.len(), 32);
}

// ---------------------------------------------------------------------------
// Store + orchestrator integration
// ---------------------------------------------------------------------------

fn formatted_store(piv: &VirtualPiv) -> Store {
    let reader = piv.reader_name();
    let mgmt = "010203040506070801020304050607080102030405060708";
    Store::format(&reader, piv, 8, 512, 0x82, Some(mgmt), None).unwrap()
}

/// store_blob + list_blobs + fetch_blob round-trip (unencrypted).
#[test]
fn test_store_list_fetch_plain() {
    let piv = with_key_piv();
    let mgmt = "010203040506070801020304050607080102030405060708";
    let mut store = formatted_store(&piv);

    let payload = b"hello yb store";
    store_blob(
        &mut store,
        &piv,
        "greeting",
        payload,
        false,
        None,
        Some(mgmt),
        None,
    )
    .unwrap();

    let blobs = list_blobs(&store);
    assert_eq!(blobs.len(), 1);
    assert_eq!(blobs[0].name, "greeting");
    assert!(!blobs[0].is_encrypted);

    let reader = piv.reader_name();
    let fetched = fetch_blob(&store, &piv, &reader, "greeting", None, false)
        .unwrap()
        .unwrap();
    assert_eq!(fetched, payload);
}

/// store_blob + fetch_blob round-trip (encrypted via ECDH).
#[test]
fn test_store_fetch_encrypted() {
    let piv = with_key_piv();
    let reader = piv.reader_name();
    let mgmt = "010203040506070801020304050607080102030405060708";
    let mut store = formatted_store(&piv);

    // Get the public key for slot 0x82 from the device info.
    // We need a p256::PublicKey; use generate_key to place one, then reconstruct it.
    let point = piv.generate_key(&reader, 0x82, Some(mgmt)).unwrap();
    let pub_key = p256::PublicKey::from_sec1_bytes(&point).unwrap();

    let payload = b"secret message";
    store_blob(
        &mut store,
        &piv,
        "secret",
        payload,
        true,
        Some(&pub_key),
        Some(mgmt),
        None,
    )
    .unwrap();

    let blobs = list_blobs(&store);
    assert_eq!(blobs[0].is_encrypted, true);

    let reader = piv.reader_name();
    let fetched = fetch_blob(&store, &piv, &reader, "secret", Some("123456"), false)
        .unwrap()
        .unwrap();
    assert_eq!(fetched, payload);
}

/// remove_blob removes the blob and it no longer appears in list_blobs.
#[test]
fn test_remove_blob() {
    let piv = with_key_piv();
    let mgmt = "010203040506070801020304050607080102030405060708";
    let mut store = formatted_store(&piv);

    store_blob(
        &mut store,
        &piv,
        "to-delete",
        b"bye",
        false,
        None,
        Some(mgmt),
        None,
    )
    .unwrap();
    assert_eq!(list_blobs(&store).len(), 1);

    let removed = remove_blob(&mut store, &piv, "to-delete", Some(mgmt), None).unwrap();
    assert!(removed);
    assert_eq!(list_blobs(&store).len(), 0);
}

/// Context::with_backend works with VirtualPiv.
#[test]
fn test_context_with_backend() {
    let piv = Arc::new(with_key_piv());
    let ctx = Context::with_backend(piv, Some("123456".to_owned()), false).unwrap();
    assert_eq!(ctx.serial, 88_888_888);
    assert_eq!(ctx.pin.as_deref(), Some("123456"));
}

/// remove_blob returns false for a blob that does not exist.
#[test]
fn test_remove_nonexistent() {
    let piv = with_key_piv();
    let mgmt = "010203040506070801020304050607080102030405060708";
    let mut store = formatted_store(&piv);

    let removed = remove_blob(&mut store, &piv, "ghost", Some(mgmt), None).unwrap();
    assert!(!removed);
}
