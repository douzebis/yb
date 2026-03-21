// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
// SPDX-FileCopyrightText: 2025 - 2026 Thales Cloud Sécurisé
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
    orchestrator::{
        fetch_blob, list_blobs, remove_blob, store_blob, Compression, Encryption, StoreOptions,
    },
    piv::PivBackend,
    store::Store,
    test_utils::{OpType, OperationGenerator, ToyFilesystem},
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
        StoreOptions {
            encryption: Encryption::None,
            compression: Compression::None,
        },
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
        StoreOptions {
            encryption: Encryption::Encrypted(&pub_key),
            compression: Compression::None,
        },
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
        StoreOptions {
            encryption: Encryption::None,
            compression: Compression::None,
        },
        Some(mgmt),
        None,
    )
    .unwrap();
    assert_eq!(list_blobs(&store).len(), 1);

    let removed = remove_blob(&mut store, &piv, "to-delete", Some(mgmt), None).unwrap();
    assert!(removed);
    assert_eq!(list_blobs(&store).len(), 0);
}

// ---------------------------------------------------------------------------
// Compression path coverage
// ---------------------------------------------------------------------------

/// Brotli wins: short English prose — brotli's static dictionary compresses
/// this far better than xz.
/// Fixture: "The quick brown fox jumps over the lazy dog. " × 5 (225 bytes).
/// Measured: brotli=62  xz=116  → brotli wins.
#[test]
fn test_compression_brotli_path() {
    let piv = with_key_piv();
    let mgmt = "010203040506070801020304050607080102030405060708";
    let mut store = formatted_store(&piv);
    let reader = piv.reader_name();

    let payload: Vec<u8> = b"The quick brown fox jumps over the lazy dog. "
        .repeat(5)
        .to_vec();

    store_blob(
        &mut store,
        &piv,
        "brotli-blob",
        &payload,
        StoreOptions {
            encryption: Encryption::None,
            compression: Compression::Auto,
        },
        Some(mgmt),
        None,
    )
    .unwrap();

    let head = store.find_head("brotli-blob").unwrap();
    assert!(head.is_compressed, "expected C-bit set");
    // Stored bytes must start with brotli magic YBr\x01.
    assert!(
        head.payload.starts_with(b"\x59\x42\x72\x01"),
        "expected brotli magic"
    );

    let fetched = fetch_blob(&store, &piv, &reader, "brotli-blob", None, false)
        .unwrap()
        .unwrap();
    assert_eq!(fetched, payload);
}

/// XZ wins: sequential little-endian u32 integers — LZMA2's delta model
/// compresses structured binary better than brotli.
/// Fixture: 0u32..250 as LE bytes (1000 bytes).
/// Measured: brotli=327  xz=292  → xz wins.
#[test]
fn test_compression_xz_path() {
    let piv = with_key_piv();
    let mgmt = "010203040506070801020304050607080102030405060708";
    let mut store = formatted_store(&piv);
    let reader = piv.reader_name();

    let payload: Vec<u8> = (0u32..250).flat_map(|i| i.to_le_bytes()).collect();

    store_blob(
        &mut store,
        &piv,
        "xz-blob",
        &payload,
        StoreOptions {
            encryption: Encryption::None,
            compression: Compression::Auto,
        },
        Some(mgmt),
        None,
    )
    .unwrap();

    let head = store.find_head("xz-blob").unwrap();
    assert!(head.is_compressed, "expected C-bit set");
    // Stored bytes must start with xz magic \xfd7zXZ\x00.
    assert!(
        head.payload.starts_with(b"\xfd7zXZ\x00"),
        "expected xz magic"
    );

    let fetched = fetch_blob(&store, &piv, &reader, "xz-blob", None, false)
        .unwrap()
        .unwrap();
    assert_eq!(fetched, payload);
}

/// Raw path (C=0): short string — both compressors expand it due to header
/// overhead, so the payload is stored uncompressed.
/// Fixture: b"hello world" (11 bytes).
/// Measured: brotli=19  xz=68  → neither helps, raw wins.
#[test]
fn test_compression_raw_path() {
    let piv = with_key_piv();
    let mgmt = "010203040506070801020304050607080102030405060708";
    let mut store = formatted_store(&piv);
    let reader = piv.reader_name();

    let payload = b"hello world";

    store_blob(
        &mut store,
        &piv,
        "raw-blob",
        payload,
        StoreOptions {
            encryption: Encryption::None,
            compression: Compression::Auto,
        },
        Some(mgmt),
        None,
    )
    .unwrap();

    let head = store.find_head("raw-blob").unwrap();
    assert!(!head.is_compressed, "expected C-bit clear");

    let fetched = fetch_blob(&store, &piv, &reader, "raw-blob", None, false)
        .unwrap()
        .unwrap();
    assert_eq!(fetched, payload);
}

/// Context::with_backend works with VirtualPiv.
#[test]
fn test_context_with_backend() {
    let piv = Arc::new(with_key_piv());
    let ctx = Context::with_backend(piv, Some("123456".to_owned()), false).unwrap();
    assert_eq!(ctx.serial, 88_888_888);
    assert_eq!(ctx.require_pin().unwrap().as_deref(), Some("123456"));
}

/// T8: from_device with a mismatched object count — first object claims N
/// objects but fewer are actually present → error instead of panic.
#[test]
fn test_from_device_missing_objects() {
    use yb_core::store::constants::OBJECT_ID_ZERO;

    let piv = default_piv();
    let mgmt = "010203040506070801020304050607080102030405060708";
    let reader = piv.reader_name();

    // Write only object 0, which claims object_count = 5.  Objects 1–4 are
    // never written, so reading them returns an error.
    use yb_core::store::constants::{MAGIC_O, OBJECT_COUNT_O, STORE_KEY_SLOT_O};
    let mut buf = vec![0u8; 512];
    // Magic (little-endian)
    let magic: u32 = 0xF2ED5F0B;
    buf[MAGIC_O..MAGIC_O + 4].copy_from_slice(&magic.to_le_bytes());
    buf[OBJECT_COUNT_O] = 5; // claims 5 objects
    buf[STORE_KEY_SLOT_O] = 0x82;
    // age = 0 (empty slot)
    piv.write_object(&reader, OBJECT_ID_ZERO, &buf, Some(mgmt), None)
        .unwrap();

    use yb_core::store::Store;
    let result = Store::from_device(&reader, &piv);
    assert!(
        result.is_err(),
        "from_device must error when claimed objects are missing"
    );
}

/// T11: Context::with_backend errors when the backend exposes multiple devices.
#[test]
fn test_with_backend_multiple_devices_errors() {
    use std::sync::Arc;
    use yb_core::piv::{DeviceInfo, PivBackend};

    struct TwoDevicePiv;
    impl PivBackend for TwoDevicePiv {
        fn list_readers(&self) -> anyhow::Result<Vec<String>> {
            Ok(vec!["r0".to_owned(), "r1".to_owned()])
        }
        fn list_devices(&self) -> anyhow::Result<Vec<DeviceInfo>> {
            Ok(vec![
                DeviceInfo {
                    serial: 1,
                    version: "5.4.3".to_owned(),
                    reader: "r0".to_owned(),
                },
                DeviceInfo {
                    serial: 2,
                    version: "5.4.3".to_owned(),
                    reader: "r1".to_owned(),
                },
            ])
        }
        fn read_object(&self, _r: &str, _id: u32) -> anyhow::Result<Vec<u8>> {
            anyhow::bail!("stub")
        }
        fn write_object(
            &self,
            _r: &str,
            _id: u32,
            _d: &[u8],
            _mk: Option<&str>,
            _pin: Option<&str>,
        ) -> anyhow::Result<()> {
            anyhow::bail!("stub")
        }
        fn verify_pin(&self, _r: &str, _pin: &str) -> anyhow::Result<()> {
            anyhow::bail!("stub")
        }
        fn send_apdu(&self, _r: &str, _apdu: &[u8]) -> anyhow::Result<Vec<u8>> {
            anyhow::bail!("stub")
        }
        fn ecdh(
            &self,
            _r: &str,
            _slot: u8,
            _peer: &[u8],
            _pin: Option<&str>,
        ) -> anyhow::Result<Vec<u8>> {
            anyhow::bail!("stub")
        }
        fn read_certificate(&self, _r: &str, _slot: u8) -> anyhow::Result<Vec<u8>> {
            anyhow::bail!("stub")
        }
        fn generate_key(&self, _r: &str, _slot: u8, _mk: Option<&str>) -> anyhow::Result<Vec<u8>> {
            anyhow::bail!("stub")
        }
        fn generate_certificate(
            &self,
            _r: &str,
            _slot: u8,
            _subj: &str,
            _mk: Option<&str>,
            _pin: Option<&str>,
        ) -> anyhow::Result<Vec<u8>> {
            anyhow::bail!("stub")
        }
        fn read_printed_object_with_pin(&self, _r: &str, _pin: &str) -> anyhow::Result<Vec<u8>> {
            anyhow::bail!("stub")
        }
    }

    let result = Context::with_backend(Arc::new(TwoDevicePiv), None, false);
    let err = result
        .err()
        .expect("with_backend must error when backend has multiple devices");
    let msg = err.to_string();
    assert!(
        msg.contains("multiple devices"),
        "error must mention 'multiple devices': {msg}"
    );
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

/// T15: Seeded random store/fetch/remove/list operations against VirtualPiv.
/// Verifies every fetch/remove/list result against ToyFilesystem ground truth.
#[test]
fn test_random_operations() {
    let piv = with_key_piv();
    let mgmt = "010203040506070801020304050607080102030405060708";
    let mut store = formatted_store(&piv);

    let mut toy = ToyFilesystem::new();
    let mut gen = OperationGenerator::new(42, 7);
    let ops = gen.generate(300, 0.0);

    let reader = piv.reader_name();

    for op in &ops {
        match op.op_type {
            OpType::Store => {
                let ok = store_blob(
                    &mut store,
                    &piv,
                    &op.name,
                    &op.payload,
                    StoreOptions {
                        encryption: Encryption::None,
                        compression: Compression::None,
                    },
                    Some(mgmt),
                    None,
                )
                .unwrap();
                if ok {
                    toy.store(&op.name, op.payload.clone(), 0);
                }
            }
            OpType::Fetch => {
                let result = fetch_blob(&store, &piv, &reader, &op.name, None, false).unwrap();
                let expected = toy.fetch(&op.name).map(|(p, _)| p.as_slice());
                assert_eq!(result.as_deref(), expected, "fetch '{}' mismatch", op.name);
            }
            OpType::Remove => {
                let removed = remove_blob(&mut store, &piv, &op.name, Some(mgmt), None).unwrap();
                let expected = toy.remove(&op.name);
                assert_eq!(
                    removed, expected,
                    "remove '{}' return value mismatch",
                    op.name
                );
            }
            OpType::List => {
                let blobs: Vec<String> = list_blobs(&store).into_iter().map(|b| b.name).collect();
                assert_eq!(blobs, toy.list(), "list mismatch");
            }
        }
    }
}
