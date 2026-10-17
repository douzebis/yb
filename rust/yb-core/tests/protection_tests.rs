// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Spec 0028 — the `Protection` trait: blobs are protected before any
//! write, so a refused protection (PIN, touch) writes nothing; and the
//! legacy protection round-trips through the `*_with` entry points.

use anyhow::{bail, Result};
use std::path::Path;
use yb_core::orchestrator::{
    fetch_blob_with, store_blob_with, BlobMeta, LegacyProtection, Protected, Protection, SigVerdict,
};
use yb_core::piv::{Fault, PivBackend, VirtualPiv};
use yb_core::store::{Object, Store};
use yb_core::{
    fetch_blob, parse_ec_public_key_from_cert_der, store_blob, Compression, Encryption,
    StoreOptions,
};

const MGMT: &str = "010203040506070801020304050607080102030405060708";
/// PIN of the `with_key.yaml` fixture.
const PIN: &str = "654321";

fn new_piv() -> VirtualPiv {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/with_key.yaml");
    VirtualPiv::from_fixture(&fixture).unwrap()
}

fn plain() -> StoreOptions<'static> {
    StoreOptions {
        encryption: Encryption::None,
        compression: Compression::None,
    }
}

/// A protection that refuses, as a wrong PIN or a missed touch would.
struct Refusing;

impl Protection for Refusing {
    fn overhead(&self, _encrypt: bool) -> (usize, usize) {
        (0, 65)
    }
    fn protect(&self, _: &str, _: &[u8], _: bool, _: bool, _: u32, _: u32) -> Result<Protected> {
        bail!("refused")
    }
    fn open(&self, _: &BlobMeta, _: &[u8], _: &[u8]) -> Result<Vec<u8>> {
        unreachable!("not used by store_blob_with")
    }
    fn quick_check(&self, _: &Object, _: &Store) -> SigVerdict {
        unreachable!("not used by store_blob_with")
    }
}

/// A refused protection writes nothing, not even the cleanup of an earlier
/// interrupted write (spec 0028, "Writing"; invariant 0004).
#[test]
fn refused_protection_writes_nothing() {
    let piv = new_piv();
    let reader = piv.reader_name();
    let mut store = Store::format(&reader, &piv, 16, 0x82, MGMT).unwrap();
    assert!(store_blob(&mut store, &piv, "kept", &[0xAA; 100], plain(), MGMT, None).unwrap());

    // Interrupt a multi-chunk store at its second write: its first chunk
    // stays on the card as a leftover, which the next write cleans up.
    piv.inject_fault(Fault::WriteFails(2));
    let interrupted = store_blob(&mut store, &piv, "big", &[0xBB; 8000], plain(), MGMT, None);
    assert!(interrupted.is_err());
    piv.clear_faults();

    let mut store = Store::from_device(&reader, &piv).unwrap();
    let writes = piv.write_count();
    let refused = store_blob_with(
        &mut store,
        &piv,
        &Refusing,
        "new",
        &[0xCC; 100],
        false,
        Compression::None,
        MGMT,
    );
    assert!(refused.is_err());
    assert_eq!(piv.write_count(), writes, "a refused protection wrote");

    let store = Store::from_device(&reader, &piv).unwrap();
    let kept = fetch_blob(&store, &piv, &reader, "kept", None, false).unwrap();
    assert_eq!(kept.as_deref(), Some(&[0xAA; 100][..]));
    assert!(store.find_head("new").is_none());
}

/// The legacy protection stores, checks and opens an encrypted blob.
#[test]
fn legacy_protection_round_trip() {
    let piv = new_piv();
    let reader = piv.reader_name();
    let mut store = Store::format(&reader, &piv, 16, 0x82, MGMT).unwrap();
    let cert = piv
        .generate_certificate(&reader, 0x82, "CN=Test", MGMT, None)
        .unwrap();
    let public_key = parse_ec_public_key_from_cert_der(&cert).unwrap();
    let verifying_key = p256::ecdsa::VerifyingKey::from(&public_key);
    let protection = LegacyProtection {
        piv: &piv,
        reader: &reader,
        slot: 0x82,
        encryption_key: Some(&public_key),
        verifying_key: Some(&verifying_key),
        pin: Some(PIN),
        debug: false,
    };
    let data = b"secret".repeat(500);
    assert!(store_blob_with(
        &mut store,
        &piv,
        &protection,
        "vault",
        &data,
        true,
        Compression::Auto,
        MGMT,
    )
    .unwrap());

    let store = Store::from_device(&reader, &piv).unwrap();
    let head = store.find_head("vault").unwrap();
    assert!(head.is_encrypted());
    assert_eq!(protection.quick_check(head, &store), SigVerdict::Verified);
    let fetched = fetch_blob_with(&store, &protection, "vault").unwrap();
    assert_eq!(fetched.as_deref(), Some(&data[..]));
}
