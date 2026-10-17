// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Spec 0028 — the post-quantum store layer: descriptor in `0x5F_0000`,
//! chunks from `0x5F_0001` with the new magic, format writing the
//! descriptor last, and older yb's parser refusing every object.

use anyhow::Result;
use std::path::Path;
use yb_core::orchestrator::{
    fetch_blob_with, store_blob_with, BlobMeta, Protected, Protection, SigVerdict,
};
use yb_core::piv::{Fault, MgmtAlgo, PivBackend, VirtualPiv};
use yb_core::store::constants::{OBJECT_ID_ZERO, PQ_MAGIC};
use yb_core::store::{Descriptor, Object, Store, StoreKind};
use yb_core::{fetch_blob, store_blob, Compression, Encryption, StoreOptions};

const MGMT: &str = "010203040506070801020304050607080102030405060708";

fn new_piv() -> VirtualPiv {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/with_key.yaml");
    VirtualPiv::from_fixture(&fixture).unwrap()
}

fn descriptor(object_count: u8) -> Descriptor {
    Descriptor {
        object_count,
        mgmt_algo: MgmtAlgo::Aes192,
        credential_id: vec![0x5a; 64],
        mgmt_salt: [0x11; 32],
        mgmt_nonce: [0x22; 12],
        mgmt_wrapped: vec![0x33; 24 + 16],
    }
}

/// Stores the payload as is, with a 4-byte trailer: the chunk machinery
/// alone (the post-quantum protection is tested elsewhere).
struct Plain;

impl Protection for Plain {
    fn overhead(&self, _encrypt: bool) -> (usize, usize) {
        (0, 4)
    }
    fn protect(
        &self,
        _: &str,
        payload: &[u8],
        _: bool,
        _: bool,
        _: u32,
        _: u32,
    ) -> Result<Protected> {
        Ok(Protected {
            stored: payload.to_vec(),
            key_byte: 0,
            trailer: b"test".to_vec(),
            management_key: None,
        })
    }
    fn open(&self, _: &BlobMeta, stored: &[u8], trailer: &[u8]) -> Result<Vec<u8>> {
        assert_eq!(trailer, b"test");
        Ok(stored.to_vec())
    }
    fn quick_check(&self, _: &Object, _: &Store) -> SigVerdict {
        SigVerdict::Verified
    }
}

fn plain_options() -> StoreOptions<'static> {
    StoreOptions {
        encryption: Encryption::None,
        compression: Compression::None,
    }
}

#[test]
fn format_writes_descriptor_and_chunks() {
    let piv = new_piv();
    let reader = piv.reader_name();
    let desc = descriptor(8);
    Store::format_post_quantum(&reader, &piv, desc.clone(), MGMT).unwrap();

    let raw0 = piv.read_object(&reader, OBJECT_ID_ZERO).unwrap();
    assert_eq!(Descriptor::from_bytes(&raw0).unwrap(), desc);
    for i in 1..=8u32 {
        let raw = piv.read_object(&reader, OBJECT_ID_ZERO + i).unwrap();
        assert_eq!(u32::from_le_bytes(raw[..4].try_into().unwrap()), PQ_MAGIC);
    }
    assert!(piv.read_object(&reader, OBJECT_ID_ZERO + 9).is_err());

    let store = Store::from_device(&reader, &piv).unwrap();
    assert_eq!(store.kind, StoreKind::PostQuantum(Box::new(desc)));
    assert_eq!(store.free_count(), 8);
    assert_eq!(store.object_id(0), OBJECT_ID_ZERO + 1);
}

#[test]
fn format_deletes_yb_leftovers_only() {
    let piv = new_piv();
    let reader = piv.reader_name();
    // A legacy store of 32 objects, with a blob, and a foreign object.
    let mut legacy = Store::format(&reader, &piv, 32, 0x82, MGMT).unwrap();
    assert!(store_blob(
        &mut legacy,
        &piv,
        "old",
        &[7; 9000],
        plain_options(),
        MGMT,
        None
    )
    .unwrap());
    piv.write_object(&reader, OBJECT_ID_ZERO + 20, b"not yb", MGMT)
        .unwrap();

    Store::format_post_quantum(&reader, &piv, descriptor(8), MGMT).unwrap();

    for i in 9..=32u32 {
        let present = piv.read_object(&reader, OBJECT_ID_ZERO + i);
        if i == 20 {
            assert_eq!(present.unwrap(), b"not yb", "a foreign object was touched");
        } else {
            assert!(
                present.is_err(),
                "object 0x{:06x} was left behind",
                OBJECT_ID_ZERO + i
            );
        }
    }
}

#[test]
fn chunks_store_and_fetch() {
    let piv = new_piv();
    let reader = piv.reader_name();
    let mut store = Store::format_post_quantum(&reader, &piv, descriptor(8), MGMT).unwrap();
    let data: Vec<u8> = (0..9000u32).map(|i| i as u8).collect();
    assert!(store_blob_with(
        &mut store,
        &piv,
        &Plain,
        "big",
        &data,
        false,
        Compression::None,
        Some(MGMT)
    )
    .unwrap());

    let raw0 = piv.read_object(&reader, OBJECT_ID_ZERO).unwrap();
    assert!(
        Descriptor::from_bytes(&raw0).is_ok(),
        "the descriptor was overwritten"
    );
    let store = Store::from_device(&reader, &piv).unwrap();
    assert!(store.find_head("big").unwrap().chunk_pos() == 0);
    let fetched = fetch_blob_with(&store, &Plain, "big").unwrap();
    assert_eq!(fetched.as_deref(), Some(&data[..]));
}

/// Invariant 0014 (seed): older yb's parser, which only knows the legacy
/// magic, refuses every object of a post-quantum store.
#[test]
fn legacy_parser_refuses_every_object() {
    let piv = new_piv();
    let reader = piv.reader_name();
    let mut store = Store::format_post_quantum(&reader, &piv, descriptor(4), MGMT).unwrap();
    store_blob_with(
        &mut store,
        &piv,
        &Plain,
        "b",
        &[1; 5000],
        false,
        Compression::None,
        Some(MGMT),
    )
    .unwrap();
    for i in 0..=4u32 {
        let raw = piv.read_object(&reader, OBJECT_ID_ZERO + i).unwrap();
        assert!(
            Object::from_bytes(i as u8, &raw).is_err(),
            "object {i} parsed as legacy"
        );
    }
}

/// Invariant 0016: a format interrupted at any write never leaves a
/// post-quantum store; whatever store is still readable is the old one,
/// intact (nothing was written yet); a new format succeeds.
#[test]
fn interrupted_format_leaves_no_store() {
    for n in 1..=64 {
        let piv = new_piv();
        let reader = piv.reader_name();
        let mut legacy = Store::format(&reader, &piv, 16, 0x82, MGMT).unwrap();
        store_blob(
            &mut legacy,
            &piv,
            "old",
            &[7; 4000],
            plain_options(),
            MGMT,
            None,
        )
        .unwrap();

        piv.inject_fault(Fault::WriteFails(n));
        let result = Store::format_post_quantum(&reader, &piv, descriptor(8), MGMT);
        piv.clear_faults();

        if result.is_ok() {
            assert!(Store::from_device(&reader, &piv)
                .unwrap()
                .kind
                .is_post_quantum());
            return;
        }
        match Store::from_device(&reader, &piv) {
            Err(_) => {}
            Ok(store) => {
                assert_eq!(
                    store.kind,
                    StoreKind::Legacy,
                    "write {n}: a half-made store"
                );
                let old = fetch_blob(&store, &piv, &reader, "old", None, false).unwrap();
                assert_eq!(old.as_deref(), Some(&[7u8; 4000][..]), "write {n}");
            }
        }
        Store::format_post_quantum(&reader, &piv, descriptor(8), MGMT).unwrap();
        assert!(Store::from_device(&reader, &piv)
            .unwrap()
            .kind
            .is_post_quantum());
    }
    panic!("format did not complete within 64 writes");
}
