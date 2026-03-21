// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
// SPDX-FileCopyrightText: 2025 - 2026 Thales Cloud Sécurisé
//
// SPDX-License-Identifier: MIT

use super::constants::*;
use super::{write_u24_le, write_u32_le, Object, Store};

// ---------------------------------------------------------------------------
// Object helpers
// ---------------------------------------------------------------------------

fn make_empty_object(object_size: usize) -> Vec<u8> {
    let mut buf = vec![0u8; object_size];
    write_u32_le(&mut buf, MAGIC_O, YBLOB_MAGIC);
    buf[OBJECT_COUNT_O] = 12;
    buf[STORE_KEY_SLOT_O] = 0x82;
    // age = 0 (already zero)
    buf
}

#[test]
fn round_trip_empty() {
    let raw = make_empty_object(512);
    let obj = Object::from_bytes(0, &raw).unwrap();
    assert!(obj.is_empty());
    assert_eq!(obj.to_bytes(), raw);
}

#[test]
fn round_trip_head() {
    let object_size = 512;
    let name = "hello";
    let payload_data = b"world!";

    let obj = Object {
        index: 0,
        object_size,
        yblob_magic: YBLOB_MAGIC,
        object_count: 12,
        store_key_slot: 0x82,
        age: 1,
        chunk_pos: 0,
        next_chunk: 0, // self-referential = last chunk
        blob_mtime: 1_700_000_000,
        blob_size: payload_data.len() as u32,
        blob_key_slot: 0,
        blob_plain_size: payload_data.len() as u32,
        blob_name: name.to_owned(),
        payload: payload_data.to_vec(),
        dirty: false,
    };

    let bytes = obj.to_bytes();
    assert_eq!(bytes.len(), object_size);

    let obj2 = Object::from_bytes(0, &bytes).unwrap();
    assert_eq!(obj2.blob_name, name);
    assert_eq!(obj2.age, 1);
    assert_eq!(obj2.chunk_pos, 0);
    assert_eq!(obj2.blob_mtime, 1_700_000_000);
    assert_eq!(&obj2.payload[..payload_data.len()], payload_data);
}

#[test]
fn round_trip_continuation() {
    let object_size = 512;
    let payload_data = vec![0xABu8; 100];

    let obj = Object {
        index: 1,
        object_size,
        yblob_magic: YBLOB_MAGIC,
        object_count: 12,
        store_key_slot: 0x82,
        age: 2,
        chunk_pos: 1,
        next_chunk: 1, // self-referential = last chunk
        blob_mtime: 0,
        blob_size: 0,
        blob_key_slot: 0,
        blob_plain_size: 0,
        blob_name: String::new(),
        payload: payload_data.clone(),
        dirty: false,
    };

    let bytes = obj.to_bytes();
    let obj2 = Object::from_bytes(1, &bytes).unwrap();
    assert_eq!(obj2.chunk_pos, 1);
    assert_eq!(&obj2.payload[..payload_data.len()], &payload_data);
}

/// Binary compatibility test: a vector produced by the Python implementation.
/// python: store 7-byte blob "config" age=1 slot=0x82 mtime=1_717_243_342 unencrypted
#[test]
fn python_compat_vector() {
    // Constructed from Python constants and known field values.
    let mut raw = vec![0u8; 512];
    write_u32_le(&mut raw, MAGIC_O, YBLOB_MAGIC);
    raw[OBJECT_COUNT_O] = 12;
    raw[STORE_KEY_SLOT_O] = 0x82;
    write_u24_le(&mut raw, OBJECT_AGE_O, 1);
    raw[CHUNK_POS_O] = 0;
    raw[NEXT_CHUNK_O] = 0;
    write_u32_le(&mut raw, BLOB_MTIME_O, 1_717_243_342);
    write_u24_le(&mut raw, BLOB_SIZE_O, 7);
    raw[BLOB_KEY_SLOT_O] = 0;
    write_u24_le(&mut raw, BLOB_PLAIN_SIZE_O, 7);
    raw[BLOB_NAME_LEN_O] = 6;
    raw[BLOB_NAME_O..BLOB_NAME_O + 6].copy_from_slice(b"config");
    raw[BLOB_NAME_O + 6..BLOB_NAME_O + 13].copy_from_slice(b"content");

    let obj = Object::from_bytes(0, &raw).unwrap();
    assert_eq!(obj.blob_name, "config");
    assert_eq!(obj.blob_size, 7);
    assert_eq!(obj.blob_mtime, 1_717_243_342);
    assert_eq!(obj.blob_key_slot, 0);
    assert_eq!(&obj.payload[..7], b"content");

    // Re-serialize must be identical.
    assert_eq!(obj.to_bytes(), raw);
}

// ---------------------------------------------------------------------------
// T1 — sanitize
// ---------------------------------------------------------------------------

fn make_store_in_memory(object_count: u8, object_size: usize) -> Store {
    let objects = (0..object_count)
        .map(|i| Object {
            index: i,
            object_size,
            yblob_magic: YBLOB_MAGIC,
            object_count,
            store_key_slot: 0x82,
            age: 0,
            chunk_pos: 0,
            next_chunk: 0,
            blob_mtime: 0,
            blob_size: 0,
            blob_key_slot: 0,
            blob_plain_size: 0,
            blob_name: String::new(),
            payload: Vec::new(),
            dirty: false,
        })
        .collect();
    Store {
        reader: "mock".to_owned(),
        object_size,
        object_count,
        store_key_slot: 0x82,
        objects,
        store_age: 0,
    }
}

fn make_head(store: &mut Store, idx: u8, name: &str, age: u32, next: u8) {
    let obj = &mut store.objects[idx as usize];
    obj.age = age;
    obj.chunk_pos = 0;
    obj.next_chunk = next;
    obj.blob_name = name.to_owned();
    obj.blob_size = 1;
    obj.blob_plain_size = 1;
    obj.payload = vec![0];
    store.store_age = store.store_age.max(age);
}

fn make_continuation(store: &mut Store, idx: u8, age: u32, next: u8) {
    let obj = &mut store.objects[idx as usize];
    obj.age = age;
    obj.chunk_pos = 1;
    obj.next_chunk = next;
    obj.payload = vec![0];
    store.store_age = store.store_age.max(age);
}

/// T1a: duplicate-named heads — sanitize keeps the newer one.
#[test]
fn sanitize_keeps_newer_duplicate() {
    let mut store = make_store_in_memory(4, 512);
    // Two heads both named "foo": older at idx=0 (age=1), newer at idx=1 (age=2).
    make_head(&mut store, 0, "foo", 1, 0); // self-referential = single-chunk
    make_head(&mut store, 1, "foo", 2, 1);

    store.sanitize();

    // The older one (idx=0) must be reset; the newer (idx=1) must survive.
    assert!(
        store.objects[0].is_empty(),
        "older duplicate should be reset"
    );
    assert!(store.objects[1].is_head(), "newer duplicate should survive");
}

/// T1b: orphaned continuation chunk — sanitize resets it.
#[test]
fn sanitize_resets_orphaned_continuation() {
    let mut store = make_store_in_memory(4, 512);
    // idx=0 is a valid single-chunk blob "bar".
    make_head(&mut store, 0, "bar", 1, 0);
    // idx=1 is a continuation with no reachable head.
    make_continuation(&mut store, 1, 2, 1);

    store.sanitize();

    assert!(store.objects[0].is_head(), "good head should survive");
    assert!(
        store.objects[1].is_empty(),
        "orphaned continuation should be reset"
    );
}

/// T1c: clean store — sanitize is a no-op (no objects become dirty).
#[test]
fn sanitize_noop_on_clean_store() {
    let mut store = make_store_in_memory(4, 512);
    // One head with a continuation.
    make_head(&mut store, 0, "x", 1, 1);
    // next == self → last chunk
    make_continuation(&mut store, 1, 2, 1);
    // Clear dirty flags (make_head/make_continuation don't touch dirty).
    for obj in &mut store.objects {
        obj.dirty = false;
    }

    store.sanitize();

    // No object should have become dirty.
    assert!(!store.objects[0].dirty, "clean head should not be dirtied");
    assert!(
        !store.objects[1].dirty,
        "clean continuation should not be dirtied"
    );
}

// ---------------------------------------------------------------------------
// T2 — chunk_chain cycle guard
// ---------------------------------------------------------------------------

/// T2: chunk_chain terminates on a corrupt store with a cycle (A → B → A).
///
/// We add a HashSet-based cycle guard to chunk_chain so it doesn't loop
/// forever.  This test verifies termination.
#[test]
fn chunk_chain_cycle_terminates() {
    let mut store = make_store_in_memory(4, 512);
    // Build cycle: idx=0 (head) → idx=1 → idx=2 → idx=1 (cycle).
    make_head(&mut store, 0, "cyclic", 1, 1);
    make_continuation(&mut store, 1, 2, 2);
    make_continuation(&mut store, 2, 3, 1); // → back to idx=1: cycle

    // If chunk_chain has a cycle guard this must terminate in finite time.
    let chain = store.chunk_chain(0);
    // The chain must not include any index twice.
    let unique: std::collections::HashSet<u8> = chain.iter().copied().collect();
    assert_eq!(chain.len(), unique.len(), "chain must not revisit an index");
}

// ---------------------------------------------------------------------------
// T12 — Store::format with boundary object_count
// ---------------------------------------------------------------------------

/// T12: format with object_count = 0 writes nothing and returns a valid Store.
#[test]
fn format_zero_objects() {
    use crate::piv::{DeviceInfo, PivBackend};
    use anyhow::bail;

    struct NullPiv;
    impl PivBackend for NullPiv {
        fn list_readers(&self) -> anyhow::Result<Vec<String>> {
            Ok(vec!["r".to_owned()])
        }
        fn list_devices(&self) -> anyhow::Result<Vec<DeviceInfo>> {
            Ok(vec![DeviceInfo {
                serial: 1,
                version: "5.4.3".to_owned(),
                reader: "r".to_owned(),
            }])
        }
        fn read_object(&self, _r: &str, _id: u32) -> anyhow::Result<Vec<u8>> {
            bail!("null")
        }
        fn write_object(
            &self,
            _r: &str,
            _id: u32,
            _d: &[u8],
            _mk: Option<&str>,
            _pin: Option<&str>,
        ) -> anyhow::Result<()> {
            Ok(()) // silently drop writes
        }
        fn verify_pin(&self, _r: &str, _pin: &str) -> anyhow::Result<()> {
            bail!("null")
        }
        fn send_apdu(&self, _r: &str, _apdu: &[u8]) -> anyhow::Result<Vec<u8>> {
            bail!("null")
        }
        fn ecdh(
            &self,
            _r: &str,
            _slot: u8,
            _peer: &[u8],
            _pin: Option<&str>,
        ) -> anyhow::Result<Vec<u8>> {
            bail!("null")
        }
        fn read_certificate(&self, _r: &str, _slot: u8) -> anyhow::Result<Vec<u8>> {
            bail!("null")
        }
        fn generate_key(&self, _r: &str, _slot: u8, _mk: Option<&str>) -> anyhow::Result<Vec<u8>> {
            bail!("null")
        }
        fn generate_certificate(
            &self,
            _r: &str,
            _slot: u8,
            _subj: &str,
            _mk: Option<&str>,
            _pin: Option<&str>,
        ) -> anyhow::Result<Vec<u8>> {
            bail!("null")
        }
        fn read_printed_object_with_pin(&self, _r: &str, _pin: &str) -> anyhow::Result<Vec<u8>> {
            bail!("null")
        }
    }

    let piv = NullPiv;
    let store = Store::format("r", &piv, 0, 512, 0x82, None, None).unwrap();
    assert_eq!(store.object_count, 0);
    assert_eq!(store.objects.len(), 0);
    assert_eq!(store.free_count(), 0);
}

// ---------------------------------------------------------------------------
// T13 — alloc_free returns None on a full store
// ---------------------------------------------------------------------------

/// T13: alloc_free returns None when all slots are occupied.
#[test]
fn alloc_free_returns_none_when_full() {
    let mut store = make_store_in_memory(2, 512);
    make_head(&mut store, 0, "a", 1, 0);
    make_head(&mut store, 1, "b", 2, 1);

    assert_eq!(store.free_count(), 0);
    assert!(store.alloc_free().is_none());
}
