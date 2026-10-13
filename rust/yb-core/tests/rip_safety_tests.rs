// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Spec 0031 — rip-safe replace.
//!
//! A blob store or remove interrupted after any number of object writes (a
//! YubiKey pulled out of the computer) leaves the blob concerned with its
//! old or its new content, never neither, and every other blob unchanged.
//! `Fault::WriteFails(n)` rejects the n-th object write, as a rip would.

use std::collections::BTreeMap;
use std::path::Path;
use yb_core::piv::{Fault, PivBackend, VirtualPiv};
use yb_core::store::Store;
use yb_core::test_utils::{OpType, OperationGenerator};
use yb_core::{
    chunks_needed, fetch_blob, list_blobs, objects_needed, remove_blob, remove_blobs, store_blob,
    Compression, Encryption, StoreOptions,
};

const MGMT: &str = "010203040506070801020304050607080102030405060708";
const VAULT: &str = "vault.kdbx";
/// PIN of the `with_key.yaml` fixture, for decrypting encrypted blobs.
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

fn put(store: &mut Store, piv: &VirtualPiv, name: &str, data: &[u8]) {
    assert!(store_blob(store, piv, name, data, plain(), MGMT, None).unwrap());
}

/// The content of `name` as a fresh load of the card shows it.
fn content(piv: &VirtualPiv, name: &str) -> Option<Vec<u8>> {
    let reader = piv.reader_name();
    let store = Store::from_device(&reader, piv).unwrap();
    fetch_blob(&store, piv, &reader, name, Some(PIN), false)
        .unwrap_or_else(|e| panic!("fetching {name}: {e:#}"))
}

/// Blobs present in every scenario, which must never change.
fn others() -> Vec<(&'static str, Vec<u8>)> {
    vec![("small", vec![0xAA; 100]), ("medium", vec![0xBB; 4000])]
}

enum Op {
    Store(Vec<u8>),
    Remove,
}

/// A card with the other blobs and, if given, the old content of VAULT.
fn setup(old: Option<&[u8]>) -> VirtualPiv {
    let piv = new_piv();
    let reader = piv.reader_name();
    let mut store = Store::format(&reader, &piv, 16, 0x82, MGMT).unwrap();
    for (name, data) in others() {
        put(&mut store, &piv, name, &data);
    }
    if let Some(old) = old {
        put(&mut store, &piv, VAULT, old);
    }
    piv
}

/// Interrupt `op` at its 1st, 2nd, … object write until it completes, and
/// check the rip property after each interruption.
fn check_rip_property(old: Option<Vec<u8>>, op: Op) {
    let new = match &op {
        Op::Store(data) => Some(data.clone()),
        Op::Remove => None,
    };
    for n in 1..=64 {
        let piv = setup(old.as_deref());
        let reader = piv.reader_name();
        let mut store = Store::from_device(&reader, &piv).unwrap();

        piv.inject_fault(Fault::WriteFails(n));
        let result = match &op {
            Op::Store(data) => {
                store_blob(&mut store, &piv, VAULT, data, plain(), MGMT, None).map(|_| ())
            }
            Op::Remove => remove_blob(&mut store, &piv, VAULT, MGMT).map(|_| ()),
        };
        piv.clear_faults();

        let after = content(&piv, VAULT);
        assert!(
            after == old || after == new,
            "interrupted at write {n}: {VAULT} is neither its old nor its new content \
             ({:?} bytes)",
            after.as_ref().map(Vec::len)
        );
        for (name, data) in others() {
            assert_eq!(
                content(&piv, name).as_deref(),
                Some(data.as_slice()),
                "interrupted at write {n}: {name} changed"
            );
        }
        if result.is_ok() {
            // The fault was beyond the operation's last write.
            assert_eq!(after, new, "a completed operation leaves the new content");
            return;
        }
    }
    panic!("the operation did not complete within 64 object writes");
}

#[test]
fn rip_during_first_store() {
    check_rip_property(None, Op::Store(vec![0x01; 5000]));
}

#[test]
fn rip_during_replace_single_chunk() {
    check_rip_property(Some(vec![0x01; 100]), Op::Store(vec![0x02; 200]));
}

#[test]
fn rip_during_replace_same_chunk_count() {
    check_rip_property(Some(vec![0x01; 5000]), Op::Store(vec![0x02; 5000]));
}

#[test]
fn rip_during_replace_with_more_chunks() {
    check_rip_property(Some(vec![0x01; 1000]), Op::Store(vec![0x02; 8000]));
}

#[test]
fn rip_during_replace_with_fewer_chunks() {
    check_rip_property(Some(vec![0x01; 8000]), Op::Store(vec![0x02; 1000]));
}

#[test]
fn rip_during_remove() {
    check_rip_property(Some(vec![0x01; 5000]), Op::Remove);
}

/// G1: the new copy is written into objects that were free, never into the
/// old copy's objects.
#[test]
fn replace_never_reuses_the_old_copys_objects() {
    let piv = setup(Some(&[0x01; 5000]));
    let reader = piv.reader_name();
    let chain = |store: &Store| {
        let head = store
            .objects
            .iter()
            .position(|o| o.is_head() && o.blob_name == VAULT)
            .unwrap();
        store.chunk_chain(head as u8)
    };

    let mut store = Store::from_device(&reader, &piv).unwrap();
    let old = chain(&store);
    put(&mut store, &piv, VAULT, &[0x02; 5000]);
    let new = chain(&Store::from_device(&reader, &piv).unwrap());

    assert!(
        new.iter().all(|i| !old.contains(i)),
        "new chain {new:?} reuses objects of the old chain {old:?}"
    );
    // The old copy is gone once the replace completed.
    assert_eq!(content(&piv, VAULT), Some(vec![0x02; 5000]));
}

/// Reading never writes: loading a store with leftovers of an interrupted
/// replace (both copies on the card) discards the old copy in memory only.
#[test]
fn loading_a_store_with_leftovers_writes_nothing() {
    let piv = setup(Some(&[0x01; 5000]));
    let reader = piv.reader_name();
    let vault_heads = |s: &Store| {
        s.objects
            .iter()
            .filter(|o| o.is_head() && o.blob_name == VAULT)
            .count()
    };

    // Interrupt replaces earlier and earlier until one leaves both copies on
    // the card: the new copy written, the old one not yet freed.
    let both_copies = (1..=64).any(|n| {
        let piv_n = setup(Some(&[0x01; 5000]));
        let mut store = Store::from_device(&reader, &piv_n).unwrap();
        piv_n.inject_fault(Fault::WriteFails(n));
        let _ = store_blob(
            &mut store,
            &piv_n,
            VAULT,
            &[0x02; 5000],
            plain(),
            MGMT,
            None,
        );
        piv_n.clear_faults();
        let raw_before = Store::from_device_raw(&reader, &piv_n).unwrap();
        if vault_heads(&raw_before) != 2 {
            return false;
        }
        let loaded = Store::from_device(&reader, &piv_n).unwrap();
        let raw_after = Store::from_device_raw(&reader, &piv_n).unwrap();
        assert_eq!(
            vault_heads(&loaded),
            1,
            "the loaded store shows both copies"
        );
        assert_eq!(vault_heads(&raw_after), 2, "loading wrote to the card");
        assert_eq!(content(&piv_n, VAULT), Some(vec![0x02; 5000]));
        true
    });
    assert!(
        both_copies,
        "no interruption point left both copies on the card"
    );
    drop(piv);
}

/// The `yb rm` path: several blobs removed in one write pass.
#[test]
fn rip_during_multi_blob_remove() {
    let vault = vec![0x01; 5000];
    let second = vec![0x03; 4000];
    for n in 1..=64 {
        let piv = setup(Some(&vault));
        let reader = piv.reader_name();
        let mut store = Store::from_device(&reader, &piv).unwrap();
        put(&mut store, &piv, "second", &second);

        let mut store = Store::from_device(&reader, &piv).unwrap();
        piv.inject_fault(Fault::WriteFails(n));
        let result = remove_blobs(&mut store, &piv, &[VAULT, "second"], MGMT);
        piv.clear_faults();

        for (name, old) in [(VAULT, &vault), ("second", &second)] {
            let after = content(&piv, name);
            assert!(
                after.is_none() || after.as_ref() == Some(old),
                "interrupted at write {n}: {name} is neither whole nor gone"
            );
        }
        for (name, data) in others() {
            assert_eq!(content(&piv, name), Some(data), "write {n}: {name} changed");
        }
        if result.is_ok() {
            assert_eq!(content(&piv, VAULT), None);
            assert_eq!(content(&piv, "second"), None);
            return;
        }
    }
    panic!("the removal did not complete within 64 object writes");
}

/// An encrypted replace whose signature trailer needs an extra chunk.
#[test]
fn rip_during_encrypted_replace_with_signature_spill() {
    // A payload size whose signature trailer spills into an extra chunk.
    let probe = setup(None);
    let object_size = Store::from_device(&probe.reader_name(), &probe)
        .unwrap()
        .object_size;
    let enc = |n: usize| n + yb_core::crypto::GCM_OVERHEAD;
    let size = (2000..20_000)
        .find(|&n| {
            objects_needed(enc(n), VAULT.len(), object_size)
                > chunks_needed(enc(n), VAULT.len(), object_size)
        })
        .expect("a size with a spilling signature");
    let old = vec![0x01; size];
    let new = vec![0x02; size];

    let encrypted_setup = || {
        let piv = new_piv();
        let reader = piv.reader_name();
        let point = piv.generate_key(&reader, 0x82, Some(MGMT)).unwrap();
        let pk = p256::PublicKey::from_sec1_bytes(&point).unwrap();
        let mut store = Store::format(&reader, &piv, 16, 0x82, MGMT).unwrap();
        for (name, data) in others() {
            put(&mut store, &piv, name, &data);
        }
        let opts = StoreOptions {
            encryption: Encryption::Encrypted(&pk),
            compression: Compression::None,
        };
        assert!(store_blob(&mut store, &piv, VAULT, &old, opts, MGMT, None).unwrap());
        (piv, pk)
    };

    for n in 1..=64 {
        let (piv, pk) = encrypted_setup();
        let reader = piv.reader_name();
        let mut store = Store::from_device(&reader, &piv).unwrap();
        piv.inject_fault(Fault::WriteFails(n));
        let opts = StoreOptions {
            encryption: Encryption::Encrypted(&pk),
            compression: Compression::None,
        };
        let result = store_blob(&mut store, &piv, VAULT, &new, opts, MGMT, None);
        piv.clear_faults();

        let after = content(&piv, VAULT);
        assert!(
            after.as_ref() == Some(&old) || after.as_ref() == Some(&new),
            "interrupted at write {n}: the encrypted vault is neither old nor new"
        );
        for (name, data) in others() {
            assert_eq!(content(&piv, name), Some(data), "write {n}: {name} changed");
        }
        if result.is_ok() {
            assert_eq!(after, Some(new));
            return;
        }
    }
    panic!("the replace did not complete within 64 object writes");
}

/// Random operation sequences with random interruptions (the Python-era
/// ejection test, ported and completed): after every operation the store is
/// reloaded from the card, the blob concerned holds its old or its new
/// content, and every other blob matches the model.
#[test]
fn random_operations_with_interruptions() {
    for seed in [1u64, 2, 3] {
        let piv = new_piv();
        let reader = piv.reader_name();
        Store::format(&reader, &piv, 32, 0x82, MGMT).unwrap();
        let mut model: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        // xorshift, for reproducible interruption points.
        let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut interruptions = 0;

        let ops = OperationGenerator::new(seed, 8).generate(400, 0.0);
        for (i, op) in ops.iter().enumerate() {
            let mut store = Store::from_device(&reader, &piv).unwrap();
            if matches!(op.op_type, OpType::Store | OpType::Remove) && next() % 5 == 0 {
                piv.inject_fault(Fault::WriteFails(1 + (next() % 8) as usize));
                interruptions += 1;
            }
            let old = model.get(&op.name).cloned();
            match op.op_type {
                OpType::Store => {
                    let _ =
                        store_blob(&mut store, &piv, &op.name, &op.payload, plain(), MGMT, None);
                    piv.clear_faults();
                    let after = content(&piv, &op.name);
                    assert!(
                        after == old || after.as_deref() == Some(op.payload.as_slice()),
                        "seed {seed}, op {i}: store of {} left neither old nor new",
                        op.name
                    );
                    match after {
                        Some(data) => model.insert(op.name.clone(), data),
                        None => model.remove(&op.name),
                    };
                }
                OpType::Remove => {
                    let _ = remove_blob(&mut store, &piv, &op.name, MGMT);
                    piv.clear_faults();
                    let after = content(&piv, &op.name);
                    assert!(
                        after.is_none() || after == old,
                        "seed {seed}, op {i}: removal of {} left something else",
                        op.name
                    );
                    match after {
                        Some(data) => model.insert(op.name.clone(), data),
                        None => model.remove(&op.name),
                    };
                }
                OpType::Fetch | OpType::List => {}
            }

            // Every blob on the card matches the model, and nothing else is.
            let store = Store::from_device(&reader, &piv).unwrap();
            let names: Vec<String> = list_blobs(&store).into_iter().map(|b| b.name).collect();
            let expected: Vec<String> = model.keys().cloned().collect();
            assert_eq!(names, expected, "seed {seed}, op {i}: blob names");
            for (name, data) in &model {
                assert_eq!(
                    content(&piv, name).as_ref(),
                    Some(data),
                    "seed {seed}, op {i}: {name} changed"
                );
            }
        }
        assert!(interruptions > 20, "seed {seed}: too few interruptions");
    }
}
