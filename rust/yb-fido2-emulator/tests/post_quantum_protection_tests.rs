// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Spec 0028 — the post-quantum protection end to end: the emulator for
//! FIDO2, the simulated YubiKey for PIV.  Round trips, one touch per blob,
//! corruption, forgery by someone with the management key, a PIV reset
//! (D11), and refusals that write nothing.

use anyhow::Result;
use std::path::Path;
use yb_core::fido2::ffi::FidoDevIo;
use yb_core::fido2::{Device, Fido2Error};
use yb_core::orchestrator::post_quantum::{
    blob_checksum, create_post_quantum_store, quick_check, IntegrityError, PostQuantumProtection,
    FLAG_ENCRYPTED, PQ_VERSION,
};
use yb_core::orchestrator::{
    fetch_blob_with, store_blob_with, BlobMeta, Protected, Protection, SigVerdict,
};
use yb_core::piv::{MgmtAlgo, PivBackend, VirtualPiv};
use yb_core::store::Store;
use yb_core::Compression;
use yb_fido2_emulator as emulator;

const IO: FidoDevIo = FidoDevIo {
    open: emulator::io_open,
    close: emulator::io_close,
    read: emulator::io_read,
    write: emulator::io_write,
};
const PIN: &str = "654321";
const FACTORY_MGMT: &str = "010203040506070801020304050607080102030405060708";
/// The user's own management key (the factory one is refused, D7).
const MGMT: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718";

struct Setup {
    piv: VirtualPiv,
    reader: String,
    dev: Device,
    store: Store,
    /// The emulator's touch count when the store was ready.
    touches_at_start: u32,
}

fn no_message() {}

impl Setup {
    fn new() -> Self {
        let fixture =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../yb-core/tests/fixtures/with_key.yaml");
        let piv = VirtualPiv::from_fixture(&fixture).unwrap();
        let reader = piv.reader_name();
        piv.set_management_key(&reader, FACTORY_MGMT, MGMT, MgmtAlgo::Tdes)
            .unwrap();
        emulator::power_on(Some(88_888_888));
        emulator::set_touch(true);
        let dev = Device::open_with_io(&IO).unwrap();
        dev.set_pin(PIN).unwrap();
        let before = emulator::touches();
        let store =
            create_post_quantum_store(&piv, &reader, &dev, PIN, MGMT, MgmtAlgo::Tdes, 16, &|| {})
                .unwrap();
        assert_eq!(emulator::touches() - before, 2, "format: two touches");
        Self {
            piv,
            reader,
            dev,
            store,
            touches_at_start: emulator::touches(),
        }
    }

    fn protection(&self) -> PostQuantumProtection<'_> {
        PostQuantumProtection {
            piv: &self.piv,
            reader: &self.reader,
            descriptor: self.store.descriptor().unwrap(),
            fido2: &self.dev,
            pin: PIN,
            on_touch: &no_message,
            on_touched: &|| {},
        }
    }

    fn store(&mut self, name: &str, data: &[u8], encrypt: bool) -> Result<bool> {
        let reader = self.reader.clone();
        let mut store = Store::from_device(&reader, &self.piv)?;
        let r = store_blob_with(
            &mut store,
            &self.piv,
            &self.protection(),
            name,
            data,
            encrypt,
            Compression::Auto,
            None,
        );
        self.store = store;
        r
    }

    /// Touches since the store was ready.
    fn touches(&self) -> u32 {
        emulator::touches() - self.touches_at_start
    }

    fn fetch(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let store = Store::from_device(&self.reader, &self.piv)?;
        fetch_blob_with(&store, &self.protection(), name)
    }
}

fn integrity(e: anyhow::Error) -> IntegrityError {
    e.downcast::<IntegrityError>().expect("an IntegrityError")
}

#[test]
fn round_trips_with_one_touch_per_blob() {
    let mut s = Setup::new();
    let secret = b"correct horse battery staple".repeat(200);
    let public = vec![0x5a; 7000];
    assert!(s.store("secret", &secret, true).unwrap());
    assert!(s.store("public", &public, false).unwrap());
    assert_eq!(s.touches(), 2, "one touch per stored blob");

    assert_eq!(s.fetch("secret").unwrap().as_deref(), Some(&secret[..]));
    assert_eq!(s.fetch("public").unwrap().as_deref(), Some(&public[..]));
    assert_eq!(s.touches(), 4, "one touch per fetched blob");

    let store = Store::from_device(&s.reader, &s.piv).unwrap();
    for name in ["secret", "public"] {
        let head = store.find_head(name).unwrap();
        assert_eq!(quick_check(head, &store), SigVerdict::ChecksumOk);
    }
    assert!(store.find_head("secret").unwrap().is_encrypted());
    assert!(!store.find_head("public").unwrap().is_encrypted());
}

/// A byte changed on the card: the checksum (no PIN) and fetch both say
/// corrupted.
#[test]
fn corruption_is_detected_without_pin() {
    let mut s = Setup::new();
    assert!(s.store("doc", &[0x11; 500], false).unwrap());
    let store = Store::from_device(&s.reader, &s.piv).unwrap();
    let head = store.find_head("doc").unwrap();
    let id = store.object_id(head.index());
    let mut raw = s.piv.read_object(&s.reader, id).unwrap();
    raw[40] ^= 0x01; // a payload byte
    s.piv.write_object(&s.reader, id, &raw, MGMT).unwrap();

    let store = Store::from_device(&s.reader, &s.piv).unwrap();
    let head = store.find_head("doc").unwrap();
    assert_eq!(quick_check(head, &store), SigVerdict::Corrupted);
    let before = s.touches();
    let err = integrity(s.fetch("doc").unwrap_err());
    assert_eq!(err, IntegrityError::Corrupted("doc".into()));
    assert_eq!(s.touches(), before, "no touch for a corrupted blob");
}

/// Someone with the management key, but not the card's K2: correct
/// checksums are easy to write, seals are not (G4).
struct Forger {
    encrypt: bool,
}

impl Protection for Forger {
    fn overhead(&self, encrypt: bool) -> (usize, usize) {
        if encrypt {
            (29, 65)
        } else {
            (0, 97)
        }
    }
    fn protect(
        &self,
        name: &str,
        payload: &[u8],
        _: bool,
        compressed: bool,
        plain_size: u32,
        mtime: u32,
    ) -> Result<Protected> {
        let salt: [u8; 32] = rand::random();
        let stored = if self.encrypt {
            let mut s = vec![PQ_VERSION];
            s.extend((0..payload.len() + 28).map(|_| rand::random::<u8>()));
            s
        } else {
            payload.to_vec()
        };
        let key_byte = if self.encrypt { FLAG_ENCRYPTED } else { 0 };
        let meta = BlobMeta {
            name: name.to_owned(),
            key_byte,
            compressed,
            plain_size,
            stored_size: stored.len() as u32,
            mtime,
        };
        let mut trailer = vec![PQ_VERSION];
        trailer.extend_from_slice(&salt);
        trailer.extend_from_slice(&blob_checksum(&meta, &salt, &stored));
        if !self.encrypt {
            trailer.extend_from_slice(&rand::random::<[u8; 32]>());
        }
        Ok(Protected {
            stored,
            key_byte,
            trailer,
            management_key: Some(MGMT.to_owned().into()),
        })
    }
    fn open(&self, _: &BlobMeta, _: &[u8], _: &[u8]) -> Result<Vec<u8>> {
        unreachable!()
    }
    fn quick_check(&self, _: &yb_core::store::Object, _: &Store) -> SigVerdict {
        unreachable!()
    }
}

#[test]
fn forged_blobs_pass_the_checksum_but_not_the_seal() {
    for encrypt in [false, true] {
        let s = Setup::new();
        let mut store = Store::from_device(&s.reader, &s.piv).unwrap();
        assert!(store_blob_with(
            &mut store,
            &s.piv,
            &Forger { encrypt },
            "forged",
            &[0x66; 300],
            encrypt,
            Compression::None,
            None,
        )
        .unwrap());

        let store = Store::from_device(&s.reader, &s.piv).unwrap();
        let head = store.find_head("forged").unwrap();
        assert_eq!(quick_check(head, &store), SigVerdict::ChecksumOk);
        let err = integrity(s.fetch("forged").unwrap_err());
        assert_eq!(
            err,
            IntegrityError::SealFailed("forged".into()),
            "encrypt {encrypt}"
        );
    }
}

/// D11: after a PIV reset, objects written back with the factory key are
/// refused at fetch and store, and nothing is written.
#[test]
fn piv_reset_is_detected() {
    let mut s = Setup::new();
    assert!(s.store("doc", b"kept", true).unwrap());
    let ids: Vec<u32> = (0..=16).map(|i| 0x5F_0000 + i).collect();
    let saved: Vec<(u32, Vec<u8>)> = ids
        .iter()
        .filter_map(|&id| s.piv.read_object(&s.reader, id).ok().map(|raw| (id, raw)))
        .collect();

    s.piv.reset_piv(&s.reader).unwrap();
    s.piv
        .change_reference(&s.reader, yb_core::PinRef::Pin, "123456", PIN)
        .ok();
    for (id, raw) in &saved {
        s.piv
            .write_object(&s.reader, *id, raw, FACTORY_MGMT)
            .unwrap();
    }

    let err = integrity(s.fetch("doc").unwrap_err());
    assert_eq!(err, IntegrityError::ManagementKeyMismatch);
    let writes = s.piv.write_count();
    let err = integrity(s.store("new", b"x", false).unwrap_err());
    assert_eq!(err, IntegrityError::ManagementKeyMismatch);
    assert_eq!(
        s.piv.write_count(),
        writes,
        "a store after a PIV reset wrote"
    );
}

/// A refused touch or a wrong PIN stores nothing (spec 0028, "Writing").
#[test]
fn refusals_write_nothing() {
    let mut s = Setup::new();
    let writes = s.piv.write_count();

    emulator::set_touch(false);
    let err = s.store("a", b"data", true).unwrap_err();
    assert_eq!(err.downcast::<Fido2Error>().unwrap(), Fido2Error::NoTouch);
    emulator::set_touch(true);
    assert_eq!(s.piv.write_count(), writes);

    let wrong = PostQuantumProtection {
        pin: "000000",
        ..s.protection()
    };
    let mut store = Store::from_device(&s.reader, &s.piv).unwrap();
    let err = store_blob_with(
        &mut store,
        &s.piv,
        &wrong,
        "b",
        b"data",
        true,
        Compression::None,
        None,
    )
    .unwrap_err();
    assert_eq!(
        err.downcast::<Fido2Error>().unwrap(),
        Fido2Error::PinInvalid
    );
    assert_eq!(s.piv.write_count(), writes);
}
