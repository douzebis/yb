// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Spec 0028, libyubiblob 0.2.0: post-quantum stores through the C
//! functions, on a simulated YubiKey (`YB_FIXTURE`) whose FIDO2 side is
//! the emulator, served on a socket (`YB_FIDO2_SOCKET`).

use std::ffi::{c_void, CStr, CString};
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

use tempfile::TempDir;
use yb_core::fido2::pairing::open_yubikey;
use yb_core::fido2::socket::SOCKET_ENV;
use yb_core::orchestrator::post_quantum::{create_post_quantum_store, PostQuantumProtection};
use yb_core::orchestrator::store_blob_with;
use yb_core::piv::virtual_piv::fixtures;
use yb_core::piv::{MgmtAlgo, PivBackend, VirtualPiv};
use yb_core::store::Store;
use yb_core::Compression;
use yb_fido2_emulator::server::Server;
use yubiblob::*;

const SERIAL: u32 = 88_888_888;
const FACTORY_MGMT: &str = "010203040506070801020304050607080102030405060708";
const OWN_MGMT: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718";
const FIDO2_PIN: &[u8] = b"fido2-pin";
/// The fixture's PIV PIN: never tried as the FIDO2 PIN.
const PIV_PIN: &[u8] = b"654321";

/// `YB_FIXTURE`, `YB_FIDO2_SOCKET` and the emulator are process-wide: one
/// test at a time.
static LOCK: Mutex<()> = Mutex::new(());

/// A YubiKey with a post-quantum store of 16 objects, made as `yb format
/// --post-quantum` does, and its FIDO2 side served by the emulator.
struct Card {
    dir: TempDir,
    server: Server,
}

impl Card {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let server = serve(&dir, "fido2.sock", SERIAL);
        let piv = VirtualPiv::from_fixture_yaml(fixtures::WITH_KEY).unwrap();
        let reader = piv.reader_name();
        piv.set_management_key(&reader, FACTORY_MGMT, OWN_MGMT, MgmtAlgo::Tdes)
            .unwrap();
        let dev = open_yubikey(SERIAL, 1, &|| {}).unwrap();
        let pin = std::str::from_utf8(FIDO2_PIN).unwrap();
        dev.set_pin(pin).unwrap();
        create_post_quantum_store(
            &piv,
            &reader,
            &dev,
            pin,
            OWN_MGMT,
            MgmtAlgo::Tdes,
            16,
            &|| {},
        )
        .unwrap();
        drop(dev);
        let card = Self { dir, server };
        piv.save_fixture(&card.path()).unwrap();
        card
    }

    fn path(&self) -> PathBuf {
        self.dir.path().join("card.yaml")
    }

    /// Change the card in place (between sessions).
    fn change(&self, f: impl FnOnce(&VirtualPiv, &str)) {
        let piv = VirtualPiv::from_fixture(&self.path()).unwrap();
        let reader = piv.reader_name();
        f(&piv, &reader);
        piv.save_fixture(&self.path()).unwrap();
    }

    /// Store an unencrypted blob, kept in the card's file (a library
    /// session's writes last as long as the session).
    fn put(&self, name: &str, data: &[u8]) {
        self.change(|piv, reader| {
            let mut store = Store::from_device(reader, piv).unwrap();
            let descriptor = store.descriptor().unwrap().clone();
            let dev = open_yubikey(SERIAL, 1, &|| {}).unwrap();
            let protection = PostQuantumProtection {
                piv,
                reader,
                descriptor: &descriptor,
                fido2: &dev,
                pin: std::str::from_utf8(FIDO2_PIN).unwrap(),
                on_touch: &|| {},
                on_touched: &|| {},
            };
            let stored = store_blob_with(
                &mut store,
                piv,
                &protection,
                name,
                data,
                false,
                Compression::None,
                None,
            )
            .unwrap();
            assert!(stored);
        });
    }

    fn open(&self, flags: u32) -> Session {
        std::env::set_var("YB_FIXTURE", self.path());
        let mut s = ptr::null_mut();
        let status = unsafe { yubiblob_open(0, flags, &mut s) };
        assert_eq!(status, YUBIBLOB_OK, "{}", last_error());
        Session(s)
    }
}

/// A fresh emulator reporting `serial`, served at `dir/name`, used by the
/// next calls.
fn serve(dir: &TempDir, name: &str, serial: u32) -> Server {
    let server = Server::start(&dir.path().join(name), Some(serial)).unwrap();
    std::env::set_var(SOCKET_ENV, &server.path);
    server
}

struct Session(*mut yubiblob::Session);

impl Drop for Session {
    fn drop(&mut self) {
        unsafe { yubiblob_close(self.0) };
    }
}

impl Session {
    fn store(&self, name: &str, data: &[u8], flags: u32, pin: &[u8]) -> Status {
        let name = CString::new(name).unwrap();
        unsafe {
            yubiblob_store(
                self.0,
                name.as_ptr(),
                data.as_ptr(),
                data.len(),
                flags,
                pin.as_ptr(),
                pin.len(),
            )
        }
    }

    fn fetch(&self, name: &str, pin: &[u8]) -> Result<Vec<u8>, Status> {
        let name = CString::new(name).unwrap();
        let (mut data, mut len) = (ptr::null_mut(), 0usize);
        let status = unsafe {
            yubiblob_fetch(
                self.0,
                name.as_ptr(),
                pin.as_ptr(),
                pin.len(),
                &mut data,
                &mut len,
            )
        };
        if status != YUBIBLOB_OK {
            return Err(status);
        }
        let content = unsafe { std::slice::from_raw_parts(data, len) }.to_vec();
        unsafe { yubiblob_buffer_free(data, len) };
        Ok(content)
    }

    /// `yubiblob_fetch_unencrypted`: the content and the verdict.
    fn fetch_unencrypted(&self, name: &str) -> Result<(Vec<u8>, SignatureVerdict), Status> {
        let name = CString::new(name).unwrap();
        let (mut data, mut len) = (ptr::null_mut(), 0usize);
        let mut verdict = SignatureVerdict::MAX;
        let status = unsafe {
            yubiblob_fetch_unencrypted(self.0, name.as_ptr(), &mut data, &mut len, &mut verdict)
        };
        if status != YUBIBLOB_OK {
            return Err(status);
        }
        let content = unsafe { std::slice::from_raw_parts(data, len) }.to_vec();
        unsafe { yubiblob_buffer_free(data, len) };
        Ok((content, verdict))
    }

    fn remove(&self, name: &str, pin: &[u8]) -> Status {
        let name = CString::new(name).unwrap();
        unsafe { yubiblob_remove(self.0, name.as_ptr(), 0, pin.as_ptr(), pin.len()) }
    }

    /// (name, encrypted, verdict) of every blob.
    fn list(&self) -> Vec<(String, bool, SignatureVerdict)> {
        let (mut blobs, mut count) = (ptr::null_mut(), 0usize);
        let status = unsafe { yubiblob_list(self.0, &mut blobs, &mut count) };
        assert_eq!(status, YUBIBLOB_OK, "{}", last_error());
        let listed = (0..count)
            .map(|i| {
                let b = unsafe { &*blobs.add(i) };
                let name = unsafe { CStr::from_ptr(b.name) };
                (name.to_str().unwrap().to_owned(), b.encrypted, b.signature)
            })
            .collect();
        unsafe { yubiblob_blobs_free(blobs, count) };
        listed
    }

    fn info(&self) -> StoreInfo {
        let mut info = StoreInfo {
            object_count: 0,
            free_objects: 0,
            kind: u32::MAX,
        };
        let status = unsafe { yubiblob_store_info(self.0, &mut info) };
        assert_eq!(status, YUBIBLOB_OK, "{}", last_error());
        info
    }

    /// Count the touch notifications in `counter`.
    fn count_touches(&self, counter: &AtomicU32) {
        let user = ptr::from_ref(counter).cast_mut().cast::<c_void>();
        let status = unsafe { yubiblob_set_touch_callback(self.0, Some(count_touch), user) };
        assert_eq!(status, YUBIBLOB_OK);
    }

    /// Count the "touch is over" notifications in `counter` (spec 0051 S5).
    fn count_touched(&self, counter: &AtomicU32) {
        let user = ptr::from_ref(counter).cast_mut().cast::<c_void>();
        let status = unsafe { yubiblob_set_touched_callback(self.0, Some(count_touch), user) };
        assert_eq!(status, YUBIBLOB_OK);
    }
}

unsafe extern "C" fn count_touch(user: *mut c_void) {
    (*user.cast::<AtomicU32>()).fetch_add(1, Ordering::SeqCst);
}

fn last_error() -> String {
    unsafe { CStr::from_ptr(yubiblob_last_error()) }
        .to_string_lossy()
        .into_owned()
}

fn lock() -> std::sync::MutexGuard<'static, ()> {
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

#[test]
fn round_trips_with_a_touch_per_blob() {
    let _lock = lock();
    let card = Card::new();
    let s = card.open(0);
    let info = s.info();
    assert_eq!(info.kind, YUBIBLOB_KIND_POST_QUANTUM);
    assert_eq!((info.object_count, info.free_objects), (16, 16));

    let notified = AtomicU32::new(0);
    s.count_touches(&notified);
    let over = AtomicU32::new(0);
    s.count_touched(&over);
    let before = card.server.touches();
    let secret = b"post-quantum secret ".repeat(300);
    let flags = YUBIBLOB_STORE_ENCRYPT | YUBIBLOB_STORE_COMPRESS;
    assert_eq!(
        s.store("vault.kdbx", &secret, flags, FIDO2_PIN),
        YUBIBLOB_OK,
        "{}",
        last_error()
    );
    assert_eq!(s.store("public", b"plain", 0, FIDO2_PIN), YUBIBLOB_OK);
    assert_eq!(s.fetch("vault.kdbx", FIDO2_PIN).unwrap(), secret);
    assert_eq!(s.fetch("public", FIDO2_PIN).unwrap(), b"plain");
    assert_eq!(card.server.touches() - before, 4, "one touch per blob");
    assert_eq!(notified.load(Ordering::SeqCst), 4, "one notification each");

    // Checked without PIN by the checksum.
    assert_eq!(
        s.list(),
        [
            ("public".to_owned(), false, YUBIBLOB_SIGNATURE_CHECKSUM_OK),
            (
                "vault.kdbx".to_owned(),
                true,
                YUBIBLOB_SIGNATURE_CHECKSUM_OK
            ),
        ]
    );

    // Removing needs the management key: the PIN and one touch.
    assert_eq!(
        s.remove("public", FIDO2_PIN),
        YUBIBLOB_OK,
        "{}",
        last_error()
    );
    assert_eq!(notified.load(Ordering::SeqCst), 5);
    // Each announced touch is followed by its end.
    assert_eq!(over.load(Ordering::SeqCst), 5);
    assert_eq!(s.list().len(), 1);

    // No callback: still works.
    let status = unsafe { yubiblob_set_touch_callback(s.0, None, ptr::null_mut()) };
    assert_eq!(status, YUBIBLOB_OK);
    assert_eq!(s.fetch("vault.kdbx", FIDO2_PIN).unwrap(), secret);
    assert_eq!(notified.load(Ordering::SeqCst), 5);
}

/// The FIDO2 PIN only: the PIV PIN is a wrong FIDO2 PIN, with the
/// attempts left; 3 in a row ask for a replug; then, with 3 attempts
/// left, the PIN is not tried without the open flag (D10).
#[test]
fn fido2_pin_rules() {
    let _lock = lock();
    let card = Card::new();
    let s = card.open(0);
    assert_eq!(s.store("doc", b"data", 0, FIDO2_PIN), YUBIBLOB_OK);

    assert_eq!(s.fetch("doc", PIV_PIN), Err(YUBIBLOB_ERR_WRONG_PIN));
    assert_eq!(yubiblob_last_pin_tries(), 7);
    assert_eq!(s.fetch("doc", PIV_PIN), Err(YUBIBLOB_ERR_WRONG_PIN));
    assert_eq!(s.fetch("doc", PIV_PIN), Err(YUBIBLOB_ERR_REPLUG));
    assert_eq!(s.fetch("doc", FIDO2_PIN), Err(YUBIBLOB_ERR_REPLUG));
    card.server.replug();
    assert_eq!(s.fetch("doc", PIV_PIN), Err(YUBIBLOB_ERR_WRONG_PIN));
    assert_eq!(s.fetch("doc", PIV_PIN), Err(YUBIBLOB_ERR_WRONG_PIN));
    assert_eq!(yubiblob_last_pin_tries(), 3);

    assert_eq!(
        s.fetch("doc", FIDO2_PIN),
        Err(YUBIBLOB_ERR_FEW_PIN_ATTEMPTS)
    );
    assert_eq!(s.remove("doc", FIDO2_PIN), YUBIBLOB_ERR_FEW_PIN_ATTEMPTS);
    drop(s);
    card.put("kept", b"data");
    let s = card.open(YUBIBLOB_OPEN_ALLOW_LOW_PIN_ATTEMPTS);
    assert_eq!(s.fetch("kept", FIDO2_PIN).unwrap(), b"data");
    // A right PIN restores the attempts.
    drop(s);
    let s = card.open(0);
    assert_eq!(s.fetch("kept", FIDO2_PIN).unwrap(), b"data");
}

/// A refused touch: nothing written, nothing returned.
#[test]
fn no_touch() {
    let _lock = lock();
    let card = Card::new();
    let s = card.open(0);
    assert_eq!(s.store("doc", b"data", 0, FIDO2_PIN), YUBIBLOB_OK);
    let (announced, over) = (AtomicU32::new(0), AtomicU32::new(0));
    s.count_touches(&announced);
    s.count_touched(&over);
    card.server.set_touch(false);
    assert_eq!(
        s.store("new", b"x", YUBIBLOB_STORE_ENCRYPT, FIDO2_PIN),
        YUBIBLOB_ERR_NO_TOUCH
    );
    assert_eq!(s.fetch("doc", FIDO2_PIN), Err(YUBIBLOB_ERR_NO_TOUCH));
    assert_eq!(s.remove("doc", FIDO2_PIN), YUBIBLOB_ERR_NO_TOUCH);
    // A refused touch ends too: a notice comes down (spec 0051 S5).
    assert_eq!(announced.load(Ordering::SeqCst), 3);
    assert_eq!(over.load(Ordering::SeqCst), 3);
    card.server.set_touch(true);
    assert_eq!(s.list().len(), 1);
    assert_eq!(s.info().free_objects, 15);
}

/// A changed byte is corrupted (checksum, no touch); a changed management
/// key, as after a PIV reset, is tampering (D11).
#[test]
fn corrupted_and_tampered() {
    let _lock = lock();
    let card = Card::new();
    card.put("a", &[0x11; 400]);
    card.put("b", b"kept");
    card.change(|piv, reader| {
        let store = Store::from_device(reader, piv).unwrap();
        let id = store.object_id(store.find_head("a").unwrap().index());
        let mut raw = piv.read_object(reader, id).unwrap();
        raw[40] ^= 0x01;
        piv.write_object(reader, id, &raw, OWN_MGMT).unwrap();
    });
    let s = card.open(0);
    let before = card.server.touches();
    assert_eq!(s.fetch("a", FIDO2_PIN), Err(YUBIBLOB_ERR_CORRUPTED));
    assert_eq!(
        card.server.touches(),
        before,
        "no touch for a corrupted blob"
    );
    assert_eq!(s.list()[0].2, YUBIBLOB_SIGNATURE_CORRUPTED);
    drop(s);

    card.change(|piv, reader| {
        piv.set_management_key(reader, OWN_MGMT, FACTORY_MGMT, MgmtAlgo::Tdes)
            .unwrap();
    });
    let s = card.open(0);
    assert_eq!(s.fetch("b", FIDO2_PIN), Err(YUBIBLOB_ERR_TAMPERED));
    assert_eq!(s.store("c", b"x", 0, FIDO2_PIN), YUBIBLOB_ERR_TAMPERED);
    assert_eq!(s.remove("b", FIDO2_PIN), YUBIBLOB_ERR_TAMPERED);
    assert_eq!(s.list().len(), 2);
}

/// The FIDO2 side missing, or reset (credential gone).
#[test]
fn fido2_side_missing_or_reset() {
    let _lock = lock();
    let card = Card::new();
    let s = card.open(0);
    assert_eq!(s.store("doc", b"data", 0, FIDO2_PIN), YUBIBLOB_OK);

    // Another YubiKey's FIDO2 side only.
    let _other = serve(&card.dir, "other.sock", SERIAL + 1);
    assert_eq!(s.fetch("doc", FIDO2_PIN), Err(YUBIBLOB_ERR_NO_FIDO2_ACCESS));

    // This YubiKey after a FIDO2 reset: no PIN, then a new PIN.
    let _reset = serve(&card.dir, "reset.sock", SERIAL);
    assert_eq!(s.fetch("doc", FIDO2_PIN), Err(YUBIBLOB_ERR_NO_CREDENTIAL));
    let dev = open_yubikey(SERIAL, 1, &|| {}).unwrap();
    dev.set_pin(std::str::from_utf8(FIDO2_PIN).unwrap())
        .unwrap();
    drop(dev);
    assert_eq!(s.fetch("doc", FIDO2_PIN), Err(YUBIBLOB_ERR_NO_CREDENTIAL));
}

/// Spec 0044: unencrypted blobs read with no PIN and no touch, even with
/// the FIDO2 PIN blocked; encrypted ones refused; corruption detected.
#[test]
fn fetch_unencrypted_without_fido2() {
    let _lock = lock();
    let card = Card::new();
    card.put("public", b"plain");
    let s = card.open(0);
    assert_eq!(
        s.store("secret", b"x", YUBIBLOB_STORE_ENCRYPT, FIDO2_PIN),
        YUBIBLOB_OK
    );
    // 3 wrong PINs in a row: the FIDO2 side refuses until replugged.
    for _ in 0..3 {
        assert_ne!(s.fetch("public", PIV_PIN), Ok(b"plain".to_vec()));
    }
    assert_eq!(s.fetch("public", FIDO2_PIN), Err(YUBIBLOB_ERR_REPLUG));

    let touches = card.server.touches();
    assert_eq!(
        s.fetch_unencrypted("public"),
        Ok((b"plain".to_vec(), YUBIBLOB_SIGNATURE_CHECKSUM_OK))
    );
    assert_eq!(card.server.touches(), touches, "no touch");
    assert_eq!(s.fetch_unencrypted("secret"), Err(YUBIBLOB_ERR_ENCRYPTED));
    assert_eq!(s.fetch_unencrypted("nothing"), Err(YUBIBLOB_ERR_NOT_FOUND));
    drop(s);

    card.change(|piv, reader| {
        let store = Store::from_device(reader, piv).unwrap();
        let id = store.object_id(store.find_head("public").unwrap().index());
        let mut raw = piv.read_object(reader, id).unwrap();
        raw[40] ^= 0x01;
        piv.write_object(reader, id, &raw, OWN_MGMT).unwrap();
    });
    let s = card.open(0);
    assert_eq!(s.fetch_unencrypted("public"), Err(YUBIBLOB_ERR_CORRUPTED));
}

/// A legacy store still says its kind.
#[test]
fn legacy_kind() {
    let _lock = lock();
    let dir = TempDir::new().unwrap();
    let path: PathBuf = dir.path().join("card.yaml");
    let piv = VirtualPiv::from_fixture_yaml(fixtures::WITH_KEY).unwrap();
    let reader = piv.reader_name();
    Store::format(&reader, &piv, 8, 0x82, FACTORY_MGMT).unwrap();
    piv.save_fixture(Path::new(&path)).unwrap();
    std::env::set_var("YB_FIXTURE", &path);
    let mut s = ptr::null_mut();
    assert_eq!(unsafe { yubiblob_open(0, 0, &mut s) }, YUBIBLOB_OK);
    let s = Session(s);
    assert_eq!(s.info().kind, YUBIBLOB_KIND_LEGACY);
    // Spec 0044 G5: an unencrypted legacy blob needs no PIN.
    assert_eq!(s.store("doc", b"legacy", 0, PIV_PIN), YUBIBLOB_OK);
    let (data, verdict) = s.fetch_unencrypted("doc").unwrap();
    assert_eq!(data, b"legacy");
    assert_ne!(verdict, YUBIBLOB_SIGNATURE_CORRUPTED);
}
