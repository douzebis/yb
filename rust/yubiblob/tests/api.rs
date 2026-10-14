// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Spec 0039: libyubiblob through its C functions, on simulated YubiKeys
//! (`YB_FIXTURE`, a file each test prepares as `yb format` would).

use std::ffi::{CStr, CString};
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::Mutex;

use tempfile::TempDir;
use yb_core::auxiliaries::{
    enable_pin_protected_management_key, generate_random_management_key, KeySwitch,
};
use yb_core::piv::virtual_piv::fixtures;
use yb_core::store::Store;
use yb_core::{PivBackend, VirtualPiv};
use yubiblob::*;

const FACTORY_KEY: &str = "010203040506070801020304050607080102030405060708";
const PIN: &[u8] = b"654321";

/// `YB_FIXTURE` is process-wide: one test at a time sets it and opens.
static FIXTURE: Mutex<()> = Mutex::new(());

/// A YubiKey as `yb format` leaves it: a certificate in slot 0x82, a store
/// of `objects` objects, the management key kept on the YubiKey behind the
/// PIN.  `before_save` may change the card further.
fn card(
    dir: &TempDir,
    yaml: &str,
    pin: &str,
    objects: u8,
    before_save: impl FnOnce(&VirtualPiv),
) -> PathBuf {
    let piv = VirtualPiv::from_fixture_yaml(yaml).unwrap();
    let reader = piv.reader_name();
    piv.generate_key(&reader, 0x82, Some(FACTORY_KEY)).unwrap();
    piv.generate_certificate(&reader, 0x82, "CN=Test", FACTORY_KEY, None)
        .unwrap();
    Store::format(&reader, &piv, objects, 0x82, FACTORY_KEY).unwrap();
    piv.verify_pin(&reader, pin).unwrap();
    let algo = piv.management_key_algorithm(&reader).unwrap();
    let new_key = generate_random_management_key(algo);
    enable_pin_protected_management_key(
        &reader,
        &piv,
        &KeySwitch {
            old_key: FACTORY_KEY,
            old_key_in_printed: false,
            new_key: &new_key,
            algo,
            clearing_legacy_flag: false,
        },
    )
    .unwrap();
    before_save(&piv);
    let path = dir.path().join("card.yaml");
    piv.save_fixture(&path).unwrap();
    path
}

fn standard_card(dir: &TempDir) -> PathBuf {
    card(dir, fixtures::WITH_KEY, "654321", 16, |_| {})
}

fn last_error() -> String {
    unsafe { CStr::from_ptr(yubiblob_last_error()) }
        .to_string_lossy()
        .into_owned()
}

/// Open a session on the simulated YubiKey in `path`.
fn open(path: &Path, flags: u32) -> Result<*mut yubiblob::Session, Status> {
    let _lock = FIXTURE.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("YB_FIXTURE", path);
    let mut session = ptr::null_mut();
    match unsafe { yubiblob_open(0, flags, &mut session) } {
        YUBIBLOB_OK => Ok(session),
        status => Err(status),
    }
}

fn store(s: *mut yubiblob::Session, name: &str, data: &[u8], flags: u32, pin: &[u8]) -> Status {
    let name = CString::new(name).unwrap();
    unsafe {
        yubiblob_store(
            s,
            name.as_ptr(),
            data.as_ptr(),
            data.len(),
            flags,
            pin.as_ptr(),
            pin.len(),
        )
    }
}

fn fetch(s: *mut yubiblob::Session, name: &str, pin: &[u8]) -> Result<Vec<u8>, Status> {
    let name = CString::new(name).unwrap();
    let (mut data, mut len) = (ptr::null_mut(), 0usize);
    let status = unsafe {
        yubiblob_fetch(
            s,
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

struct Listed {
    name: String,
    size: u32,
    generation: u32,
    encrypted: bool,
    signature: SignatureVerdict,
}

fn list(s: *mut yubiblob::Session) -> Vec<Listed> {
    let (mut blobs, mut count) = (ptr::null_mut(), 0usize);
    assert_eq!(
        unsafe { yubiblob_list(s, &mut blobs, &mut count) },
        YUBIBLOB_OK,
        "{}",
        last_error()
    );
    let listed = (0..count)
        .map(|i| {
            let b = unsafe { &*blobs.add(i) };
            Listed {
                name: unsafe { CStr::from_ptr(b.name) }
                    .to_string_lossy()
                    .into_owned(),
                size: b.size,
                generation: b.generation,
                encrypted: b.encrypted,
                signature: b.signature,
            }
        })
        .collect();
    unsafe { yubiblob_blobs_free(blobs, count) };
    listed
}

const ENCRYPTED: u32 = YUBIBLOB_STORE_ENCRYPT | YUBIBLOB_STORE_COMPRESS;

#[test]
fn version() {
    assert_eq!(yubiblob_abi_version(), YUBIBLOB_ABI_VERSION);
    let v = unsafe { CStr::from_ptr(yubiblob_version()) };
    assert_eq!(v.to_str().unwrap(), env!("CARGO_PKG_VERSION"));
}

#[test]
fn list_devices() {
    let dir = TempDir::new().unwrap();
    let path = standard_card(&dir);
    let _lock = FIXTURE.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("YB_FIXTURE", &path);
    let (mut devices, mut count) = (ptr::null_mut(), 0usize);
    assert_eq!(
        unsafe { yubiblob_list_devices(&mut devices, &mut count) },
        YUBIBLOB_OK
    );
    assert_eq!(count, 1);
    let d = unsafe { &*devices };
    assert_eq!(d.serial, 88_888_888);
    assert!(d.has_store);
    assert_eq!(
        unsafe { CStr::from_ptr(d.firmware) }.to_str().unwrap(),
        "5.4.3"
    );
    unsafe { yubiblob_devices_free(devices, count) };
}

/// Store, list, stat, fetch, remove: the round trip, the generation
/// changing with each store (G4), the signature verified.
#[test]
fn store_list_fetch_remove() {
    let dir = TempDir::new().unwrap();
    let s = open(&standard_card(&dir), 0).unwrap();

    assert_eq!(
        store(s, "vault.kdbx", b"first version", ENCRYPTED, PIN),
        YUBIBLOB_OK,
        "{}",
        last_error()
    );
    let first = list(s);
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].name, "vault.kdbx");
    assert_eq!(first[0].size, 13);
    assert!(first[0].encrypted);
    assert_eq!(first[0].signature, YUBIBLOB_SIGNATURE_VERIFIED);
    assert_eq!(fetch(s, "vault.kdbx", PIN).unwrap(), b"first version");

    assert_eq!(
        store(s, "vault.kdbx", b"second", ENCRYPTED, PIN),
        YUBIBLOB_OK
    );
    let second = list(s);
    assert_ne!(second[0].generation, first[0].generation);
    assert_eq!(fetch(s, "vault.kdbx", PIN).unwrap(), b"second");

    let name = CString::new("vault.kdbx").unwrap();
    let mut info = unsafe { std::mem::zeroed::<yubiblob::BlobInfo>() };
    assert_eq!(
        unsafe { yubiblob_stat(s, name.as_ptr(), &mut info) },
        YUBIBLOB_OK
    );
    assert_eq!(info.generation, second[0].generation);
    unsafe { yubiblob_blob_info_clear(&mut info) };
    assert!(info.name.is_null());

    let mut room = yubiblob::StoreInfo {
        object_count: 0,
        free_objects: 0,
    };
    assert_eq!(unsafe { yubiblob_store_info(s, &mut room) }, YUBIBLOB_OK);
    assert_eq!(room.object_count, 16);
    assert!(room.free_objects < 16);

    assert_eq!(
        unsafe { yubiblob_remove(s, name.as_ptr(), PIN.as_ptr(), PIN.len()) },
        YUBIBLOB_OK
    );
    assert!(list(s).is_empty());
    unsafe { yubiblob_close(s) };
}

#[test]
fn unencrypted_blob() {
    let dir = TempDir::new().unwrap();
    let s = open(&standard_card(&dir), 0).unwrap();
    assert_eq!(store(s, "note", b"plain", 0, PIN), YUBIBLOB_OK);
    assert!(!list(s)[0].encrypted);
    assert_eq!(fetch(s, "note", PIN).unwrap(), b"plain");
    unsafe { yubiblob_close(s) };
}

#[test]
fn not_found() {
    let dir = TempDir::new().unwrap();
    let s = open(&standard_card(&dir), 0).unwrap();
    let name = CString::new("missing").unwrap();
    let mut info = unsafe { std::mem::zeroed::<yubiblob::BlobInfo>() };
    assert_eq!(
        unsafe { yubiblob_stat(s, name.as_ptr(), &mut info) },
        YUBIBLOB_ERR_NOT_FOUND
    );
    assert_eq!(fetch(s, "missing", PIN), Err(YUBIBLOB_ERR_NOT_FOUND));
    assert_eq!(
        unsafe { yubiblob_remove(s, name.as_ptr(), PIN.as_ptr(), PIN.len()) },
        YUBIBLOB_ERR_NOT_FOUND
    );
    unsafe { yubiblob_close(s) };
}

/// A wrong PIN is a wrong PIN, with the tries left; nothing is written.
#[test]
fn wrong_pin() {
    let dir = TempDir::new().unwrap();
    let s = open(&standard_card(&dir), 0).unwrap();
    assert_eq!(
        store(s, "x", b"data", ENCRYPTED, b"000000"),
        YUBIBLOB_ERR_WRONG_PIN
    );
    assert_eq!(yubiblob_last_pin_tries(), 2);
    assert!(!last_error().is_empty());
    assert!(list(s).is_empty());

    assert_eq!(store(s, "x", b"data", ENCRYPTED, PIN), YUBIBLOB_OK);
    assert_eq!(fetch(s, "x", b"000000"), Err(YUBIBLOB_ERR_WRONG_PIN));
    assert_eq!(yubiblob_last_pin_tries(), 2);
    unsafe { yubiblob_close(s) };
}

/// Not enough free objects: refused before anything is written.
#[test]
fn store_full_writes_nothing() {
    let dir = TempDir::new().unwrap();
    let s = open(&card(&dir, fixtures::WITH_KEY, "654321", 4, |_| {}), 0).unwrap();
    let big = vec![0x5A_u8; 20_000];
    assert_eq!(
        store(s, "big", &big, YUBIBLOB_STORE_ENCRYPT, PIN),
        YUBIBLOB_ERR_STORE_FULL
    );
    assert!(list(s).is_empty());
    unsafe { yubiblob_close(s) };
}

/// A tampered blob is CORRUPTED, and its content is not returned.
#[test]
fn corrupted_blob_is_not_fetched() {
    let dir = TempDir::new().unwrap();
    let path = card(&dir, fixtures::WITH_KEY, "654321", 16, |piv| {
        let reader = piv.reader_name();
        let mut store = Store::from_device(&reader, piv).unwrap();
        // Unencrypted, so that the stored bytes hold the payload as is.
        let printed = yb_core::auxiliaries::read_printed_keys(&reader, piv, "654321").unwrap();
        let key = printed.current.unwrap();
        let options = yb_core::StoreOptions {
            encryption: yb_core::Encryption::None,
            compression: yb_core::Compression::None,
        };
        assert!(yb_core::store_blob(
            &mut store,
            piv,
            "x",
            b"payload",
            options,
            &key,
            Some("654321")
        )
        .unwrap());
        let head = store.find_head("x").unwrap().index();
        let id = 0x5F_0000 + u32::from(head);
        let mut raw = piv.read_object(&reader, id).unwrap();
        let at = raw.windows(7).position(|w| w == b"payload").unwrap();
        raw[at] ^= 0x01;
        piv.write_object(&reader, id, &raw, &key).unwrap();
    });
    let s = open(&path, 0).unwrap();
    assert_eq!(list(s)[0].signature, YUBIBLOB_SIGNATURE_CORRUPTED);
    assert_eq!(fetch(s, "x", PIN), Err(YUBIBLOB_ERR_CORRUPTED));
    unsafe { yubiblob_close(s) };
}

/// Factory PIN: writes refused unless allowed at open (spec 0024).
#[test]
fn default_credentials() {
    let dir = TempDir::new().unwrap();
    let path = card(&dir, fixtures::DEFAULT, "123456", 16, |_| {});
    let s = open(&path, 0).unwrap();
    assert_eq!(
        store(s, "x", b"data", ENCRYPTED, b"123456"),
        YUBIBLOB_ERR_DEFAULT_CREDENTIALS
    );
    unsafe { yubiblob_close(s) };
    let s = open(&path, YUBIBLOB_OPEN_ALLOW_DEFAULT_CREDENTIALS).unwrap();
    assert_eq!(
        store(s, "x", b"data", ENCRYPTED, b"123456"),
        YUBIBLOB_OK,
        "{}",
        last_error()
    );
    unsafe { yubiblob_close(s) };
}

/// A YubiKey without a store is reported as such.
#[test]
fn no_store() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("card.yaml");
    VirtualPiv::from_fixture_yaml(fixtures::WITH_KEY)
        .unwrap()
        .save_fixture(&path)
        .unwrap();
    assert_eq!(open(&path, 0).err(), Some(YUBIBLOB_ERR_NO_STORE));
}

#[test]
fn invalid_arguments() {
    let dir = TempDir::new().unwrap();
    let s = open(&standard_card(&dir), 0).unwrap();
    let status =
        unsafe { yubiblob_store(s, ptr::null(), ptr::null(), 0, 0, PIN.as_ptr(), PIN.len()) };
    assert_eq!(status, YUBIBLOB_ERR_INVALID_ARGUMENT);
    assert_eq!(
        store(s, "x", b"data", 0x80, PIN),
        YUBIBLOB_ERR_INVALID_ARGUMENT
    );
    assert_eq!(
        store(s, "x", b"data", 0, b""),
        YUBIBLOB_ERR_INVALID_ARGUMENT
    );
    let mut session = ptr::null_mut();
    assert_eq!(
        unsafe { yubiblob_open(0, 0x80, &mut session) },
        YUBIBLOB_ERR_INVALID_ARGUMENT
    );
    assert_eq!(
        unsafe { yubiblob_list(ptr::null_mut(), ptr::null_mut(), ptr::null_mut()) },
        YUBIBLOB_ERR_INVALID_ARGUMENT
    );
    unsafe { yubiblob_close(s) };
    // Freeing NULL is a no-op.
    unsafe {
        yubiblob_close(ptr::null_mut());
        yubiblob_buffer_free(ptr::null_mut(), 0);
        yubiblob_blobs_free(ptr::null_mut(), 0);
        yubiblob_devices_free(ptr::null_mut(), 0);
        yubiblob_blob_info_clear(ptr::null_mut());
    }
}
