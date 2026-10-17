// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! libyubiblob: a blob store on a YubiKey, for C and C++ programs (spec
//! 0039).
//!
//! The C interface over `yb-core`: list, fetch, store and remove named
//! blobs on a YubiKey set up with `yb format` (management key kept on the
//! YubiKey, unlocked by the PIN), with yb's guarantees (`docs/invariants/`).
//!
//! Conventions, for every function:
//! - it returns a `yubiblob_status_t`; results come through out
//!   parameters, written only on success;
//! - memory it returns is freed with the matching `yubiblob_*_free`;
//! - strings are UTF-8 and NUL-terminated;
//! - `yubiblob_last_error()` describes the calling thread's last failure;
//! - a panic never crosses the interface: it becomes
//!   `YUBIBLOB_ERR_INTERNAL`.

use std::cell::{Cell, RefCell};
use std::ffi::{c_char, c_void, CStr, CString};
use std::fmt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use p256::ecdsa::VerifyingKey;
use yb_core::errors::{render, CardError, PcscCode, RenderEnv};
use yb_core::orchestrator::{check_blob_signature, fetch_unencrypted, NoPinFetchError, SigVerdict};
use yb_core::report::StorePresence;
use yb_core::store::Store;
use yb_core::{
    context::OutputOptions, fetch_blob, list_blobs, parse_ec_public_key_from_cert_der,
    remove_blobs, store_blob, Compression, Context, ContextOptions, DevicePicker, Encryption,
    SecretOp, SlotKeyCheck, StoreOptions, Zeroizing,
};
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The interface's version: 0 until 1.0, where changes may break callers
/// between minor versions (spec 0039 G7).
pub const YUBIBLOB_ABI_VERSION: u32 = 0;

/// What a function returned.
pub type Status = i32;

pub const YUBIBLOB_OK: Status = 0;
/// No blob of that name.
pub const YUBIBLOB_ERR_NOT_FOUND: Status = 1;
/// Not enough free objects, found before writing anything.
pub const YUBIBLOB_ERR_STORE_FULL: Status = 2;
/// The card ran out of memory while writing; blobs keep their previous
/// content (invariant 0001).
pub const YUBIBLOB_ERR_CARD_FULL: Status = 3;
/// Wrong PIN; `yubiblob_last_pin_tries()` gives the tries left.
pub const YUBIBLOB_ERR_WRONG_PIN: Status = 4;
pub const YUBIBLOB_ERR_PIN_BLOCKED: Status = 5;
/// No YubiKey connected, or none with that serial number.
pub const YUBIBLOB_ERR_NO_DEVICE: Status = 6;
/// Several YubiKeys connected, and no serial number given.
pub const YUBIBLOB_ERR_SEVERAL_DEVICES: Status = 7;
/// The YubiKey is not set up for yb (`yb format`).
pub const YUBIBLOB_ERR_NO_STORE: Status = 8;
/// The YubiKey was removed during the call.
pub const YUBIBLOB_ERR_CARD_REMOVED: Status = 9;
/// The blob's signature does not verify (invariant 0006).
pub const YUBIBLOB_ERR_CORRUPTED: Status = 10;
/// Refused: factory PIN or PUK (spec 0024), unless allowed at open.
pub const YUBIBLOB_ERR_DEFAULT_CREDENTIALS: Status = 11;
/// A bad name, a NULL pointer, bad flags.
pub const YUBIBLOB_ERR_INVALID_ARGUMENT: Status = 12;
/// Anything else; see `yubiblob_last_error()`.
pub const YUBIBLOB_ERR_INTERNAL: Status = 13;
/// A post-quantum store: a blob's seal does not verify, or the management
/// key does not match (the PIV application may have been reset); nothing
/// was returned or written (spec 0028).
pub const YUBIBLOB_ERR_TAMPERED: Status = 14;
/// The YubiKey was not touched in time.
pub const YUBIBLOB_ERR_NO_TOUCH: Status = 15;
/// 3 FIDO2 PIN attempts or fewer left: not tried, unless the session was
/// opened with `YUBIBLOB_OPEN_ALLOW_LOW_PIN_ATTEMPTS`.
pub const YUBIBLOB_ERR_FEW_PIN_ATTEMPTS: Status = 16;
/// 3 wrong FIDO2 PINs in a row: unplug and replug the YubiKey.
pub const YUBIBLOB_ERR_REPLUG: Status = 17;
/// The store's FIDO2 credential is gone (FIDO2 reset).
pub const YUBIBLOB_ERR_NO_CREDENTIAL: Status = 18;
/// The FIDO2 side of the YubiKey cannot be found or opened (FIDO
/// application disabled, or no permission on the device).
pub const YUBIBLOB_ERR_NO_FIDO2_ACCESS: Status = 19;
/// `yubiblob_fetch_unencrypted`: the blob is encrypted, so it needs the
/// PIN (`yubiblob_fetch`); nothing was returned (spec 0044).
pub const YUBIBLOB_ERR_ENCRYPTED: Status = 20;

/// A blob's signature, as checked with the store's certificate.
pub type SignatureVerdict = i32;

pub const YUBIBLOB_SIGNATURE_VERIFIED: SignatureVerdict = 0;
/// Stored by a yb version before signatures.
pub const YUBIBLOB_SIGNATURE_UNSIGNED: SignatureVerdict = 1;
/// Not checkable here: no certificate to check it with, or a signature
/// version newer than this library knows.
pub const YUBIBLOB_SIGNATURE_UNVERIFIABLE: SignatureVerdict = 2;
pub const YUBIBLOB_SIGNATURE_CORRUPTED: SignatureVerdict = 3;
/// A blob of a post-quantum store whose checksum matches (spec 0028, D5):
/// not corrupted; its authenticity is checked when it is fetched.
pub const YUBIBLOB_SIGNATURE_CHECKSUM_OK: SignatureVerdict = 4;

/// `yubiblob_open` flag: allow writes with the factory PIN or PUK.
pub const YUBIBLOB_OPEN_ALLOW_DEFAULT_CREDENTIALS: u32 = 0x1;
/// `yubiblob_open` flag: try the FIDO2 PIN even with 3 attempts or fewer
/// left (post-quantum stores; a blocked FIDO2 PIN cannot be unblocked).
pub const YUBIBLOB_OPEN_ALLOW_LOW_PIN_ATTEMPTS: u32 = 0x2;

/// `StoreInfo.kind`: a legacy store, protected by PIV (the PIV PIN).
pub const YUBIBLOB_KIND_LEGACY: u32 = 0;
/// `StoreInfo.kind`: a post-quantum store, protected by FIDO2 (the FIDO2
/// PIN and a touch per blob; spec 0028).
pub const YUBIBLOB_KIND_POST_QUANTUM: u32 = 1;
/// `yubiblob_store` flag: encrypt to the store's key (recommended).
pub const YUBIBLOB_STORE_ENCRYPT: u32 = 0x1;
/// `yubiblob_store` flag: compress if it makes the blob smaller.
pub const YUBIBLOB_STORE_COMPRESS: u32 = 0x2;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A connected YubiKey.
#[repr(C)]
pub struct Device {
    pub serial: u32,
    /// Firmware version, e.g. "5.7.1".
    pub firmware: *mut c_char,
    /// Set up for yb (`yb format`).
    pub has_store: bool,
}

/// A blob, as listed without the PIN.
#[repr(C)]
pub struct BlobInfo {
    pub name: *mut c_char,
    /// Size of the content.
    pub size: u32,
    /// Size on the card (after compression and encryption).
    pub stored_size: u32,
    /// Modification time, Unix seconds.
    pub mtime: u32,
    /// Changes with every write of the blob: tells a changed blob exactly.
    pub generation: u32,
    pub encrypted: bool,
    pub signature: SignatureVerdict,
}

/// The store's room, in objects, and its kind, which tells which PIN to
/// ask for: `YUBIBLOB_KIND_LEGACY` (PIV PIN) or `YUBIBLOB_KIND_POST_QUANTUM`
/// (FIDO2 PIN).
#[repr(C)]
pub struct StoreInfo {
    pub object_count: u32,
    pub free_objects: u32,
    pub kind: u32,
}

/// A session on one YubiKey (opaque).
pub struct Session {
    ctx: Context,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

thread_local! {
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::default());
    static LAST_PIN_TRIES: Cell<i32> = const { Cell::new(-1) };
}

/// A failure, with its status and a message for people.
struct Failure {
    status: Status,
    message: String,
    pin_tries: Option<u8>,
}

type Outcome<T> = Result<T, Failure>;

fn fail(status: Status, message: impl Into<String>) -> Failure {
    Failure {
        status,
        message: message.into(),
        pin_tries: None,
    }
}

/// Raised by the device picker: several YubiKeys and no serial number.
#[derive(Debug)]
struct SeveralDevices;

impl fmt::Display for SeveralDevices {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("several YubiKeys are connected: give a serial number")
    }
}

impl std::error::Error for SeveralDevices {}

/// The status of a `yb-core` error: the card's answer when it tells one,
/// otherwise `default`.  The message is yb's, which names no serial
/// number, reader or secret (invariant 0011).
fn from_error(e: anyhow::Error, default: Status) -> Failure {
    let mut status = default;
    let mut pin_tries = None;
    for cause in e.chain() {
        if cause.downcast_ref::<SeveralDevices>().is_some() {
            status = YUBIBLOB_ERR_SEVERAL_DEVICES;
            break;
        }
        match cause.downcast_ref::<NoPinFetchError>() {
            Some(NoPinFetchError::Encrypted(_)) => {
                status = YUBIBLOB_ERR_ENCRYPTED;
                break;
            }
            Some(NoPinFetchError::Corrupted(_)) => {
                status = YUBIBLOB_ERR_CORRUPTED;
                break;
            }
            None => {}
        }
        #[cfg(not(windows))]
        if let Some(s) = post_quantum_status(cause) {
            status = s;
            break;
        }
        match cause.downcast_ref::<CardError>() {
            Some(CardError::Status { sw, .. }) if sw & 0xFFF0 == 0x63C0 => {
                status = YUBIBLOB_ERR_WRONG_PIN;
                pin_tries = Some((sw & 0x000F) as u8);
                break;
            }
            Some(CardError::Status { sw: 0x6983, .. }) => {
                status = YUBIBLOB_ERR_PIN_BLOCKED;
                break;
            }
            Some(CardError::Status { sw: 0x6A84, .. }) => {
                status = YUBIBLOB_ERR_CARD_FULL;
                break;
            }
            Some(CardError::Pcsc {
                code: PcscCode::RemovedCard | PcscCode::ResetCard,
                ..
            }) => {
                status = YUBIBLOB_ERR_CARD_REMOVED;
                break;
            }
            Some(CardError::Pcsc {
                code: PcscCode::NoReaders,
                ..
            }) => {
                status = YUBIBLOB_ERR_NO_DEVICE;
                break;
            }
            _ => {}
        }
    }
    let env = RenderEnv {
        firmware: None,
        yb_version: None,
    };
    Failure {
        status,
        message: render(&e, &env),
        pin_tries,
    }
}

/// The status of a post-quantum failure (spec 0028).
#[cfg(not(windows))]
fn post_quantum_status(cause: &(dyn std::error::Error + 'static)) -> Option<Status> {
    use yb_core::fido2::Fido2Error;
    use yb_core::orchestrator::post_quantum::IntegrityError;
    if let Some(e) = cause.downcast_ref::<IntegrityError>() {
        return Some(match e {
            IntegrityError::Corrupted(_) => YUBIBLOB_ERR_CORRUPTED,
            IntegrityError::SealFailed(_) | IntegrityError::ManagementKeyMismatch => {
                YUBIBLOB_ERR_TAMPERED
            }
        });
    }
    cause.downcast_ref::<Fido2Error>().map(|e| match e {
        Fido2Error::NoTouch => YUBIBLOB_ERR_NO_TOUCH,
        Fido2Error::PinInvalid => YUBIBLOB_ERR_WRONG_PIN,
        Fido2Error::PinAuthBlocked => YUBIBLOB_ERR_REPLUG,
        Fido2Error::PinBlocked => YUBIBLOB_ERR_PIN_BLOCKED,
        // A post-quantum store's YubiKey had a FIDO2 PIN: none means a
        // FIDO2 reset, which destroyed the credential too.
        Fido2Error::PinNotSet | Fido2Error::NoCredential => YUBIBLOB_ERR_NO_CREDENTIAL,
        Fido2Error::FewAttempts(_) => YUBIBLOB_ERR_FEW_PIN_ATTEMPTS,
        Fido2Error::NoDevice => YUBIBLOB_ERR_NO_FIDO2_ACCESS,
        Fido2Error::Other(_) => YUBIBLOB_ERR_INTERNAL,
    })
}

/// Run a function's body: record its failure for `yubiblob_last_error()`,
/// and turn a panic into `YUBIBLOB_ERR_INTERNAL`.
fn run(body: impl FnOnce() -> Outcome<()>) -> Status {
    let result = catch_unwind(AssertUnwindSafe(body)).unwrap_or_else(|_| {
        Err(fail(
            YUBIBLOB_ERR_INTERNAL,
            "internal error in libyubiblob (please report it)",
        ))
    });
    let (status, message, tries) = match result {
        Ok(()) => (YUBIBLOB_OK, String::new(), None),
        Err(f) => (f.status, f.message, f.pin_tries),
    };
    LAST_ERROR.with(|last| {
        *last.borrow_mut() = CString::new(message.replace('\0', " ")).unwrap_or_default();
    });
    LAST_PIN_TRIES.with(|last| last.set(tries.map_or(-1, i32::from)));
    status
}

// ---------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------

/// # Safety
/// `p` is NULL or a NUL-terminated string.
unsafe fn text<'a>(p: *const c_char, what: &str) -> Outcome<&'a str> {
    if p.is_null() {
        return Err(fail(
            YUBIBLOB_ERR_INVALID_ARGUMENT,
            format!("{what} is NULL"),
        ));
    }
    CStr::from_ptr(p).to_str().map_err(|_| {
        fail(
            YUBIBLOB_ERR_INVALID_ARGUMENT,
            format!("{what} is not UTF-8"),
        )
    })
}

/// # Safety
/// `p` is NULL with `len` 0, or points to `len` readable bytes.
unsafe fn bytes<'a>(p: *const u8, len: usize, what: &str) -> Outcome<&'a [u8]> {
    if len == 0 {
        return Ok(&[]);
    }
    if p.is_null() {
        return Err(fail(
            YUBIBLOB_ERR_INVALID_ARGUMENT,
            format!("{what} is NULL"),
        ));
    }
    Ok(std::slice::from_raw_parts(p, len))
}

/// The PIN, copied into zeroizing memory.
///
/// # Safety
/// As [`bytes`].
unsafe fn pin_text(p: *const u8, len: usize) -> Outcome<Zeroizing<String>> {
    let raw = bytes(p, len, "the PIN")?;
    if raw.is_empty() {
        return Err(fail(YUBIBLOB_ERR_INVALID_ARGUMENT, "the PIN is empty"));
    }
    let pin = Zeroizing::new(raw.to_vec());
    std::str::from_utf8(&pin)
        .map(|s| Zeroizing::new(s.to_owned()))
        .map_err(|_| fail(YUBIBLOB_ERR_INVALID_ARGUMENT, "the PIN is not UTF-8"))
}

/// # Safety
/// `p` is NULL or a valid pointer to a session from `yubiblob_open`.
unsafe fn session_ref<'a>(p: *mut Session) -> Outcome<&'a Session> {
    p.as_ref()
        .ok_or_else(|| fail(YUBIBLOB_ERR_INVALID_ARGUMENT, "the session is NULL"))
}

/// # Safety
/// `p` is NULL or a valid pointer to a session from `yubiblob_open`, not
/// used elsewhere during the call.
unsafe fn session_mut<'a>(p: *mut Session) -> Outcome<&'a mut Session> {
    p.as_mut()
        .ok_or_else(|| fail(YUBIBLOB_ERR_INVALID_ARGUMENT, "the session is NULL"))
}

fn not_null<T>(p: *mut T, what: &str) -> Outcome<()> {
    if p.is_null() {
        Err(fail(
            YUBIBLOB_ERR_INVALID_ARGUMENT,
            format!("{what} is NULL"),
        ))
    } else {
        Ok(())
    }
}

fn owned_text(s: &str) -> *mut c_char {
    CString::new(s.replace('\0', " "))
        .unwrap_or_default()
        .into_raw()
}

/// # Safety
/// `p` is NULL or came from [`owned_text`], and is freed once.
unsafe fn free_text(p: *mut c_char) {
    if !p.is_null() {
        drop(CString::from_raw(p));
    }
}

/// An array handed to the caller: (pointer, count); NULL when empty.
fn owned_array<T>(items: Vec<T>) -> (*mut T, usize) {
    if items.is_empty() {
        return (ptr::null_mut(), 0);
    }
    let count = items.len();
    (Box::into_raw(items.into_boxed_slice()).cast::<T>(), count)
}

/// # Safety
/// `p` and `count` came from [`owned_array`], and are freed once.
unsafe fn take_array<T>(p: *mut T, count: usize) -> Vec<T> {
    if p.is_null() || count == 0 {
        return Vec::new();
    }
    Box::from_raw(ptr::slice_from_raw_parts_mut(p, count)).into_vec()
}

// ---------------------------------------------------------------------------
// Session helpers
// ---------------------------------------------------------------------------

/// Holds the PIN in the session's context for one call, and forgets it,
/// with the management key read with it, when the call ends (G5).
struct PinScope<'a>(&'a Context);

impl<'a> PinScope<'a> {
    /// `pin` is the PIN of the store's kind: the FIDO2 PIN for a
    /// post-quantum store, never held as the PIV PIN (spec 0028, D10).
    fn new(ctx: &'a Context, pin: &str, post_quantum: bool) -> Self {
        if post_quantum {
            ctx.set_fido2_pin(pin);
        } else {
            ctx.set_pin(pin);
        }
        Self(ctx)
    }
}

impl Drop for PinScope<'_> {
    fn drop(&mut self) {
        self.0.clear_secrets();
    }
}

fn load_store(ctx: &Context) -> Outcome<Store> {
    Store::from_device(&ctx.reader, ctx.piv.as_ref())
        .map_err(|e| from_error(e, YUBIBLOB_ERR_NO_STORE))
}

fn verifying_key(ctx: &Context, store: &Store) -> Option<VerifyingKey> {
    let cert = ctx
        .piv
        .read_certificate(&ctx.reader, store.store_key_slot)
        .ok()?;
    let pk = parse_ec_public_key_from_cert_der(&cert).ok()?;
    Some(VerifyingKey::from(&pk))
}

/// The check without PIN: the signature (legacy stores) or the checksum
/// (post-quantum stores).
fn quick_check(
    head: &yb_core::store::Object,
    store: &Store,
    key: Option<&VerifyingKey>,
) -> SigVerdict {
    #[cfg(not(windows))]
    if store.kind.is_post_quantum() {
        return yb_core::orchestrator::post_quantum::quick_check(head, store);
    }
    check_blob_signature(head, store, key)
}

fn verdict(v: SigVerdict) -> SignatureVerdict {
    match v {
        SigVerdict::Verified => YUBIBLOB_SIGNATURE_VERIFIED,
        SigVerdict::Unsigned => YUBIBLOB_SIGNATURE_UNSIGNED,
        SigVerdict::Unverifiable | SigVerdict::NewerVersion => YUBIBLOB_SIGNATURE_UNVERIFIABLE,
        SigVerdict::Corrupted => YUBIBLOB_SIGNATURE_CORRUPTED,
        SigVerdict::ChecksumOk => YUBIBLOB_SIGNATURE_CHECKSUM_OK,
    }
}

/// Every blob of the store, as `BlobInfo` (names allocated).
fn blob_infos(ctx: &Context, store: &Store) -> Vec<BlobInfo> {
    let key = verifying_key(ctx, store);
    list_blobs(store)
        .into_iter()
        .filter_map(|b| {
            let head = store.find_head(&b.name)?;
            Some(BlobInfo {
                name: owned_text(&b.name),
                size: b.plain_size,
                stored_size: b.encrypted_size,
                mtime: b.mtime,
                generation: head.age(),
                encrypted: b.is_encrypted,
                signature: verdict(quick_check(head, store, key.as_ref())),
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Post-quantum stores (spec 0028): the FIDO2 PIN and one touch per blob
// ---------------------------------------------------------------------------

#[cfg(not(windows))]
mod post_quantum {
    use super::*;
    use yb_core::context::PostQuantumSession;
    use yb_core::orchestrator::{fetch_blob_with, store_blob_with};

    /// The FIDO2 side of the session's YubiKey, with the PIN (refused when
    /// few attempts are left, D10).
    fn session(ctx: &Context) -> Outcome<PostQuantumSession> {
        ctx.post_quantum_session()
            .map_err(|e| from_error(e, YUBIBLOB_ERR_INTERNAL))
    }

    /// A failure through `session`: a wrong FIDO2 PIN tells the attempts
    /// left, as a wrong PIV PIN does.
    fn failure(session: &PostQuantumSession, e: anyhow::Error) -> Failure {
        let mut f = from_error(e, YUBIBLOB_ERR_INTERNAL);
        if f.status == YUBIBLOB_ERR_WRONG_PIN {
            f.pin_tries = session
                .device
                .pin_retries()
                .ok()
                .map(|n| n.min(u32::from(u8::MAX)) as u8);
        }
        f
    }

    fn descriptor(store: &Store) -> Outcome<&yb_core::store::Descriptor> {
        store
            .descriptor()
            .ok_or_else(|| fail(YUBIBLOB_ERR_INTERNAL, "not a post-quantum store"))
    }

    pub(super) fn fetch(ctx: &Context, store: &Store, name: &str) -> Outcome<Vec<u8>> {
        let session = session(ctx)?;
        let protection = session.protection(ctx, descriptor(store)?);
        fetch_blob_with(store, &protection, name)
            .map_err(|e| failure(&session, e))?
            .ok_or_else(|| fail(YUBIBLOB_ERR_NOT_FOUND, format!("no blob named {name}")))
    }

    pub(super) fn store(
        ctx: &Context,
        store: &mut Store,
        name: &str,
        content: &[u8],
        encrypt: bool,
        compression: Compression,
    ) -> Outcome<bool> {
        let session = session(ctx)?;
        let descriptor = descriptor(store)?.clone();
        let protection = session.protection(ctx, &descriptor);
        store_blob_with(
            store,
            ctx.piv.as_ref(),
            &protection,
            name,
            content,
            encrypt,
            compression,
            None,
        )
        .map_err(|e| failure(&session, e))
    }

    /// The management key, checked against the card (D7, D11).
    pub(super) fn management_key(ctx: &Context, store: &Store) -> Outcome<Zeroizing<String>> {
        let session = session(ctx)?;
        session
            .protection(ctx, descriptor(store)?)
            .management_key()
            .map_err(|e| failure(&session, e))
    }
}

#[cfg(windows)]
mod post_quantum {
    use super::*;

    fn unsupported<T>() -> Outcome<T> {
        Err(fail(
            YUBIBLOB_ERR_INTERNAL,
            "post-quantum stores are not supported on Windows",
        ))
    }

    pub(super) fn fetch(_: &Context, _: &Store, _: &str) -> Outcome<Vec<u8>> {
        unsupported()
    }

    pub(super) fn store(
        _: &Context,
        _: &mut Store,
        _: &str,
        _: &[u8],
        _: bool,
        _: Compression,
    ) -> Outcome<bool> {
        unsupported()
    }

    pub(super) fn management_key(_: &Context, _: &Store) -> Outcome<Zeroizing<String>> {
        unsupported()
    }
}

// ---------------------------------------------------------------------------
// Version and errors
// ---------------------------------------------------------------------------

/// The interface's version (`YUBIBLOB_ABI_VERSION` of the library loaded).
#[no_mangle]
pub extern "C" fn yubiblob_abi_version() -> u32 {
    YUBIBLOB_ABI_VERSION
}

/// The library's version, e.g. "0.1.0" (static; not to be freed).
#[no_mangle]
pub extern "C" fn yubiblob_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

/// The calling thread's last failure, for people (English); empty after a
/// success.  Valid until the thread's next call into the library.
#[no_mangle]
pub extern "C" fn yubiblob_last_error() -> *const c_char {
    LAST_ERROR.with(|last| last.borrow().as_ptr())
}

/// After `YUBIBLOB_ERR_WRONG_PIN`: the PIN tries left; otherwise -1.
#[no_mangle]
pub extern "C" fn yubiblob_last_pin_tries() -> i32 {
    LAST_PIN_TRIES.with(Cell::get)
}

// ---------------------------------------------------------------------------
// Devices
// ---------------------------------------------------------------------------

/// The YubiKeys connected (none is not a failure).  No PIN.
///
/// # Safety
/// `devices` and `count` point to writable storage.
#[no_mangle]
pub unsafe extern "C" fn yubiblob_list_devices(
    devices: *mut *mut Device,
    count: *mut usize,
) -> Status {
    run(|| {
        not_null(devices, "devices")?;
        not_null(count, "count")?;
        let piv = yb_core::open_backend().map_err(|e| from_error(e, YUBIBLOB_ERR_INTERNAL))?;
        let found = match piv.list_devices() {
            Ok(found) => found,
            Err(e) => match from_error(e, YUBIBLOB_ERR_INTERNAL) {
                f if f.status == YUBIBLOB_ERR_NO_DEVICE => Vec::new(),
                f => return Err(f),
            },
        };
        let list: Vec<Device> = found
            .iter()
            .map(|d| Device {
                serial: d.serial,
                firmware: owned_text(&d.version),
                has_store: matches!(
                    StorePresence::probe(&d.reader, piv.as_ref()),
                    StorePresence::Present(_)
                ),
            })
            .collect();
        let (p, n) = owned_array(list);
        *devices = p;
        *count = n;
        Ok(())
    })
}

/// Free a list from `yubiblob_list_devices`.
///
/// # Safety
/// `devices` and `count` came from `yubiblob_list_devices`, freed once.
#[no_mangle]
pub unsafe extern "C" fn yubiblob_devices_free(devices: *mut Device, count: usize) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        for d in take_array(devices, count) {
            free_text(d.firmware);
        }
    }));
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

/// Open a session on the YubiKey `serial` (0: the only one connected).  No
/// PIN.  Fails with `YUBIBLOB_ERR_NO_STORE` on a YubiKey not set up for yb.
///
/// # Safety
/// `session` points to writable storage.
#[no_mangle]
pub unsafe extern "C" fn yubiblob_open(
    serial: u32,
    flags: u32,
    session: *mut *mut Session,
) -> Status {
    run(|| {
        not_null(session, "session")?;
        if flags & !(YUBIBLOB_OPEN_ALLOW_DEFAULT_CREDENTIALS | YUBIBLOB_OPEN_ALLOW_LOW_PIN_ATTEMPTS)
            != 0
        {
            return Err(fail(YUBIBLOB_ERR_INVALID_ARGUMENT, "unknown flags"));
        }
        let picker: DevicePicker = Box::new(|_, _| Err(SeveralDevices.into()));
        let mut ctx = Context::new(
            ContextOptions {
                serial: (serial != 0).then_some(serial),
                allow_defaults: flags & YUBIBLOB_OPEN_ALLOW_DEFAULT_CREDENTIALS != 0,
                ..ContextOptions::default()
            },
            Box::new(|| Ok(None)),
            picker,
            OutputOptions {
                debug: false,
                quiet: true,
            },
        )
        .map_err(|e| from_error(e, YUBIBLOB_ERR_NO_DEVICE))?;
        ctx.allow_low_pin_attempts = flags & YUBIBLOB_OPEN_ALLOW_LOW_PIN_ATTEMPTS != 0;
        match StorePresence::probe(&ctx.reader, ctx.piv.as_ref()) {
            StorePresence::Present(_) => {}
            StorePresence::None => {
                return Err(fail(
                    YUBIBLOB_ERR_NO_STORE,
                    "this YubiKey is not set up for yb (yb format)",
                ))
            }
            StorePresence::Unreadable(reason) => {
                return Err(fail(
                    YUBIBLOB_ERR_NO_STORE,
                    format!("the store is unreadable: {reason}"),
                ))
            }
        }
        *session = Box::into_raw(Box::new(Session { ctx }));
        Ok(())
    })
}

/// Close a session (NULL: nothing).
///
/// # Safety
/// `session` came from `yubiblob_open`, and is closed once.
#[no_mangle]
pub unsafe extern "C" fn yubiblob_close(session: *mut Session) {
    if !session.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| drop(Box::from_raw(session))));
    }
}

/// What `yubiblob_set_touch_callback` takes: called with `user` just
/// before the YubiKey waits for a touch.
pub type TouchCallback = Option<unsafe extern "C" fn(user: *mut c_void)>;

/// Be told when the YubiKey waits for a touch (post-quantum stores: one
/// touch per blob fetched or stored, and one per removal), e.g. to show
/// "Touch your YubiKey".  NULL removes the callback.  The callback runs on
/// the calling thread, during the call that needs the touch.
///
/// # Safety
/// `session` came from `yubiblob_open`; `callback`, if not NULL, is safe
/// to call with `user` while the session is open.
#[no_mangle]
pub unsafe extern "C" fn yubiblob_set_touch_callback(
    session: *mut Session,
    callback: TouchCallback,
    user: *mut c_void,
) -> Status {
    run(|| {
        let ctx = &mut session_mut(session)?.ctx;
        ctx.on_touch = match callback {
            Some(f) => {
                let user = user as usize;
                // SAFETY: the caller guarantees `f` may be called with `user`.
                Box::new(move || unsafe { f(user as *mut c_void) })
            }
            None => Box::new(|| {}),
        };
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// Listing (no PIN; reads never write, invariant 0002)
// ---------------------------------------------------------------------------

/// Every blob of the store.  No PIN.
///
/// # Safety
/// `session` came from `yubiblob_open`; `blobs` and `count` point to
/// writable storage.
#[no_mangle]
pub unsafe extern "C" fn yubiblob_list(
    session: *mut Session,
    blobs: *mut *mut BlobInfo,
    count: *mut usize,
) -> Status {
    run(|| {
        let ctx = &session_ref(session)?.ctx;
        not_null(blobs, "blobs")?;
        not_null(count, "count")?;
        let store = load_store(ctx)?;
        let (p, n) = owned_array(blob_infos(ctx, &store));
        *blobs = p;
        *count = n;
        Ok(())
    })
}

/// Free a list from `yubiblob_list`.
///
/// # Safety
/// `blobs` and `count` came from `yubiblob_list`, freed once.
#[no_mangle]
pub unsafe extern "C" fn yubiblob_blobs_free(blobs: *mut BlobInfo, count: usize) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        for b in take_array(blobs, count) {
            free_text(b.name);
        }
    }));
}

/// One blob, by name.  No PIN.  Free with `yubiblob_blob_info_clear`.
///
/// # Safety
/// `session` came from `yubiblob_open`; `name` is a string; `info` points
/// to writable storage.
#[no_mangle]
pub unsafe extern "C" fn yubiblob_stat(
    session: *mut Session,
    name: *const c_char,
    info: *mut BlobInfo,
) -> Status {
    run(|| {
        let ctx = &session_ref(session)?.ctx;
        let name = text(name, "the name")?;
        not_null(info, "info")?;
        let store = load_store(ctx)?;
        let mut found = None;
        for b in blob_infos(ctx, &store) {
            if found.is_none() && CStr::from_ptr(b.name).to_str() == Ok(name) {
                found = Some(b);
            } else {
                free_text(b.name);
            }
        }
        let found =
            found.ok_or_else(|| fail(YUBIBLOB_ERR_NOT_FOUND, format!("no blob named {name}")))?;
        info.write(found);
        Ok(())
    })
}

/// Free the name in a `yubiblob_blob_info_t` from `yubiblob_stat`.
///
/// # Safety
/// `info` is NULL or was filled by `yubiblob_stat`, cleared once.
#[no_mangle]
pub unsafe extern "C" fn yubiblob_blob_info_clear(info: *mut BlobInfo) {
    if let Some(info) = info.as_mut() {
        free_text(info.name);
        info.name = ptr::null_mut();
    }
}

/// The store's room, in objects.  No PIN.
///
/// # Safety
/// `session` came from `yubiblob_open`; `info` points to writable storage.
#[no_mangle]
pub unsafe extern "C" fn yubiblob_store_info(
    session: *mut Session,
    info: *mut StoreInfo,
) -> Status {
    run(|| {
        let ctx = &session_ref(session)?.ctx;
        not_null(info, "info")?;
        let store = load_store(ctx)?;
        info.write(StoreInfo {
            object_count: u32::from(store.object_count),
            free_objects: store.free_count() as u32,
            kind: if store.kind.is_post_quantum() {
                YUBIBLOB_KIND_POST_QUANTUM
            } else {
                YUBIBLOB_KIND_LEGACY
            },
        });
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// Content (with the PIN)
// ---------------------------------------------------------------------------

/// A blob's content, after its signature is checked (spec 0033): a
/// corrupted blob returns nothing.  Free with `yubiblob_buffer_free`.
///
/// # Safety
/// `session` came from `yubiblob_open`; `name` is a string; `pin` points
/// to `pin_len` bytes; `data` and `len` point to writable storage.
#[no_mangle]
pub unsafe extern "C" fn yubiblob_fetch(
    session: *mut Session,
    name: *const c_char,
    pin: *const u8,
    pin_len: usize,
    data: *mut *mut u8,
    len: *mut usize,
) -> Status {
    run(|| {
        let ctx = &session_ref(session)?.ctx;
        let name = text(name, "the name")?;
        let pin = pin_text(pin, pin_len)?;
        not_null(data, "data")?;
        not_null(len, "len")?;
        let store = load_store(ctx)?;
        let post_quantum = store.kind.is_post_quantum();
        let _scope = PinScope::new(ctx, &pin, post_quantum);
        let head = store
            .find_head(name)
            .ok_or_else(|| fail(YUBIBLOB_ERR_NOT_FOUND, format!("no blob named {name}")))?;
        let key = verifying_key(ctx, &store);
        if quick_check(head, &store, key.as_ref()) == SigVerdict::Corrupted {
            let why = if post_quantum {
                "its checksum does not match"
            } else {
                "its signature does not verify"
            };
            return Err(fail(
                YUBIBLOB_ERR_CORRUPTED,
                format!("{name} is corrupted or was tampered with: {why}"),
            ));
        }
        let content = if post_quantum {
            post_quantum::fetch(ctx, &store, name)?
        } else {
            fetch_blob(
                &store,
                ctx.piv.as_ref(),
                &ctx.reader,
                name,
                Some(&pin),
                false,
            )
            .map_err(|e| from_error(e, YUBIBLOB_ERR_INTERNAL))?
            .ok_or_else(|| fail(YUBIBLOB_ERR_NOT_FOUND, format!("no blob named {name}")))?
        };
        let content = content.into_boxed_slice();
        *len = content.len();
        *data = Box::into_raw(content).cast::<u8>();
        Ok(())
    })
}

/// An unencrypted blob's content, without any PIN or touch (spec 0044):
/// for a YubiKey whose PIN is blocked, or whose FIDO2 application was reset.
/// - Legacy stores: the signature is checked, as by `yubiblob_fetch`.
/// - Post-quantum stores: only the checksum is checked, not the seal nor
///   the management key.  Corruption is detected, forgery is not: use it
///   only for content with its own integrity check (e.g. a KDBX 4
///   database), or with the user's consent.
///
/// `*verdict` tells which check passed (`YUBIBLOB_SIGNATURE_VERIFIED`,
/// `..._UNSIGNED`, `..._UNVERIFIABLE` or `..._CHECKSUM_OK`).  An encrypted
/// blob fails with `YUBIBLOB_ERR_ENCRYPTED`, returning nothing.  Free
/// `*data` with `yubiblob_buffer_free`.
///
/// # Safety
/// `session` came from `yubiblob_open`; `name` is a string; `data`, `len`
/// and `verdict` point to writable storage.
#[no_mangle]
pub unsafe extern "C" fn yubiblob_fetch_unencrypted(
    session: *mut Session,
    name: *const c_char,
    data: *mut *mut u8,
    len: *mut usize,
    verdict: *mut SignatureVerdict,
) -> Status {
    run(|| {
        let ctx = &session_ref(session)?.ctx;
        let name = text(name, "the name")?;
        not_null(data, "data")?;
        not_null(len, "len")?;
        not_null(verdict, "verdict")?;
        let store = load_store(ctx)?;
        let (content, v) = fetch_unencrypted(&store, ctx.piv.as_ref(), &ctx.reader, name)
            .map_err(|e| from_error(e, YUBIBLOB_ERR_INTERNAL))?
            .ok_or_else(|| fail(YUBIBLOB_ERR_NOT_FOUND, format!("no blob named {name}")))?;
        let content = content.into_boxed_slice();
        *len = content.len();
        *data = Box::into_raw(content).cast::<u8>();
        *verdict = self::verdict(v);
        Ok(())
    })
}

/// Free (and overwrite) content from `yubiblob_fetch` or
/// `yubiblob_fetch_unencrypted`.
///
/// # Safety
/// `data` and `len` came from one of them, freed once.
#[no_mangle]
pub unsafe extern "C" fn yubiblob_buffer_free(data: *mut u8, len: usize) {
    if data.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let mut content = Box::from_raw(ptr::slice_from_raw_parts_mut(data, len));
        content.zeroize();
    }));
}

/// Store a blob: the new copy is written before the old one is freed
/// (invariant 0001).  Fails, writing nothing, with
/// `YUBIBLOB_ERR_STORE_FULL` if the store lacks free objects.
///
/// # Safety
/// `session` came from `yubiblob_open`; `name` is a string; `data`
/// points to `len` bytes; `pin` points to `pin_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn yubiblob_store(
    session: *mut Session,
    name: *const c_char,
    data: *const u8,
    len: usize,
    flags: u32,
    pin: *const u8,
    pin_len: usize,
) -> Status {
    run(|| {
        let ctx = &session_ref(session)?.ctx;
        let name = text(name, "the name")?;
        let content = bytes(data, len, "the data")?;
        let pin = pin_text(pin, pin_len)?;
        if flags & !(YUBIBLOB_STORE_ENCRYPT | YUBIBLOB_STORE_COMPRESS) != 0 {
            return Err(fail(YUBIBLOB_ERR_INVALID_ARGUMENT, "unknown flags"));
        }
        let compression = if flags & YUBIBLOB_STORE_COMPRESS != 0 {
            Compression::Auto
        } else {
            Compression::None
        };
        let mut store = load_store(ctx)?;
        let post_quantum = store.kind.is_post_quantum();
        let _scope = PinScope::new(ctx, &pin, post_quantum);

        let stored = if post_quantum {
            post_quantum::store(
                ctx,
                &mut store,
                name,
                content,
                flags & YUBIBLOB_STORE_ENCRYPT != 0,
                compression,
            )?
        } else {
            store_legacy(ctx, &mut store, name, content, flags, compression, &pin)?
        };
        if !stored {
            return Err(fail(
                YUBIBLOB_ERR_STORE_FULL,
                format!("not enough free objects to store {name}; nothing was written"),
            ));
        }
        if !post_quantum {
            ctx.complete_pending_repairs();
        }
        Ok(())
    })
}

/// Store into a legacy store: the PIV credentials' policy (spec 0024), the
/// slot's key checked (invariant 0008).
fn store_legacy(
    ctx: &Context,
    store: &mut Store,
    name: &str,
    content: &[u8],
    flags: u32,
    compression: Compression,
    pin: &str,
) -> Outcome<bool> {
    ctx.enforce_default_policy(SecretOp::Store)
        .map_err(|e| from_error(e, YUBIBLOB_ERR_DEFAULT_CREDENTIALS))?;
    let slot = store.store_key_slot;
    // New blobs are always decryptable (invariant 0008).
    if ctx
        .check_slot_key(slot)
        .map_err(|e| from_error(e, YUBIBLOB_ERR_INTERNAL))?
        == SlotKeyCheck::Mismatch
    {
        return Err(fail(
            YUBIBLOB_ERR_INTERNAL,
            format!(
                "the key in slot 0x{slot:02x} does not match its certificate; nothing was stored"
            ),
        ));
    }
    let peer = if flags & YUBIBLOB_STORE_ENCRYPT != 0 {
        Some(
            ctx.get_public_key(slot)
                .map_err(|e| from_error(e, YUBIBLOB_ERR_INTERNAL))?,
        )
    } else {
        None
    };
    let management_key = ctx
        .management_key_for_write()
        .map_err(|e| from_error(e, YUBIBLOB_ERR_INTERNAL))?;
    let options = StoreOptions {
        encryption: match peer.as_ref() {
            Some(pk) => Encryption::Encrypted(pk),
            None => Encryption::None,
        },
        compression,
    };
    store_blob(
        store,
        ctx.piv.as_ref(),
        name,
        content,
        options,
        &management_key,
        Some(pin),
    )
    .map_err(|e| from_error(e, YUBIBLOB_ERR_INTERNAL))
}

/// Remove a blob.
///
/// # Safety
/// `session` came from `yubiblob_open`; `name` is a string; `pin` points
/// to `pin_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn yubiblob_remove(
    session: *mut Session,
    name: *const c_char,
    pin: *const u8,
    pin_len: usize,
) -> Status {
    run(|| {
        let ctx = &session_ref(session)?.ctx;
        let name = text(name, "the name")?;
        let pin = pin_text(pin, pin_len)?;
        let mut store = load_store(ctx)?;
        let post_quantum = store.kind.is_post_quantum();
        let _scope = PinScope::new(ctx, &pin, post_quantum);
        if store.find_head(name).is_none() {
            return Err(fail(
                YUBIBLOB_ERR_NOT_FOUND,
                format!("no blob named {name}"),
            ));
        }
        let management_key = if post_quantum {
            post_quantum::management_key(ctx, &store)?
        } else {
            ctx.management_key_for_write()
                .map_err(|e| from_error(e, YUBIBLOB_ERR_INTERNAL))?
        };
        remove_blobs(&mut store, ctx.piv.as_ref(), &[name], &management_key)
            .map_err(|e| from_error(e, YUBIBLOB_ERR_INTERNAL))?;
        if !post_quantum {
            ctx.complete_pending_repairs();
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use yb_core::errors::{CardOp, PcscOp};

    fn status_of(e: anyhow::Error) -> (Status, Option<u8>) {
        let f = from_error(e, YUBIBLOB_ERR_INTERNAL);
        (f.status, f.pin_tries)
    }

    /// The card's answers become status codes (spec 0039 G3), whatever
    /// context wraps them.
    #[test]
    fn card_answers_become_status_codes() {
        let card = |sw1, sw2| anyhow::Error::from(CardError::status(CardOp::VerifyPin, sw1, sw2));
        assert_eq!(
            status_of(card(0x63, 0xC2)),
            (YUBIBLOB_ERR_WRONG_PIN, Some(2))
        );
        assert_eq!(
            status_of(card(0x69, 0x83)),
            (YUBIBLOB_ERR_PIN_BLOCKED, None)
        );
        let full = CardError::status(CardOp::WriteObject(0x5F_0003), 0x6A, 0x84);
        let wrapped = anyhow::Error::from(full).context("the store may be partially updated");
        assert_eq!(status_of(wrapped), (YUBIBLOB_ERR_CARD_FULL, None));
        let pcsc = |code| {
            anyhow::Error::from(CardError::Pcsc {
                op: PcscOp::Transmit,
                code,
            })
        };
        assert_eq!(
            status_of(pcsc(PcscCode::RemovedCard)).0,
            YUBIBLOB_ERR_CARD_REMOVED
        );
        assert_eq!(
            status_of(pcsc(PcscCode::NoReaders)).0,
            YUBIBLOB_ERR_NO_DEVICE
        );
        assert_eq!(
            status_of(SeveralDevices.into()).0,
            YUBIBLOB_ERR_SEVERAL_DEVICES
        );
        assert_eq!(status_of(anyhow::anyhow!("other")).0, YUBIBLOB_ERR_INTERNAL);
    }

    /// A panic never crosses the interface (spec 0039).
    #[test]
    fn a_panic_becomes_an_internal_error() {
        let status = run(|| panic!("boom"));
        assert_eq!(status, YUBIBLOB_ERR_INTERNAL);
        let message = unsafe { CStr::from_ptr(yubiblob_last_error()) };
        assert!(message.to_str().unwrap().contains("internal error"));
        assert_eq!(run(|| Ok(())), YUBIBLOB_OK);
        assert!(unsafe { CStr::from_ptr(yubiblob_last_error()) }.is_empty());
    }
}
