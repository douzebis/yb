// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Proof of concept: OpenSK as an in-process FIDO2 authenticator, driven
//! through the real libfido2 (custom I/O functions), replaying the YubiKey
//! hardware results of spec 0028.

use opensk::Ctap;
use opensk::Transport;
use opensk::api::persist::Persist;
use opensk::api::user_presence::UserPresenceError;
use opensk::env::Env;
use opensk::env::test::TestEnv;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::rc::Rc;

// ---------------------------------------------------------------- libfido2 FFI
#[repr(C)]
struct FidoDevIo {
    open: extern "C" fn(*const c_char) -> *mut c_void,
    close: extern "C" fn(*mut c_void),
    read: extern "C" fn(*mut c_void, *mut u8, usize, c_int) -> c_int,
    write: extern "C" fn(*mut c_void, *const u8, usize) -> c_int,
}
type Dev = c_void;
type Cred = c_void;
type Assert = c_void;
type Pk = c_void;
const OPT_OMIT: c_int = 0;
const OPT_FALSE: c_int = 1;
const OPT_TRUE: c_int = 2;
const EXT_HMAC_SECRET: c_int = 0x01;
const CRED_PROT_UV_REQUIRED: c_int = 0x03;
const COSE_ES256: c_int = -7;

unsafe extern "C" {
    fn fido_init(flags: c_int);
    fn fido_strerr(err: c_int) -> *const c_char;
    fn fido_dev_new() -> *mut Dev;
    fn fido_dev_free(dev: *mut *mut Dev);
    fn fido_dev_set_io_functions(dev: *mut Dev, io: *const FidoDevIo) -> c_int;
    fn fido_dev_open(dev: *mut Dev, path: *const c_char) -> c_int;
    fn fido_dev_close(dev: *mut Dev) -> c_int;
    fn fido_dev_set_pin(dev: *mut Dev, pin: *const c_char, oldpin: *const c_char) -> c_int;
    fn fido_dev_get_retry_count(dev: *mut Dev, retries: *mut c_int) -> c_int;
    fn fido_cred_new() -> *mut Cred;
    fn fido_cred_free(c: *mut *mut Cred);
    fn fido_cred_set_type(c: *mut Cred, t: c_int) -> c_int;
    fn fido_cred_set_clientdata_hash(c: *mut Cred, p: *const u8, n: usize) -> c_int;
    fn fido_cred_set_rp(c: *mut Cred, id: *const c_char, name: *const c_char) -> c_int;
    fn fido_cred_set_user(c: *mut Cred, id: *const u8, n: usize, name: *const c_char,
        display: *const c_char, icon: *const c_char) -> c_int;
    fn fido_cred_set_rk(c: *mut Cred, o: c_int) -> c_int;
    fn fido_cred_set_extensions(c: *mut Cred, e: c_int) -> c_int;
    fn fido_cred_set_prot(c: *mut Cred, p: c_int) -> c_int;
    fn fido_dev_make_cred(dev: *mut Dev, c: *mut Cred, pin: *const c_char) -> c_int;
    fn fido_cred_id_ptr(c: *const Cred) -> *const u8;
    fn fido_cred_id_len(c: *const Cred) -> usize;
    fn fido_cred_pubkey_ptr(c: *const Cred) -> *const u8;
    fn fido_cred_pubkey_len(c: *const Cred) -> usize;
    fn fido_assert_new() -> *mut Assert;
    fn fido_assert_free(a: *mut *mut Assert);
    fn fido_assert_set_rp(a: *mut Assert, id: *const c_char) -> c_int;
    fn fido_assert_set_clientdata_hash(a: *mut Assert, p: *const u8, n: usize) -> c_int;
    fn fido_assert_allow_cred(a: *mut Assert, p: *const u8, n: usize) -> c_int;
    fn fido_assert_set_extensions(a: *mut Assert, e: c_int) -> c_int;
    fn fido_assert_set_hmac_salt(a: *mut Assert, p: *const u8, n: usize) -> c_int;
    fn fido_assert_set_up(a: *mut Assert, o: c_int) -> c_int;
    fn fido_assert_set_uv(a: *mut Assert, o: c_int) -> c_int;
    fn fido_dev_get_assert(dev: *mut Dev, a: *mut Assert, pin: *const c_char) -> c_int;
    fn fido_assert_hmac_secret_ptr(a: *const Assert, i: usize) -> *const u8;
    fn fido_assert_hmac_secret_len(a: *const Assert, i: usize) -> usize;
    fn fido_assert_flags(a: *const Assert, i: usize) -> u8;
    fn fido_assert_sigcount(a: *const Assert, i: usize) -> u32;
    fn fido_assert_verify(a: *const Assert, i: usize, alg: c_int, pk: *const Pk) -> c_int;
    fn es256_pk_new() -> *mut Pk;
    fn es256_pk_free(pk: *mut *mut Pk);
    fn es256_pk_from_ptr(pk: *mut Pk, p: *const u8, n: usize) -> c_int;
}

fn err(r: c_int) -> String {
    if r == 0 {
        return "OK".into();
    }
    let s = unsafe { CStr::from_ptr(fido_strerr(r)) }.to_string_lossy();
    format!("{s} (0x{r:02x})")
}

// ------------------------------------------------------------ the emulator
struct Emu {
    ctap: Ctap<TestEnv>,
    out: VecDeque<[u8; 64]>,
}

thread_local! {
    static EMU: RefCell<Option<Emu>> = const { RefCell::new(None) };
    static TOUCH: Rc<Cell<bool>> = Rc::new(Cell::new(true));
    static TOUCHES: Rc<Cell<u32>> = Rc::new(Cell::new(0));
}

fn new_ctap(mut env: TestEnv) -> Ctap<TestEnv> {
    let touch = TOUCH.with(|t| t.clone());
    let touches = TOUCHES.with(|t| t.clone());
    env.user_presence().set(move || {
        touches.set(touches.get() + 1);
        if touch.get() { Ok(()) } else { Err(UserPresenceError::Declined) }
    });
    Ctap::new(env)
}

fn power_on() {
    EMU.with(|e| *e.borrow_mut() = Some(Emu { ctap: new_ctap(TestEnv::default()), out: VecDeque::new() }));
}

/// Save the authenticator's persistent state (as a separate process would
/// write it to a file): every key/value pair of its storage.
fn save_state() -> Vec<(usize, Vec<u8>)> {
    EMU.with(|e| {
        let mut e = e.borrow_mut();
        let env = e.as_mut().unwrap().ctap.env();
        let persist = env.persist();
        let keys: Vec<usize> = persist.iter().unwrap().map(|k| k.unwrap()).collect();
        keys.into_iter().map(|k| (k, persist.find(k).unwrap().unwrap())).collect()
    })
}

/// Start a brand-new authenticator from saved state (a new process).
fn restore_state(state: &[(usize, Vec<u8>)]) {
    let mut env = TestEnv::default();
    for (k, v) in state {
        env.persist().insert(*k, v).unwrap();
    }
    EMU.with(|e| *e.borrow_mut() = Some(Emu { ctap: new_ctap(env), out: VecDeque::new() }));
}

/// Unplug and replug: same storage, fresh runtime state.
fn power_cycle() {
    EMU.with(|e| {
        let mut e = e.borrow_mut();
        let emu = e.as_mut().unwrap();
        let env = std::mem::take(emu.ctap.env());
        emu.ctap = new_ctap(env);
        emu.out.clear();
    });
}

extern "C" fn io_open(_path: *const c_char) -> *mut c_void {
    1 as *mut c_void // non-null token; the state lives in EMU
}
extern "C" fn io_close(_h: *mut c_void) {}
extern "C" fn io_write(_h: *mut c_void, buf: *const u8, len: usize) -> c_int {
    let data = unsafe { std::slice::from_raw_parts(buf, len) };
    // libfido2 prepends the report ID (0).
    let mut pkt = [0u8; 64];
    pkt.copy_from_slice(&data[1..65]);
    EMU.with(|e| {
        let mut e = e.borrow_mut();
        let emu = e.as_mut().unwrap();
        let resp: Vec<[u8; 64]> = emu.ctap.process_hid_packet(&pkt, Transport::MainHid).collect();
        emu.out.extend(resp);
    });
    len as c_int
}
extern "C" fn io_read(_h: *mut c_void, buf: *mut u8, len: usize, _ms: c_int) -> c_int {
    EMU.with(|e| match e.borrow_mut().as_mut().unwrap().out.pop_front() {
        Some(p) => {
            let n = len.min(64);
            unsafe { std::ptr::copy_nonoverlapping(p.as_ptr(), buf, n) };
            n as c_int
        }
        None => -1,
    })
}
static IO: FidoDevIo = FidoDevIo { open: io_open, close: io_close, read: io_read, write: io_write };

// --------------------------------------------------------------- helpers
struct Device(*mut Dev);
impl Device {
    fn open() -> Device {
        unsafe {
            let d = fido_dev_new();
            assert_eq!(fido_dev_set_io_functions(d, &IO), 0);
            let p = CString::new("opensk").unwrap();
            let r = fido_dev_open(d, p.as_ptr());
            assert_eq!(r, 0, "open: {}", err(r));
            Device(d)
        }
    }
}
impl Drop for Device {
    fn drop(&mut self) {
        unsafe {
            fido_dev_close(self.0);
            fido_dev_free(&mut self.0);
        }
    }
}

const RP: &str = "yb";
struct Credential {
    id: Vec<u8>,
    pubkey: Vec<u8>,
}

fn pin_ptr(pin: Option<&CString>) -> *const c_char {
    pin.map_or(std::ptr::null(), |p| p.as_ptr())
}

fn make_cred(dev: &Device, prot: bool, pin: Option<&CString>) -> Result<Credential, String> {
    unsafe {
        let mut c = fido_cred_new();
        let rp = CString::new(RP).unwrap();
        let user = CString::new("yb-store").unwrap();
        fido_cred_set_type(c, COSE_ES256);
        fido_cred_set_clientdata_hash(c, [7u8; 32].as_ptr(), 32);
        fido_cred_set_rp(c, rp.as_ptr(), std::ptr::null());
        fido_cred_set_user(c, [1u8; 16].as_ptr(), 16, user.as_ptr(), std::ptr::null(), std::ptr::null());
        fido_cred_set_rk(c, OPT_FALSE);
        fido_cred_set_extensions(c, EXT_HMAC_SECRET);
        if prot {
            fido_cred_set_prot(c, CRED_PROT_UV_REQUIRED);
        }
        let r = fido_dev_make_cred(dev.0, c, pin_ptr(pin));
        let res = if r == 0 {
            Ok(Credential {
                id: std::slice::from_raw_parts(fido_cred_id_ptr(c), fido_cred_id_len(c)).to_vec(),
                pubkey: std::slice::from_raw_parts(fido_cred_pubkey_ptr(c), fido_cred_pubkey_len(c)).to_vec(),
            })
        } else {
            Err(err(r))
        };
        fido_cred_free(&mut c);
        res
    }
}

struct Assertion {
    hmac: Vec<u8>,
    flags: u8,
    sigcount: u32,
    verified: String,
}

fn assertion(dev: &Device, cred: &Credential, up: c_int, salts: Option<&[u8]>, pin: Option<&CString>,
    cdh: [u8; 32]) -> Result<Assertion, String> {
    unsafe {
        let mut a = fido_assert_new();
        let rp = CString::new(RP).unwrap();
        fido_assert_set_rp(a, rp.as_ptr());
        fido_assert_set_clientdata_hash(a, cdh.as_ptr(), 32);
        fido_assert_allow_cred(a, cred.id.as_ptr(), cred.id.len());
        if let Some(s) = salts {
            fido_assert_set_extensions(a, EXT_HMAC_SECRET);
            let r = fido_assert_set_hmac_salt(a, s.as_ptr(), s.len());
            assert_eq!(r, 0, "set salt: {}", err(r));
        }
        fido_assert_set_up(a, up);
        if pin.is_some() {
            fido_assert_set_uv(a, OPT_TRUE);
        }
        let r = fido_dev_get_assert(dev.0, a, pin_ptr(pin));
        let res = if r == 0 {
            let n = fido_assert_hmac_secret_len(a, 0);
            let hmac = if n > 0 { std::slice::from_raw_parts(fido_assert_hmac_secret_ptr(a, 0), n).to_vec() } else { vec![] };
            let mut pk = es256_pk_new();
            es256_pk_from_ptr(pk, cred.pubkey.as_ptr(), cred.pubkey.len());
            let v = fido_assert_verify(a, 0, COSE_ES256, pk);
            es256_pk_free(&mut pk);
            Ok(Assertion { hmac, flags: fido_assert_flags(a, 0), sigcount: fido_assert_sigcount(a, 0), verified: err(v) })
        } else {
            Err(err(r))
        };
        fido_assert_free(&mut a);
        res
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().take(8).map(|x| format!("{x:02x}")).collect::<String>() + "…"
}
fn flags(f: u8) -> String {
    format!("UP={} UV={}", f & 0x01 != 0, f & 0x04 != 0)
}
fn touches_since<T>(f: impl FnOnce() -> T) -> (T, u32) {
    let before = TOUCHES.with(|t| t.get());
    let r = f();
    (r, TOUCHES.with(|t| t.get()) - before)
}
fn show(label: &str, r: (Result<Assertion, String>, u32)) -> Option<Vec<u8>> {
    match r.0 {
        Ok(a) => {
            println!("  {label:62} OK, touches={}, {}, hmac={} ({} bytes), sig={}, count={}",
                r.1, flags(a.flags), if a.hmac.is_empty() { "-".into() } else { hex(&a.hmac) },
                a.hmac.len(), a.verified, a.sigcount);
            Some(a.hmac)
        }
        Err(e) => {
            println!("  {label:62} REFUSED {e}, touches={}", r.1);
            None
        }
    }
}

fn main() {
    unsafe { fido_init(0) };
    power_on();
    let salt1 = [0x11u8; 32];
    let salt2 = [0x22u8; 32];
    let both: Vec<u8> = salt1.iter().chain(salt2.iter()).copied().collect();
    let cdh = [0x33u8; 32];

    println!("== Table 1: touch (no PIN set)");
    let dev = Device::open();
    let (c0, t) = touches_since(|| make_cred(&dev, false, None));
    let c0 = c0.expect("make_cred");
    println!("  {:62} OK, touches={t}, credential ID {} bytes, public key {} bytes",
        "makeCredential with hmac-secret, non-resident", c0.id.len(), c0.pubkey.len());
    show("getAssertion up=false, no extension", touches_since(|| assertion(&dev, &c0, OPT_FALSE, None, None, cdh)));
    show("getAssertion up=false, hmac-secret", touches_since(|| assertion(&dev, &c0, OPT_FALSE, Some(&salt1), None, cdh)));
    let a = show("getAssertion up=true, hmac-secret", touches_since(|| assertion(&dev, &c0, OPT_TRUE, Some(&salt1), None, cdh)));
    let b = show("getAssertion up=true, hmac-secret, same salt again", touches_since(|| assertion(&dev, &c0, OPT_TRUE, Some(&salt1), None, cdh)));
    println!("  -> same output twice: {}", a.is_some() && a == b);

    println!("== Table 2: PIN (PIN set)");
    let pin = CString::new("123456").unwrap();
    let r = unsafe { fido_dev_set_pin(dev.0, pin.as_ptr(), std::ptr::null()) };
    println!("  set PIN: {}", err(r));
    let (c1, _) = touches_since(|| make_cred(&dev, false, Some(&pin)));
    let c1 = c1.expect("make cred 1");
    let (c2, _) = touches_since(|| make_cred(&dev, true, Some(&pin)));
    let c2 = c2.expect("make cred 2");
    println!("  credential 2 (credProtect 3): ID {} bytes", c2.id.len());
    let with = show("cred 1, hmac-secret with PIN", touches_since(|| assertion(&dev, &c1, OPT_TRUE, Some(&salt1), Some(&pin), cdh)));
    let without = show("cred 1, hmac-secret without PIN", touches_since(|| assertion(&dev, &c1, OPT_TRUE, Some(&salt1), None, cdh)));
    println!("  -> outputs differ: {}", with.is_some() && without.is_some() && with != without);
    show("cred 2 (credProtect 3), without PIN", touches_since(|| assertion(&dev, &c2, OPT_TRUE, Some(&salt1), None, cdh)));
    let k = show("cred 2 (credProtect 3), with PIN", touches_since(|| assertion(&dev, &c2, OPT_TRUE, Some(&salt1), Some(&pin), cdh)));

    println!("== Spec 0028 needs");
    let two = show("cred 2, with PIN, two salts", touches_since(|| assertion(&dev, &c2, OPT_TRUE, Some(&both), Some(&pin), cdh)));
    if let (Some(k), Some(two)) = (&k, &two) {
        println!("  -> first half equals the single-salt output: {}", two.len() == 64 && two[..32] == k[..]);
    }
    TOUCH.with(|t| t.set(false));
    show("cred 2, with PIN, touch refused", touches_since(|| assertion(&dev, &c2, OPT_TRUE, Some(&salt1), Some(&pin), cdh)));
    TOUCH.with(|t| t.set(true));
    drop(dev);
    power_cycle();
    let dev = Device::open();
    let again = show("after power cycle: cred 2, with PIN, same salt", touches_since(|| assertion(&dev, &c2, OPT_TRUE, Some(&salt1), Some(&pin), cdh)));
    println!("  -> output survives a power cycle: {}", k.is_some() && again == k);

    println!("== PIN attempts");
    let retries = |dev: &Device| {
        let mut n = -1;
        let r = unsafe { fido_dev_get_retry_count(dev.0, &mut n) };
        if r == 0 { n.to_string() } else { err(r) }
    };
    println!("  retries: {}", retries(&dev));
    let bad = CString::new("000000").unwrap();
    for i in 1..=4 {
        let r = assertion(&dev, &c2, OPT_TRUE, Some(&salt1), Some(&bad), cdh).err().unwrap_or("OK?".into());
        println!("  wrong PIN #{i}: {r}; retries: {}", retries(&dev));
    }
    drop(dev);
    power_cycle();
    let dev = Device::open();
    println!("  after power cycle, retries: {}", retries(&dev));
    show("correct PIN after power cycle", touches_since(|| assertion(&dev, &c2, OPT_TRUE, Some(&salt1), Some(&pin), cdh)));
    println!("  retries: {}", retries(&dev));

    println!("== State saved and restored (new process)");
    drop(dev);
    let state = save_state();
    let bytes: usize = state.iter().map(|(_, v)| v.len()).sum();
    println!("  saved {} entries, {bytes} bytes", state.len());
    power_on(); // discard everything: a fresh, empty authenticator
    restore_state(&state);
    let dev = Device::open();
    println!("  retries after restore: {}", retries(&dev));
    let restored = show("after restore: cred 2, with PIN, same salt", touches_since(|| assertion(&dev, &c2, OPT_TRUE, Some(&salt1), Some(&pin), cdh)));
    println!("  -> output survives save and restore: {}", k.is_some() && restored == k);
    power_on();
    let dev2 = Device::open();
    show("control: fresh authenticator, cred 1, no PIN", touches_since(|| assertion(&dev2, &c1, OPT_TRUE, Some(&salt1), None, cdh)));
}
