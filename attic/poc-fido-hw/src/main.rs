// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Hardware checks for spec 0028 on a real YubiKey, through libfido2.
//!
//! Creates one non-resident credential (nothing is stored on the key) and
//! measures what the proof of concept could only check against OpenSK:
//! credential ID size, two salts, a refused touch, a power cycle.  Asks for
//! the FIDO2 PIN on standard input, and tells when to touch or replug.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::io::{BufRead, Write};

type Dev = c_void;
type Cred = c_void;
type Assert = c_void;
type DevInfo = c_void;
const OPT_FALSE: c_int = 1;
const OPT_TRUE: c_int = 2;
const EXT_HMAC_SECRET: c_int = 0x01;
const CRED_PROT_UV_REQUIRED: c_int = 0x03;
const COSE_ES256: c_int = -7;

unsafe extern "C" {
    fn fido_init(flags: c_int);
    fn fido_strerr(err: c_int) -> *const c_char;
    fn fido_dev_info_new(n: usize) -> *mut DevInfo;
    fn fido_dev_info_manifest(devlist: *mut DevInfo, ilen: usize, olen: *mut usize) -> c_int;
    fn fido_dev_info_ptr(devlist: *const DevInfo, i: usize) -> *const DevInfo;
    fn fido_dev_info_path(di: *const DevInfo) -> *const c_char;
    fn fido_dev_info_vendor(di: *const DevInfo) -> i16;
    fn fido_dev_info_free(devlist: *mut *mut DevInfo, n: usize);
    fn fido_dev_new() -> *mut Dev;
    fn fido_dev_free(dev: *mut *mut Dev);
    fn fido_dev_open(dev: *mut Dev, path: *const c_char) -> c_int;
    fn fido_dev_close(dev: *mut Dev) -> c_int;
    fn fido_dev_set_timeout(dev: *mut Dev, ms: c_int) -> c_int;
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
}

fn err(r: c_int) -> String {
    let s = unsafe { CStr::from_ptr(fido_strerr(r)) }.to_string_lossy();
    format!("{s} (0x{r:02x})")
}

/// Path of the first Yubico FIDO device, if any.
fn find_yubikey() -> Option<CString> {
    unsafe {
        let mut list = fido_dev_info_new(16);
        let mut n = 0usize;
        let mut found = None;
        if fido_dev_info_manifest(list, 16, &mut n) == 0 {
            for i in 0..n {
                let di = fido_dev_info_ptr(list, i);
                if fido_dev_info_vendor(di) as u16 == 0x1050 {
                    found = Some(CStr::from_ptr(fido_dev_info_path(di)).to_owned());
                    break;
                }
            }
        }
        fido_dev_info_free(&mut list, 16);
        found
    }
}

struct Device(*mut Dev);
impl Device {
    fn open(timeout_ms: c_int) -> Device {
        let path = find_yubikey().expect("no YubiKey FIDO device found");
        unsafe {
            let d = fido_dev_new();
            let r = fido_dev_open(d, path.as_ptr());
            assert_eq!(r, 0, "open {:?}: {}", path, err(r));
            fido_dev_set_timeout(d, timeout_ms);
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

fn retries(dev: &Device) -> String {
    let mut n = -1;
    let r = unsafe { fido_dev_get_retry_count(dev.0, &mut n) };
    if r == 0 { n.to_string() } else { err(r) }
}

fn hmac(dev: &Device, id: &[u8], salts: &[u8], pin: &CString) -> Result<Vec<u8>, String> {
    unsafe {
        let mut a = fido_assert_new();
        let rp = CString::new("yb").unwrap();
        fido_assert_set_rp(a, rp.as_ptr());
        fido_assert_set_clientdata_hash(a, [0x33u8; 32].as_ptr(), 32);
        fido_assert_allow_cred(a, id.as_ptr(), id.len());
        fido_assert_set_extensions(a, EXT_HMAC_SECRET);
        fido_assert_set_hmac_salt(a, salts.as_ptr(), salts.len());
        fido_assert_set_up(a, OPT_TRUE);
        fido_assert_set_uv(a, OPT_TRUE);
        let r = fido_dev_get_assert(dev.0, a, pin.as_ptr());
        let res = if r == 0 {
            let n = fido_assert_hmac_secret_len(a, 0);
            Ok(std::slice::from_raw_parts(fido_assert_hmac_secret_ptr(a, 0), n).to_vec())
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

fn say(msg: &str) {
    println!("\n>>> {msg}");
    std::io::stdout().flush().unwrap();
}

fn wait_enter(msg: &str) {
    say(msg);
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).unwrap();
}

fn main() {
    unsafe { fido_init(0) };
    print!("FIDO2 PIN of the test YubiKey: ");
    std::io::stdout().flush().unwrap();
    let stty = |arg: &str| {
        let _ = std::process::Command::new("stty").arg(arg).status();
    };
    stty("-echo");
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).unwrap();
    stty("echo");
    println!();
    let pin = CString::new(line.trim_end_matches(['\r', '\n'])).unwrap();
    let salt1 = [0x11u8; 32];
    let salt2 = [0x22u8; 32];
    let both: Vec<u8> = salt1.iter().chain(salt2.iter()).copied().collect();

    let dev = Device::open(30_000);
    println!("PIN attempts left: {}", retries(&dev));

    say("1/5 creating a non-resident credential: TOUCH the YubiKey when it blinks");
    let id = unsafe {
        let mut c = fido_cred_new();
        let rp = CString::new("yb").unwrap();
        let user = CString::new("yb-store").unwrap();
        fido_cred_set_type(c, COSE_ES256);
        fido_cred_set_clientdata_hash(c, [7u8; 32].as_ptr(), 32);
        fido_cred_set_rp(c, rp.as_ptr(), std::ptr::null());
        fido_cred_set_user(c, [1u8; 16].as_ptr(), 16, user.as_ptr(), std::ptr::null(), std::ptr::null());
        fido_cred_set_rk(c, OPT_FALSE);
        fido_cred_set_extensions(c, EXT_HMAC_SECRET);
        fido_cred_set_prot(c, CRED_PROT_UV_REQUIRED);
        let r = fido_dev_make_cred(dev.0, c, pin.as_ptr());
        assert_eq!(r, 0, "makeCredential: {}", err(r));
        let id = std::slice::from_raw_parts(fido_cred_id_ptr(c), fido_cred_id_len(c)).to_vec();
        fido_cred_free(&mut c);
        id
    };
    println!("RESULT credential ID size: {} bytes", id.len());

    say("2/5 one salt: TOUCH the YubiKey when it blinks");
    let one = hmac(&dev, &id, &salt1, &pin).expect("one salt");
    println!("RESULT one salt: {} bytes, {}", one.len(), hex(&one));

    say("3/5 two salts: TOUCH the YubiKey when it blinks");
    let two = hmac(&dev, &id, &both, &pin).expect("two salts");
    println!("RESULT two salts: {} bytes, {} | {}", two.len(), hex(&two[..32]), hex(&two[32..]));
    println!("RESULT first half equals the one-salt output: {}", two.len() == 64 && two[..32] == one[..]);

    say("4/5 refused touch: do NOT touch the YubiKey; wait about 30 seconds");
    match hmac(&dev, &id, &salt1, &pin) {
        Ok(_) => println!("RESULT no touch: unexpectedly OK (was it touched?)"),
        Err(e) => println!("RESULT no touch: {e}"),
    }
    println!("PIN attempts left: {}", retries(&dev));
    drop(dev);

    wait_enter("5/5 power cycle: UNPLUG the YubiKey, plug it back in, then press Enter");
    let dev = Device::open(30_000);
    say("after the power cycle: TOUCH the YubiKey when it blinks");
    let again = hmac(&dev, &id, &salt1, &pin).expect("after power cycle");
    println!("RESULT after power cycle: same output: {}", again == one);
    println!("PIN attempts left: {}", retries(&dev));
    println!("\nDone.  Nothing was stored on the YubiKey (non-resident credential).");
}
