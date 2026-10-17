// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! A FIDO2 authenticator in memory, for yb's tests (spec 0028, "Tests").
//!
//! Google's OpenSK (`TestEnv`) answers libfido2 through its custom I/O
//! functions ([`io_open`], [`io_close`], [`io_read`], [`io_write`]): no USB
//! device, no root, and it runs in the Nix build sandbox.  It also answers
//! Yubico's `READ_CONFIG` vendor command with a configured serial, as a
//! YubiKey does, which OpenSK does not know.
//!
//! One emulator per thread (tests run in parallel threads).  The touch is
//! scripted ([`set_touch`]); [`power_cycle`] simulates unplugging and
//! replugging; [`save_state`] and [`restore_state`] carry the persistent
//! state across processes (the command-line tests).

use opensk::api::persist::Persist;
use opensk::api::user_presence::UserPresenceError;
use opensk::env::test::TestEnv;
use opensk::env::Env;
use opensk::{Ctap, Transport};
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::ffi::{c_char, c_int, c_void};
use std::rc::Rc;

const REPORT_LEN: usize = 64;
const TYPE_INIT: u8 = 0x80;
/// Yubico's vendor command `READ_CONFIG`.
const YK_READ_CONFIG: u8 = 0x42;

struct Emulator {
    ctap: Ctap<TestEnv>,
    /// Reports waiting to be read by libfido2.
    out: VecDeque<[u8; REPORT_LEN]>,
    serial: Option<u32>,
}

thread_local! {
    static EMULATOR: RefCell<Option<Emulator>> = const { RefCell::new(None) };
    static TOUCH: Rc<Cell<bool>> = Rc::new(Cell::new(true));
    static TOUCHES: Rc<Cell<u32>> = Rc::new(Cell::new(0));
}

fn new_ctap(mut env: TestEnv) -> Ctap<TestEnv> {
    let touch = TOUCH.with(Rc::clone);
    let touches = TOUCHES.with(Rc::clone);
    env.user_presence().set(move || {
        touches.set(touches.get() + 1);
        if touch.get() {
            Ok(())
        } else {
            Err(UserPresenceError::Declined)
        }
    });
    Ctap::new(env)
}

fn with<T>(f: impl FnOnce(&mut Emulator) -> T) -> T {
    EMULATOR.with(|e| {
        let mut e = e.borrow_mut();
        f(e.as_mut().expect("yb-fido2-emulator: power_on first"))
    })
}

/// A brand-new authenticator (no PIN, no credential) on this thread,
/// reporting `serial` to `READ_CONFIG` (`None`: no serial, as a non-Yubico
/// device).
pub fn power_on(serial: Option<u32>) {
    EMULATOR.with(|e| {
        *e.borrow_mut() = Some(Emulator {
            ctap: new_ctap(TestEnv::default()),
            out: VecDeque::new(),
            serial,
        })
    });
}

/// Unplug and replug: same persistent state, fresh runtime state (the
/// 3-wrong-PINs block is lifted).
pub fn power_cycle() {
    with(|emu| {
        let env = std::mem::take(emu.ctap.env());
        emu.ctap = new_ctap(env);
        emu.out.clear();
    });
}

/// Whether the next touches are given (`true`, the default) or refused.
pub fn set_touch(given: bool) {
    TOUCH.with(|t| t.set(given));
}

/// The touches asked for so far on this thread.
pub fn touches() -> u32 {
    TOUCHES.with(|t| t.get())
}

/// The authenticator's persistent state, as key/value pairs.
pub fn save_state() -> Vec<(usize, Vec<u8>)> {
    with(|emu| {
        let persist = emu.ctap.env().persist();
        let keys: Vec<usize> = persist
            .iter()
            .expect("emulator storage")
            .map(|k| k.expect("emulator storage"))
            .collect();
        keys.into_iter()
            .map(|k| {
                let v = persist
                    .find(k)
                    .expect("emulator storage")
                    .unwrap_or_default();
                (k, v)
            })
            .collect()
    })
}

/// A new authenticator from saved state, as another process would start it.
pub fn restore_state(state: &[(usize, Vec<u8>)], serial: Option<u32>) {
    let mut env = TestEnv::default();
    for (k, v) in state {
        env.persist().insert(*k, v).expect("emulator storage");
    }
    EMULATOR.with(|e| {
        *e.borrow_mut() = Some(Emulator {
            ctap: new_ctap(env),
            out: VecDeque::new(),
            serial,
        })
    });
}

/// The reply to `READ_CONFIG` page 0: a length byte, then TLVs (serial
/// under tag 0x02, firmware version under 0x05).
fn device_info(serial: Option<u32>) -> Vec<u8> {
    let mut tlvs = vec![0x05, 0x03, 0x05, 0x07, 0x01];
    if let Some(serial) = serial {
        tlvs.extend_from_slice(&[0x02, 0x04]);
        tlvs.extend_from_slice(&serial.to_be_bytes());
    }
    let mut info = vec![tlvs.len() as u8];
    info.extend_from_slice(&tlvs);
    info
}

/// One report for a reply that fits in it.
fn single_report(cid: &[u8], cmd: u8, data: &[u8]) -> [u8; REPORT_LEN] {
    let mut report = [0u8; REPORT_LEN];
    report[..4].copy_from_slice(cid);
    report[4] = TYPE_INIT | cmd;
    report[5..7].copy_from_slice(&(data.len() as u16).to_be_bytes());
    report[7..7 + data.len()].copy_from_slice(data);
    report
}

/// libfido2's `open`: the state lives in the thread's emulator.
///
/// # Safety
/// Called by libfido2 with a C string (unused).
pub unsafe extern "C" fn io_open(_path: *const c_char) -> *mut c_void {
    // Any non-null handle: libfido2 only passes it back.
    std::ptr::NonNull::<c_void>::dangling().as_ptr()
}

/// libfido2's `close`.
///
/// # Safety
/// Called by libfido2 with the handle from [`io_open`].
pub unsafe extern "C" fn io_close(_handle: *mut c_void) {}

/// libfido2's `write`: one report, prefixed with the report ID (0).
///
/// # Safety
/// `buf` points to `len` readable bytes.
pub unsafe extern "C" fn io_write(_handle: *mut c_void, buf: *const u8, len: usize) -> c_int {
    let data = std::slice::from_raw_parts(buf, len);
    if len != REPORT_LEN + 1 {
        return -1;
    }
    let mut report = [0u8; REPORT_LEN];
    report.copy_from_slice(&data[1..]);
    with(|emu| {
        if report[4] == TYPE_INIT | YK_READ_CONFIG {
            let reply = single_report(&report[..4], YK_READ_CONFIG, &device_info(emu.serial));
            emu.out.push_back(reply);
        } else {
            let replies: Vec<_> = emu
                .ctap
                .process_hid_packet(&report, Transport::MainHid)
                .collect();
            emu.out.extend(replies);
        }
    });
    len as c_int
}

/// libfido2's `read`: the next report, or -1 if none is waiting.
///
/// # Safety
/// `buf` points to `len` writable bytes.
pub unsafe extern "C" fn io_read(
    _handle: *mut c_void,
    buf: *mut u8,
    len: usize,
    _ms: c_int,
) -> c_int {
    match with(|emu| emu.out.pop_front()) {
        Some(report) => {
            let n = len.min(REPORT_LEN);
            std::ptr::copy_nonoverlapping(report.as_ptr(), buf, n);
            n as c_int
        }
        None => -1,
    }
}

/// The emulator served on a Unix socket, for processes that are not the
/// test (the `yb` binaries run by the command-line tests): one thread owns
/// the emulator, so its state lasts for the whole run.  See
/// `yb_core::fido2::socket` for the protocol.
#[cfg(unix)]
pub mod server {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::Arc;

    /// A running emulator server.
    pub struct Server {
        pub path: PathBuf,
        touch: Arc<AtomicBool>,
        touches: Arc<AtomicU32>,
        replug: Arc<AtomicBool>,
    }

    impl Server {
        /// Serve a brand-new emulator reporting `serial`, on a socket at
        /// `path` (removed first if it exists).
        pub fn start(path: &Path, serial: Option<u32>) -> std::io::Result<Self> {
            let _ = std::fs::remove_file(path);
            let listener = UnixListener::bind(path)?;
            let touch = Arc::new(AtomicBool::new(true));
            let touches = Arc::new(AtomicU32::new(0));
            let replug = Arc::new(AtomicBool::new(false));
            let (t, n, r) = (
                Arc::clone(&touch),
                Arc::clone(&touches),
                Arc::clone(&replug),
            );
            std::thread::spawn(move || {
                super::power_on(serial);
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { continue };
                    if r.swap(false, Ordering::SeqCst) {
                        super::power_cycle();
                    }
                    let mut buf = [0u8; super::REPORT_LEN + 1];
                    while stream.read_exact(&mut buf).is_ok() {
                        super::set_touch(t.load(Ordering::SeqCst));
                        // SAFETY: `buf` holds REPORT_LEN + 1 bytes.
                        unsafe {
                            super::io_write(std::ptr::null_mut(), buf.as_ptr(), buf.len());
                        }
                        let mut report = [0u8; super::REPORT_LEN];
                        // SAFETY: `report` holds REPORT_LEN writable bytes.
                        while unsafe {
                            super::io_read(
                                std::ptr::null_mut(),
                                report.as_mut_ptr(),
                                report.len(),
                                0,
                            )
                        } > 0
                        {
                            if stream.write_all(&report).is_err() {
                                break;
                            }
                        }
                        n.store(super::touches(), Ordering::SeqCst);
                    }
                }
            });
            Ok(Self {
                path: path.to_owned(),
                touch,
                touches,
                replug,
            })
        }

        /// Unplug and replug the emulated key before the next connection
        /// (lifts the block after 3 wrong PINs in a row).
        pub fn replug(&self) {
            self.replug.store(true, Ordering::SeqCst);
        }

        /// Whether the next touches are given (default) or refused.
        pub fn set_touch(&self, given: bool) {
            self.touch.store(given, Ordering::SeqCst);
        }

        /// The touches asked for so far.
        pub fn touches(&self) -> u32 {
            self.touches.load(Ordering::SeqCst)
        }
    }
}
