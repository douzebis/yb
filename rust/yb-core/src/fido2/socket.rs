// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! A FIDO2 device behind a Unix socket, for the command-line tests (spec
//! 0028, "Tests"): the test runner serves the emulator (OpenSK) on the
//! socket named by `YB_FIDO2_SOCKET`, and every `yb` process it starts
//! talks to it, so the emulator's state lasts for the whole run.  Builds
//! with `test-fixture` only (invariant 0012).
//!
//! Protocol: the client writes each 64-byte report preceded by its report
//! ID (65 bytes, as libfido2 writes to HID); the server answers with the
//! 64-byte reports of the reply.

use super::ffi::FidoDevIo;
use super::hid::{ReportChannel, REPORT_LEN};
use anyhow::{bail, Context as _, Result};
use std::ffi::{c_char, c_int, c_void, CStr};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

/// The environment variable naming the emulator's socket.
pub const SOCKET_ENV: &str = "YB_FIDO2_SOCKET";

/// The socket of the emulator, if the test runner provides one.
pub fn socket_path() -> Option<String> {
    std::env::var(SOCKET_ENV).ok().filter(|p| !p.is_empty())
}

unsafe extern "C" fn io_open(path: *const c_char) -> *mut c_void {
    let Ok(path) = CStr::from_ptr(path).to_str() else {
        return std::ptr::null_mut();
    };
    match UnixStream::connect(path) {
        Ok(stream) => Box::into_raw(Box::new(stream)).cast(),
        Err(_) => std::ptr::null_mut(),
    }
}

unsafe extern "C" fn io_close(handle: *mut c_void) {
    if !handle.is_null() {
        drop(Box::from_raw(handle.cast::<UnixStream>()));
    }
}

unsafe extern "C" fn io_write(handle: *mut c_void, buf: *const u8, len: usize) -> c_int {
    let stream = &mut *handle.cast::<UnixStream>();
    let data = std::slice::from_raw_parts(buf, len);
    match stream.write_all(data) {
        Ok(()) => len as c_int,
        Err(_) => -1,
    }
}

unsafe extern "C" fn io_read(handle: *mut c_void, buf: *mut u8, len: usize, ms: c_int) -> c_int {
    let stream = &mut *handle.cast::<UnixStream>();
    let timeout = (ms > 0).then(|| Duration::from_millis(ms as u64));
    if stream.set_read_timeout(timeout).is_err() {
        return -1;
    }
    let mut report = [0u8; REPORT_LEN];
    match stream.read_exact(&mut report) {
        Ok(()) => {
            let n = len.min(REPORT_LEN);
            std::ptr::copy_nonoverlapping(report.as_ptr(), buf, n);
            n as c_int
        }
        Err(_) => -1,
    }
}

/// libfido2 I/O functions over the emulator's socket; the device "path"
/// is the socket's path.
pub const SOCKET_IO: FidoDevIo = FidoDevIo {
    open: io_open,
    close: io_close,
    read: io_read,
    write: io_write,
};

/// A report channel over the socket, for the serial vendor command.
pub struct SocketChannel(UnixStream);

impl SocketChannel {
    pub fn open(path: &str) -> Result<Self> {
        let stream = UnixStream::connect(path).with_context(|| format!("connecting to {path}"))?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        Ok(Self(stream))
    }
}

impl ReportChannel for SocketChannel {
    fn write_report(&mut self, report: &[u8; REPORT_LEN]) -> Result<()> {
        let mut buf = [0u8; REPORT_LEN + 1];
        buf[1..].copy_from_slice(report);
        self.0.write_all(&buf).context("writing to the emulator")
    }

    fn read_report(&mut self) -> Result<[u8; REPORT_LEN]> {
        let mut report = [0u8; REPORT_LEN];
        if self.0.read_exact(&mut report).is_err() {
            bail!("no reply from the emulator");
        }
        Ok(report)
    }
}
