// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! The libfido2 functions yb uses (spec 0028, D9): declared by hand, as
//! the C header `fido.h` has them.  Linked by `build.rs`.

use std::ffi::{c_char, c_int, c_void};

/// `fido_dev_t`, `fido_cred_t`, `fido_assert_t`, `fido_dev_info_t`: opaque.
pub type FidoDev = c_void;
pub type FidoCred = c_void;
pub type FidoAssert = c_void;
pub type FidoDevInfo = c_void;

/// `fido_dev_io_t`: replaces libfido2's HID I/O (64-byte reports).  Used by
/// the test emulator (spec 0028, "Tests").
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FidoDevIo {
    pub open: unsafe extern "C" fn(*const c_char) -> *mut c_void,
    pub close: unsafe extern "C" fn(*mut c_void),
    pub read: unsafe extern "C" fn(*mut c_void, *mut u8, usize, c_int) -> c_int,
    pub write: unsafe extern "C" fn(*mut c_void, *const u8, usize) -> c_int,
}

/// `fido_opt_t`.
pub const FIDO_OPT_FALSE: c_int = 1;
pub const FIDO_OPT_TRUE: c_int = 2;

pub const FIDO_EXT_HMAC_SECRET: c_int = 0x01;
pub const FIDO_CRED_PROT_UV_REQUIRED: c_int = 0x03;
pub const COSE_ES256: c_int = -7;

pub const FIDO_OK: c_int = 0x00;
pub const FIDO_ERR_OPERATION_DENIED: c_int = 0x27;
pub const FIDO_ERR_UNSUPPORTED_OPTION: c_int = 0x2b;
pub const FIDO_ERR_NO_CREDENTIALS: c_int = 0x2e;
pub const FIDO_ERR_USER_ACTION_TIMEOUT: c_int = 0x2f;
pub const FIDO_ERR_PIN_INVALID: c_int = 0x31;
pub const FIDO_ERR_PIN_BLOCKED: c_int = 0x32;
pub const FIDO_ERR_PIN_AUTH_BLOCKED: c_int = 0x34;
pub const FIDO_ERR_PIN_NOT_SET: c_int = 0x35;
pub const FIDO_ERR_UP_REQUIRED: c_int = 0x3b;

unsafe extern "C" {
    pub fn fido_init(flags: c_int);
    pub fn fido_strerr(err: c_int) -> *const c_char;

    pub fn fido_dev_info_new(n: usize) -> *mut FidoDevInfo;
    pub fn fido_dev_info_free(devlist: *mut *mut FidoDevInfo, n: usize);
    pub fn fido_dev_info_manifest(
        devlist: *mut FidoDevInfo,
        ilen: usize,
        olen: *mut usize,
    ) -> c_int;
    pub fn fido_dev_info_ptr(devlist: *const FidoDevInfo, i: usize) -> *const FidoDevInfo;
    pub fn fido_dev_info_path(di: *const FidoDevInfo) -> *const c_char;
    pub fn fido_dev_info_vendor(di: *const FidoDevInfo) -> i16;
    pub fn fido_dev_info_product(di: *const FidoDevInfo) -> i16;

    pub fn fido_dev_new() -> *mut FidoDev;
    pub fn fido_dev_free(dev: *mut *mut FidoDev);
    pub fn fido_dev_set_io_functions(dev: *mut FidoDev, io: *const FidoDevIo) -> c_int;
    pub fn fido_dev_open(dev: *mut FidoDev, path: *const c_char) -> c_int;
    pub fn fido_dev_close(dev: *mut FidoDev) -> c_int;
    pub fn fido_dev_has_pin(dev: *const FidoDev) -> bool;
    pub fn fido_dev_get_retry_count(dev: *mut FidoDev, retries: *mut c_int) -> c_int;
    pub fn fido_dev_set_pin(dev: *mut FidoDev, pin: *const c_char, oldpin: *const c_char) -> c_int;

    pub fn fido_cred_new() -> *mut FidoCred;
    pub fn fido_cred_free(cred: *mut *mut FidoCred);
    pub fn fido_cred_set_type(cred: *mut FidoCred, cose_alg: c_int) -> c_int;
    pub fn fido_cred_set_clientdata_hash(cred: *mut FidoCred, hash: *const u8, len: usize)
        -> c_int;
    pub fn fido_cred_set_rp(cred: *mut FidoCred, id: *const c_char, name: *const c_char) -> c_int;
    pub fn fido_cred_set_user(
        cred: *mut FidoCred,
        user_id: *const u8,
        user_id_len: usize,
        name: *const c_char,
        display_name: *const c_char,
        icon: *const c_char,
    ) -> c_int;
    pub fn fido_cred_set_rk(cred: *mut FidoCred, rk: c_int) -> c_int;
    pub fn fido_cred_set_extensions(cred: *mut FidoCred, ext: c_int) -> c_int;
    pub fn fido_cred_set_prot(cred: *mut FidoCred, prot: c_int) -> c_int;
    pub fn fido_dev_make_cred(dev: *mut FidoDev, cred: *mut FidoCred, pin: *const c_char) -> c_int;
    pub fn fido_cred_id_ptr(cred: *const FidoCred) -> *const u8;
    pub fn fido_cred_id_len(cred: *const FidoCred) -> usize;

    pub fn fido_assert_new() -> *mut FidoAssert;
    pub fn fido_assert_free(assert: *mut *mut FidoAssert);
    pub fn fido_assert_set_rp(assert: *mut FidoAssert, id: *const c_char) -> c_int;
    pub fn fido_assert_set_clientdata_hash(
        assert: *mut FidoAssert,
        hash: *const u8,
        len: usize,
    ) -> c_int;
    pub fn fido_assert_allow_cred(assert: *mut FidoAssert, id: *const u8, len: usize) -> c_int;
    pub fn fido_assert_set_extensions(assert: *mut FidoAssert, ext: c_int) -> c_int;
    pub fn fido_assert_set_hmac_salt(assert: *mut FidoAssert, salt: *const u8, len: usize)
        -> c_int;
    pub fn fido_assert_set_up(assert: *mut FidoAssert, up: c_int) -> c_int;
    pub fn fido_assert_set_uv(assert: *mut FidoAssert, uv: c_int) -> c_int;
    pub fn fido_dev_get_assert(
        dev: *mut FidoDev,
        assert: *mut FidoAssert,
        pin: *const c_char,
    ) -> c_int;
    pub fn fido_assert_count(assert: *const FidoAssert) -> usize;
    pub fn fido_assert_id_ptr(assert: *const FidoAssert, idx: usize) -> *const u8;
    pub fn fido_assert_id_len(assert: *const FidoAssert, idx: usize) -> usize;
    pub fn fido_assert_hmac_secret_ptr(assert: *const FidoAssert, idx: usize) -> *const u8;
    pub fn fido_assert_hmac_secret_len(assert: *const FidoAssert, idx: usize) -> usize;
}
