// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! FIDO2 through libfido2, for post-quantum stores (spec 0028).
//!
//! A small safe layer over the hand-written FFI ([`ffi`]): list devices,
//! read a YubiKey's serial ([`hid`]), create the store's credential, and
//! get `hmac-secret` outputs.  Tests plug an emulator under libfido2 with
//! its custom I/O functions, so this code is exercised by every test.

pub mod ffi;
pub mod hid;
pub mod pairing;

use anyhow::{bail, Result};
use std::ffi::{c_int, CStr, CString};
use std::sync::Once;
use zeroize::Zeroizing;

/// The relying party ID of yb's credentials (spec 0028, "Store descriptor").
pub const RP_ID: &str = "yb";
/// Yubico's USB vendor ID.
pub const YUBICO_VENDOR_ID: u16 = 0x1050;
/// The length of one `hmac-secret` salt and output.
pub const SALT_LEN: usize = 32;

/// A FIDO2 failure yb reports to the user (spec 0028, "Card operations").
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Fido2Error {
    #[error("the YubiKey was not touched in time")]
    NoTouch,
    #[error("wrong FIDO2 PIN")]
    PinInvalid,
    #[error("3 wrong FIDO2 PINs in a row: unplug and replug the YubiKey")]
    PinAuthBlocked,
    #[error(
        "the FIDO2 PIN is blocked: only a FIDO2 reset clears it, which destroys \
         post-quantum stores"
    )]
    PinBlocked,
    #[error("no FIDO2 PIN is set on this YubiKey")]
    PinNotSet,
    #[error("the FIDO2 credential is not on this YubiKey (FIDO2 reset?)")]
    NoCredential,
    #[error("FIDO2 error: {0}")]
    Other(String),
}

impl Fido2Error {
    fn from_code(code: c_int) -> Self {
        match code {
            ffi::FIDO_ERR_OPERATION_DENIED
            | ffi::FIDO_ERR_USER_ACTION_TIMEOUT
            | ffi::FIDO_ERR_UP_REQUIRED
            | ffi::FIDO_ERR_UNSUPPORTED_OPTION => Self::NoTouch,
            ffi::FIDO_ERR_PIN_INVALID => Self::PinInvalid,
            ffi::FIDO_ERR_PIN_AUTH_BLOCKED => Self::PinAuthBlocked,
            ffi::FIDO_ERR_PIN_BLOCKED => Self::PinBlocked,
            ffi::FIDO_ERR_PIN_NOT_SET => Self::PinNotSet,
            ffi::FIDO_ERR_NO_CREDENTIALS => Self::NoCredential,
            _ => Self::Other(strerr(code)),
        }
    }
}

fn strerr(code: c_int) -> String {
    // SAFETY: fido_strerr returns a static string for any code.
    let s = unsafe { CStr::from_ptr(ffi::fido_strerr(code)) };
    format!("{} (0x{code:02x})", s.to_string_lossy())
}

fn check(code: c_int) -> Result<()> {
    if code == ffi::FIDO_OK {
        Ok(())
    } else {
        Err(Fido2Error::from_code(code).into())
    }
}

/// `pin` as a NUL-terminated C string in zeroizing memory (allocated at
/// its final size, so no reallocation leaves a copy behind).
fn c_pin(pin: &str) -> Result<Zeroizing<Vec<u8>>> {
    if pin.as_bytes().contains(&0) {
        bail!("a PIN cannot contain a NUL byte");
    }
    let mut c = Zeroizing::new(Vec::with_capacity(pin.len() + 1));
    c.extend_from_slice(pin.as_bytes());
    c.push(0);
    Ok(c)
}

fn init() {
    static INIT: Once = Once::new();
    // SAFETY: fido_init is called once, before any other libfido2 call.
    INIT.call_once(|| unsafe { ffi::fido_init(0) });
}

/// A FIDO device as libfido2 lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    /// The OS path (`/dev/hidrawN` on Linux).
    pub path: String,
    pub vendor_id: u16,
    pub product_id: u16,
}

/// The FIDO devices connected.
pub fn list_devices() -> Result<Vec<DeviceInfo>> {
    init();
    const MAX: usize = 64;
    let mut devices = Vec::new();
    // SAFETY: the list is allocated for MAX entries, read for the `n`
    // libfido2 filled, and freed once.
    unsafe {
        let mut list = ffi::fido_dev_info_new(MAX);
        if list.is_null() {
            bail!("libfido2: out of memory");
        }
        let mut n = 0usize;
        let r = ffi::fido_dev_info_manifest(list, MAX, &mut n);
        if r == ffi::FIDO_OK {
            for i in 0..n {
                let di = ffi::fido_dev_info_ptr(list, i);
                devices.push(DeviceInfo {
                    path: CStr::from_ptr(ffi::fido_dev_info_path(di))
                        .to_string_lossy()
                        .into_owned(),
                    vendor_id: ffi::fido_dev_info_vendor(di) as u16,
                    product_id: ffi::fido_dev_info_product(di) as u16,
                });
            }
        }
        ffi::fido_dev_info_free(&mut list, MAX);
        check(r)?;
    }
    Ok(devices)
}

/// A credential created by [`Device::make_credential`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    /// The credential ID (opaque; 64 bytes on a YubiKey 5.7).
    pub id: Vec<u8>,
}

/// An open FIDO device.
pub struct Device {
    dev: *mut ffi::FidoDev,
}

impl Device {
    /// Open the device at `path` (from [`list_devices`]).
    pub fn open(path: &str) -> Result<Self> {
        Self::open_with(path, None)
    }

    /// Open a device through custom I/O functions: the test emulator
    /// (spec 0028, "Tests").  Test builds only (invariant 0012).
    #[cfg(any(test, feature = "test-utils", feature = "test-fixture"))]
    pub fn open_with_io(io: &ffi::FidoDevIo) -> Result<Self> {
        Self::open_with("emulator", Some(io))
    }

    fn open_with(path: &str, io: Option<&ffi::FidoDevIo>) -> Result<Self> {
        init();
        let path = CString::new(path)?;
        // SAFETY: the device is allocated, configured before it is opened,
        // and freed on failure (or by Drop).
        unsafe {
            let mut dev = ffi::fido_dev_new();
            if dev.is_null() {
                bail!("libfido2: out of memory");
            }
            let mut r = ffi::FIDO_OK;
            if let Some(io) = io {
                r = ffi::fido_dev_set_io_functions(dev, io);
            }
            if r == ffi::FIDO_OK {
                r = ffi::fido_dev_open(dev, path.as_ptr());
            }
            if r != ffi::FIDO_OK {
                ffi::fido_dev_free(&mut dev);
                return Err(Fido2Error::from_code(r).into());
            }
            Ok(Self { dev })
        }
    }

    /// Start waiting for a touch, without PIN (CTAP 2.1
    /// `authenticatorSelection`): the key blinks.  See [`Self::touched`].
    pub fn touch_begin(&self) -> Result<()> {
        // SAFETY: `dev` is open.
        check(unsafe { ffi::fido_dev_get_touch_begin(self.dev) })
    }

    /// Whether the key was touched since [`Self::touch_begin`], waiting at
    /// most `ms` milliseconds.
    pub fn touched(&self, ms: i32) -> Result<bool> {
        let mut touched: c_int = 0;
        // SAFETY: `dev` is open; `touched` is writable.
        check(unsafe { ffi::fido_dev_get_touch_status(self.dev, &mut touched, ms) })?;
        Ok(touched != 0)
    }

    /// Stop waiting for a touch (the key stops blinking).
    pub fn cancel(&self) {
        // SAFETY: `dev` is open.  A failure only means nothing to cancel.
        unsafe { ffi::fido_dev_cancel(self.dev) };
    }

    /// Whether a FIDO2 PIN is set (from the device info: no attempt used).
    pub fn has_pin(&self) -> bool {
        // SAFETY: `dev` is open.
        unsafe { ffi::fido_dev_has_pin(self.dev) }
    }

    /// The FIDO2 PIN attempts left (no attempt used).
    pub fn pin_retries(&self) -> Result<u32> {
        let mut n: c_int = -1;
        // SAFETY: `dev` is open; `n` is writable.
        check(unsafe { ffi::fido_dev_get_retry_count(self.dev, &mut n) })?;
        Ok(n.max(0) as u32)
    }

    /// Set the FIDO2 PIN of a device that has none.
    pub fn set_pin(&self, pin: &str) -> Result<()> {
        let pin = c_pin(pin)?;
        // SAFETY: `dev` is open; `pin` is a C string.
        check(unsafe { ffi::fido_dev_set_pin(self.dev, pin.as_ptr().cast(), std::ptr::null()) })
    }

    /// Create the store's credential (spec 0028, D4): ES256, not resident,
    /// `hmac-secret`, `credProtect` 3.  Needs the PIN and a touch.
    pub fn make_credential(&self, pin: &str) -> Result<Credential> {
        let rp = CString::new(RP_ID)?;
        let user = CString::new("yb store")?;
        let pin = c_pin(pin)?;
        let user_id: [u8; 16] = rand::random();
        let cdh: [u8; 32] = rand::random();
        // SAFETY: the credential is allocated, filled, used and freed here;
        // its ID is copied out before it is freed.
        unsafe {
            let mut cred = ffi::fido_cred_new();
            if cred.is_null() {
                bail!("libfido2: out of memory");
            }
            let mut r = ffi::fido_cred_set_type(cred, ffi::COSE_ES256);
            for step in [
                ffi::fido_cred_set_clientdata_hash(cred, cdh.as_ptr(), cdh.len()),
                ffi::fido_cred_set_rp(cred, rp.as_ptr(), std::ptr::null()),
                ffi::fido_cred_set_user(
                    cred,
                    user_id.as_ptr(),
                    user_id.len(),
                    user.as_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                ),
                ffi::fido_cred_set_rk(cred, ffi::FIDO_OPT_FALSE),
                ffi::fido_cred_set_extensions(cred, ffi::FIDO_EXT_HMAC_SECRET),
                ffi::fido_cred_set_prot(cred, ffi::FIDO_CRED_PROT_UV_REQUIRED),
            ] {
                if r == ffi::FIDO_OK {
                    r = step;
                }
            }
            if r == ffi::FIDO_OK {
                r = ffi::fido_dev_make_cred(self.dev, cred, pin.as_ptr().cast());
            }
            let result = if r == ffi::FIDO_OK {
                let id = std::slice::from_raw_parts(
                    ffi::fido_cred_id_ptr(cred),
                    ffi::fido_cred_id_len(cred),
                )
                .to_vec();
                Ok(Credential { id })
            } else {
                Err(Fido2Error::from_code(r).into())
            };
            ffi::fido_cred_free(&mut cred);
            result
        }
    }

    /// Which of `candidates` (credential IDs, e.g. read from several
    /// stores) is on this device: one assertion with the PIN, without a
    /// touch and without extension.  The device only recognizes the IDs it
    /// created, and answers with the one it used.  `None`: none of them.
    pub fn find_credential(&self, candidates: &[&[u8]], pin: &str) -> Result<Option<Vec<u8>>> {
        if candidates.is_empty() {
            return Ok(None);
        }
        let rp = CString::new(RP_ID)?;
        let pin = c_pin(pin)?;
        let cdh: [u8; 32] = rand::random();
        // SAFETY: the assertion is allocated, filled, used and freed here;
        // the ID it returns is copied out before.
        unsafe {
            let mut a = ffi::fido_assert_new();
            if a.is_null() {
                bail!("libfido2: out of memory");
            }
            let mut r = ffi::fido_assert_set_rp(a, rp.as_ptr());
            if r == ffi::FIDO_OK {
                r = ffi::fido_assert_set_clientdata_hash(a, cdh.as_ptr(), cdh.len());
            }
            for id in candidates {
                if r == ffi::FIDO_OK {
                    r = ffi::fido_assert_allow_cred(a, id.as_ptr(), id.len());
                }
            }
            if r == ffi::FIDO_OK {
                r = ffi::fido_assert_set_up(a, ffi::FIDO_OPT_FALSE);
            }
            if r == ffi::FIDO_OK {
                r = ffi::fido_dev_get_assert(self.dev, a, pin.as_ptr().cast());
            }
            let result = match r {
                ffi::FIDO_OK if ffi::fido_assert_count(a) == 1 => Ok(Some(
                    std::slice::from_raw_parts(
                        ffi::fido_assert_id_ptr(a, 0),
                        ffi::fido_assert_id_len(a, 0),
                    )
                    .to_vec(),
                )),
                ffi::FIDO_OK => Err(anyhow::anyhow!("libfido2: unexpected number of assertions")),
                ffi::FIDO_ERR_NO_CREDENTIALS => Ok(None),
                r => Err(Fido2Error::from_code(r).into()),
            };
            ffi::fido_assert_free(&mut a);
            result
        }
    }

    /// One assertion of `credential_id` with the PIN and a touch: the
    /// `hmac-secret` outputs for one or two salts (spec 0028, D2, D7).
    /// `clientDataHash` is random: nothing is signed (D5).
    pub fn hmac_secret(
        &self,
        credential_id: &[u8],
        salts: &[[u8; SALT_LEN]],
        pin: &str,
    ) -> Result<Vec<Zeroizing<[u8; SALT_LEN]>>> {
        if salts.is_empty() || salts.len() > 2 {
            bail!("hmac-secret takes one or two salts");
        }
        let rp = CString::new(RP_ID)?;
        let pin = c_pin(pin)?;
        let joined: Vec<u8> = salts.concat();
        let cdh: [u8; 32] = rand::random();
        // SAFETY: the assertion is allocated, filled, used and freed here;
        // its outputs are copied out (into zeroizing memory) before.
        unsafe {
            let mut a = ffi::fido_assert_new();
            if a.is_null() {
                bail!("libfido2: out of memory");
            }
            let mut r = ffi::fido_assert_set_rp(a, rp.as_ptr());
            for step in [
                ffi::fido_assert_set_clientdata_hash(a, cdh.as_ptr(), cdh.len()),
                ffi::fido_assert_allow_cred(a, credential_id.as_ptr(), credential_id.len()),
                ffi::fido_assert_set_extensions(a, ffi::FIDO_EXT_HMAC_SECRET),
                ffi::fido_assert_set_hmac_salt(a, joined.as_ptr(), joined.len()),
                ffi::fido_assert_set_up(a, ffi::FIDO_OPT_TRUE),
                ffi::fido_assert_set_uv(a, ffi::FIDO_OPT_TRUE),
            ] {
                if r == ffi::FIDO_OK {
                    r = step;
                }
            }
            if r == ffi::FIDO_OK {
                r = ffi::fido_dev_get_assert(self.dev, a, pin.as_ptr().cast());
            }
            let result = if r != ffi::FIDO_OK {
                Err(Fido2Error::from_code(r).into())
            } else if ffi::fido_assert_count(a) != 1 {
                Err(anyhow::anyhow!("libfido2: unexpected number of assertions"))
            } else {
                let len = ffi::fido_assert_hmac_secret_len(a, 0);
                if len != SALT_LEN * salts.len() {
                    Err(anyhow::anyhow!(
                        "hmac-secret: unexpected output length {len}"
                    ))
                } else {
                    let out =
                        std::slice::from_raw_parts(ffi::fido_assert_hmac_secret_ptr(a, 0), len);
                    Ok(out
                        .chunks(SALT_LEN)
                        .map(|c| {
                            let mut k = Zeroizing::new([0u8; SALT_LEN]);
                            k.copy_from_slice(c);
                            k
                        })
                        .collect())
                }
            };
            // libfido2 zeroes the outputs when it frees the assertion.
            ffi::fido_assert_free(&mut a);
            result
        }
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        // SAFETY: `dev` is open, and closed and freed once.
        unsafe {
            ffi::fido_dev_close(self.dev);
            ffi::fido_dev_free(&mut self.dev);
        }
    }
}
