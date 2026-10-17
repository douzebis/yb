// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Spec 0028 — `yb_core::fido2` against the in-memory emulator (OpenSK
//! under libfido2): the behaviors measured on a YubiKey 5.7.1 (spec 0028,
//! "Hardware results", "Tests").

use yb_core::fido2::ffi::FidoDevIo;
use yb_core::fido2::hid::{read_serial, IoChannel};
use yb_core::fido2::{Device, Fido2Error};
use yb_fido2_emulator as emulator;

const IO: FidoDevIo = FidoDevIo {
    open: emulator::io_open,
    close: emulator::io_close,
    read: emulator::io_read,
    write: emulator::io_write,
};
const SERIAL: u32 = 32_283_437;
const PIN: &str = "654321";
const S1: [u8; 32] = [0x11; 32];
const S2: [u8; 32] = [0x22; 32];

/// A fresh emulator with a FIDO2 PIN set, opened.
fn device_with_pin() -> Device {
    emulator::power_on(Some(SERIAL));
    emulator::set_touch(true);
    let dev = Device::open_with_io(&IO).unwrap();
    assert!(!dev.has_pin());
    dev.set_pin(PIN).unwrap();
    assert!(dev.has_pin());
    dev
}

fn fido2_error(e: anyhow::Error) -> Fido2Error {
    e.downcast::<Fido2Error>().expect("a Fido2Error")
}

#[test]
fn serial_over_vendor_command() {
    emulator::power_on(Some(SERIAL));
    let mut ch = IoChannel::open(&IO).unwrap();
    assert_eq!(read_serial(&mut ch).unwrap(), Some(SERIAL));

    emulator::power_on(None);
    let mut ch = IoChannel::open(&IO).unwrap();
    assert_eq!(read_serial(&mut ch).unwrap(), None);
}

#[test]
fn credential_and_two_salts_in_one_touch() {
    let dev = device_with_pin();
    assert_eq!(dev.pin_retries().unwrap(), 8);
    let cred = dev.make_credential(PIN).unwrap();
    assert!(!cred.id.is_empty() && cred.id.len() <= 255);

    let before = emulator::touches();
    let one = dev.hmac_secret(&cred.id, &[S1], PIN).unwrap();
    let two = dev.hmac_secret(&cred.id, &[S1, S2], PIN).unwrap();
    assert_eq!(emulator::touches() - before, 2, "one touch per assertion");
    assert_eq!(*one[0], *two[0], "the same salt gives the same output");
    assert_ne!(*two[0], *two[1]);
}

#[test]
fn refused_touch() {
    let dev = device_with_pin();
    let cred = dev.make_credential(PIN).unwrap();
    emulator::set_touch(false);
    let err = fido2_error(dev.hmac_secret(&cred.id, &[S1], PIN).unwrap_err());
    assert_eq!(err, Fido2Error::NoTouch);
    emulator::set_touch(true);
    assert_eq!(dev.pin_retries().unwrap(), 8, "no PIN attempt used");
}

#[test]
fn wrong_pins_block_until_power_cycle() {
    let dev = device_with_pin();
    let cred = dev.make_credential(PIN).unwrap();
    for _ in 0..2 {
        let err = fido2_error(dev.hmac_secret(&cred.id, &[S1], "000000").unwrap_err());
        assert_eq!(err, Fido2Error::PinInvalid);
    }
    let err = fido2_error(dev.hmac_secret(&cred.id, &[S1], "000000").unwrap_err());
    assert_eq!(err, Fido2Error::PinAuthBlocked);
    drop(dev);

    emulator::power_cycle();
    let dev = Device::open_with_io(&IO).unwrap();
    assert_eq!(dev.pin_retries().unwrap(), 5);
    dev.hmac_secret(&cred.id, &[S1], PIN).unwrap();
    assert_eq!(
        dev.pin_retries().unwrap(),
        8,
        "a correct PIN resets the count"
    );
}

#[test]
fn unknown_credential() {
    let dev = device_with_pin();
    let err = fido2_error(dev.hmac_secret(&[0x42; 64], &[S1], PIN).unwrap_err());
    assert_eq!(err, Fido2Error::NoCredential);
}

#[test]
fn state_survives_save_and_restore() {
    let dev = device_with_pin();
    let cred = dev.make_credential(PIN).unwrap();
    let k = dev.hmac_secret(&cred.id, &[S1], PIN).unwrap();
    drop(dev);

    let state = emulator::save_state();
    emulator::power_on(Some(SERIAL)); // discard everything
    emulator::restore_state(&state, Some(SERIAL));
    let dev = Device::open_with_io(&IO).unwrap();
    assert!(dev.has_pin());
    let again = dev.hmac_secret(&cred.id, &[S1], PIN).unwrap();
    assert_eq!(*k[0], *again[0]);
}

#[test]
fn find_credential_without_touch() {
    let dev = device_with_pin();
    let cred = dev.make_credential(PIN).unwrap();
    let stranger = vec![0x42u8; cred.id.len()];
    let before = emulator::touches();
    let found = dev.find_credential(&[&stranger, &cred.id], PIN).unwrap();
    assert_eq!(found.as_deref(), Some(&cred.id[..]));
    assert_eq!(dev.find_credential(&[&stranger], PIN).unwrap(), None);
    assert_eq!(emulator::touches(), before, "no touch asked");
}
