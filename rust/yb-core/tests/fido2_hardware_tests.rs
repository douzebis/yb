// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Spec 0028 — `yb_core::fido2` against a real YubiKey.  Ignored by
//! default; run with a test YubiKey plugged in:
//!
//! ```text
//! cargo test -p yb-core --test fido2_hardware_tests -- --ignored --nocapture
//! YB_FIDO2_PIN=... cargo test ... -- --ignored --nocapture   # with touches
//! ```

use yb_core::fido2::{self, hid, Device, Fido2Error, YUBICO_VENDOR_ID};

fn yubikey_path() -> String {
    fido2::list_devices()
        .unwrap()
        .into_iter()
        .find(|d| d.vendor_id == YUBICO_VENDOR_ID)
        .expect("no YubiKey FIDO device")
        .path
}

/// No touch, no PIN: list, read the serial, PIN state and attempts.
#[test]
#[ignore]
fn identity() {
    let path = yubikey_path();
    #[cfg(target_os = "linux")]
    {
        let mut ch = hid::Hidraw::open(&path).unwrap();
        let serial = hid::read_serial(&mut ch).unwrap();
        println!("{path}: serial {serial:?}");
        assert!(serial.is_some());
    }
    let dev = Device::open(&path).unwrap();
    println!(
        "PIN set: {}, attempts left: {}",
        dev.has_pin(),
        dev.pin_retries().unwrap()
    );
}

/// With `YB_FIDO2_PIN` and three touches: a credential, then one and two
/// salts (the first output is the same).  Nothing is stored on the key.
#[test]
#[ignore]
fn credential_and_hmac_secret() {
    let Ok(pin) = std::env::var("YB_FIDO2_PIN") else {
        eprintln!("YB_FIDO2_PIN not set: skipped");
        return;
    };
    let dev = Device::open(&yubikey_path()).unwrap();
    eprintln!("touch the YubiKey (1/3)");
    let cred = dev.make_credential(&pin).unwrap();
    println!("credential ID: {} bytes", cred.id.len());
    let (s1, s2) = ([0x11u8; 32], [0x22u8; 32]);
    eprintln!("touch the YubiKey (2/3)");
    let one = dev.hmac_secret(&cred.id, &[s1], &pin).unwrap();
    eprintln!("touch the YubiKey (3/3)");
    let two = dev.hmac_secret(&cred.id, &[s1, s2], &pin).unwrap();
    assert_eq!(two.len(), 2);
    assert_eq!(*one[0], *two[0]);
    assert_ne!(*two[0], *two[1]);
    let wrong = dev.hmac_secret(b"not a credential", &[s1], &pin);
    let err = wrong.unwrap_err().downcast::<Fido2Error>().unwrap();
    println!("unknown credential: {err}");
}

/// With `YB_FIDO2_PIN`: one touch to create a credential, then
/// `find_credential` among it and a stranger's ID, which must answer
/// **without a touch** (spec 0028, "Finding the FIDO2 side").
#[test]
#[ignore]
fn find_credential_without_touch() {
    let Ok(pin) = std::env::var("YB_FIDO2_PIN") else {
        eprintln!("YB_FIDO2_PIN not set: skipped");
        return;
    };
    let dev = Device::open(&yubikey_path()).unwrap();
    eprintln!("TOUCH the YubiKey now (creating a credential)");
    let cred = dev.make_credential(&pin).unwrap();
    eprintln!("now do NOT touch the YubiKey");
    let stranger = vec![0x42u8; cred.id.len()];
    let start = std::time::Instant::now();
    let found = dev.find_credential(&[&stranger, &cred.id], &pin);
    let elapsed = start.elapsed();
    println!("find_credential: {found:?} after {elapsed:?}");
    assert_eq!(found.unwrap().as_deref(), Some(&cred.id[..]));
    let none = dev.find_credential(&[&stranger], &pin).unwrap();
    println!("stranger only: {none:?}");
    assert_eq!(none, None);
    assert_eq!(dev.pin_retries().unwrap(), 8);
}
