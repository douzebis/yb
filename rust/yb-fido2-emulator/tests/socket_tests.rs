// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Spec 0028 — the emulator served on a socket, as the command-line tests
//! use it: a `yb` built with `test-fixture` finds it through
//! `YB_FIDO2_SOCKET`, pairs it by serial, and its state lasts across
//! connections (processes).

use yb_core::fido2::pairing::open_yubikey;
use yb_core::fido2::socket::SOCKET_ENV;
use yb_core::fido2::Fido2Error;
use yb_fido2_emulator::server::Server;

#[test]
fn served_emulator() {
    let dir = std::env::temp_dir().join(format!("yb-fido2-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let server = Server::start(&dir.join("emulator.sock"), Some(4242)).unwrap();
    std::env::set_var(SOCKET_ENV, &server.path);

    // A first "process": set the PIN, create a credential.
    let dev = open_yubikey(4242, 1, &|| {}).unwrap();
    assert!(!dev.has_pin());
    dev.set_pin("654321").unwrap();
    let cred = dev.make_credential("654321").unwrap();
    let k = dev.hmac_secret(&cred.id, &[[1; 32]], "654321").unwrap();
    drop(dev);

    // A second one sees the same authenticator.
    let dev = open_yubikey(4242, 1, &|| {}).unwrap();
    assert!(dev.has_pin());
    assert_eq!(
        *dev.hmac_secret(&cred.id, &[[1; 32]], "654321").unwrap()[0],
        *k[0]
    );
    assert_eq!(server.touches(), 3);

    server.set_touch(false);
    let err = dev.hmac_secret(&cred.id, &[[1; 32]], "654321").unwrap_err();
    assert_eq!(err.downcast::<Fido2Error>().unwrap(), Fido2Error::NoTouch);
    server.set_touch(true);

    // Another serial is not this YubiKey.  (The server serves one
    // connection at a time, as yb processes run one after the other.)
    drop(dev);
    let start = std::time::Instant::now();
    let Err(err) = open_yubikey(4243, 1, &|| {}) else {
        panic!("another serial was paired");
    };
    assert!(err.to_string().contains("not found"), "{err:#}");
    assert!(start.elapsed().as_secs() < 2, "waited for a timeout");
    let _ = std::fs::remove_dir_all(&dir);
}
