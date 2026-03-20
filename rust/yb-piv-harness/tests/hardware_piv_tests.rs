// SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Tier-2 integration tests for `HardwarePiv`.
//!
//! Runs `HardwarePiv` against a `piv-authenticator` virtual card connected to
//! `pcscd` via `vpcd`.  Requires `vsmartcard-vpcd` installed and `pcscd`
//! running.  Tests are skipped gracefully if `vpcd` is unavailable.
//!
//! Run with:
//!   cargo test -p yb-piv-harness --features integration-tests

use yb_core::piv::hardware::HardwarePiv;
use yb_core::piv::PivBackend;
use yb_piv_harness::{with_vsc, Options};

fn hardware_piv() -> HardwarePiv {
    HardwarePiv::new()
}

const MGMT: &str = "010203040506070801020304050607080102030405060708";

macro_rules! skip_if_absent {
    ($opt:expr) => {
        match $opt {
            Some(v) => v,
            None => return,
        }
    };
}

/// list_readers returns a reader that contains the virtual card.
#[test]
fn t2_list_readers() {
    skip_if_absent!(with_vsc(Options::default(), |reader| {
        let piv = hardware_piv();
        let readers = piv.list_readers().unwrap();
        assert!(
            readers.iter().any(|r| r == reader),
            "virtual reader '{reader}' not found in {readers:?}"
        );
    }));
}

/// list_devices returns exactly one device.
#[test]
fn t2_list_devices() {
    skip_if_absent!(with_vsc(Options::default(), |_reader| {
        let piv = hardware_piv();
        let devices = piv.list_devices().unwrap();
        assert_eq!(devices.len(), 1);
        // piv-authenticator reports version 5.x
        assert!(!devices[0].version.is_empty());
    }));
}

/// read_object errors on an unpopulated object ID.
#[test]
fn t2_read_object_missing() {
    skip_if_absent!(with_vsc(Options::default(), |reader| {
        let piv = hardware_piv();
        assert!(piv.read_object(&reader, 0x5F_C105).is_err());
    }));
}

/// write_object + read_object round-trip with the default 3DES management key.
#[test]
fn t2_write_read_object() {
    skip_if_absent!(with_vsc(Options::default(), |reader| {
        let piv = hardware_piv();
        let data = b"hello tier-2";
        piv.write_object(&reader, 0x5F_C105, data, Some(MGMT), None)
            .unwrap();
        let result = piv.read_object(&reader, 0x5F_C105).unwrap();
        assert_eq!(result, data);
    }));
}

/// write_object with a wrong management key is rejected.
#[test]
fn t2_write_wrong_mgmt_key() {
    skip_if_absent!(with_vsc(Options::default(), |reader| {
        let piv = hardware_piv();
        let result = piv.write_object(&reader, 0x5F_C105, b"x", Some("aabbccdd"), None);
        assert!(result.is_err());
    }));
}

/// verify_pin succeeds with the default PIN, fails with a wrong PIN.
#[test]
fn t2_verify_pin() {
    skip_if_absent!(with_vsc(Options::default(), |reader| {
        let piv = hardware_piv();
        assert!(piv.verify_pin(&reader, "123456").is_ok());
        assert!(piv.verify_pin(&reader, "wrong").is_err());
    }));
}

/// generate_key returns a 65-byte uncompressed P-256 point.
#[test]
fn t2_generate_key() {
    skip_if_absent!(with_vsc(Options::default(), |reader| {
        let piv = hardware_piv();
        let point = piv.generate_key(&reader, 0x82, Some(MGMT)).unwrap();
        assert_eq!(point.len(), 65);
        assert_eq!(point[0], 0x04, "expected uncompressed point");
    }));
}

/// generate_key without management key auth is rejected.
#[test]
fn t2_generate_key_no_auth() {
    skip_if_absent!(with_vsc(Options::default(), |reader| {
        let piv = hardware_piv();
        assert!(piv.generate_key(&reader, 0x82, None).is_err());
    }));
}

/// ecdh with a software ephemeral key returns a 32-byte shared secret.
#[test]
fn t2_ecdh() {
    skip_if_absent!(with_vsc(Options::default(), |reader| {
        let piv = hardware_piv();

        // Generate a key in slot 0x82.
        piv.generate_key(&reader, 0x82, Some(MGMT)).unwrap();

        // Perform ECDH with a software-generated ephemeral key.
        use p256::{ecdh::EphemeralSecret, elliptic_curve::sec1::ToEncodedPoint, PublicKey};
        use rand::rngs::OsRng;
        let ephemeral = EphemeralSecret::random(&mut OsRng);
        let epk: PublicKey = (&ephemeral).into();
        let epk_bytes = epk.to_encoded_point(false).as_bytes().to_vec();

        let secret = piv.ecdh(&reader, 0x82, &epk_bytes, Some("123456")).unwrap();
        assert_eq!(secret.len(), 32);
    }));
}

/// generate_certificate stores a cert that can be read back.
#[test]
fn t2_generate_certificate() {
    skip_if_absent!(with_vsc(Options::default(), |reader| {
        let piv = hardware_piv();
        let cert_der = piv
            .generate_certificate(&reader, 0x82, "CN=T2Test", Some(MGMT), None)
            .unwrap();
        assert!(!cert_der.is_empty());
        let read_back = piv.read_certificate(&reader, 0x82).unwrap();
        assert_eq!(cert_der, read_back);
    }));
}
