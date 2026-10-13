// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Spec 0032: `yb self-test` end to end, on a simulated YubiKey that the
//! self-test shares with its `yb` children through `YB_FIXTURE`.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use tempfile::TempDir;
use yb_core::piv::virtual_piv::fixtures;
use yb_core::{PivBackend, VirtualPiv};

/// A set-up YubiKey: PIN 654321, a key in slot 0x82.
fn card(dir: &TempDir) -> PathBuf {
    let path = dir.path().join("card.yaml");
    std::fs::write(&path, fixtures::WITH_KEY).unwrap();
    path
}

fn self_test(card: &Path, answer: &str, args: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_yb"))
        .env("YB_FIXTURE", card)
        // The self-test relies on no credential of the user's (G6).
        .env_remove("YB_PIN")
        .env_remove("YB_MANAGEMENT_KEY")
        .args(["self-test", "--no-flash"])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(answer.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

/// From a set-up YubiKey: reset, set-up, random operations including
/// refused stores (checked as genuinely full, G4), clean-up, final reset.
#[test]
fn self_test_passes_and_leaves_a_reset_yubikey() {
    let dir = TempDir::new().unwrap();
    let card = card(&dir);
    let out = self_test(&card, "yes\n", &["--count", "300", "--seed", "2"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(stderr.contains("ALL TESTS PASSED"), "{stderr}");
    assert!(stderr.contains("FULL ("), "no store was refused:\n{stderr}");

    // Factory state: PIN 123456, no key, no object.
    let piv = VirtualPiv::from_fixture(&card).unwrap();
    let reader = piv.reader_name();
    piv.verify_pin(&reader, "123456").unwrap();
    assert!(piv.read_certificate(&reader, 0x82).is_err());
    assert!(piv.read_object(&reader, 0x5F_0000).is_err());
}

/// `--quiet`: no progress lines, the report still shown.
#[test]
fn quiet_self_test_shows_the_report_only() {
    let dir = TempDir::new().unwrap();
    let card = card(&dir);
    let out = self_test(&card, "yes\n", &["--count", "20"]);
    let loud = String::from_utf8_lossy(&out.stderr).into_owned();
    let out = Command::new(env!("CARGO_BIN_EXE_yb"))
        .env("YB_FIXTURE", &card)
        .args(["--quiet", "self-test", "--no-flash", "--count", "20"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            c.stdin.take().unwrap().write_all(b"yes\n")?;
            c.wait_with_output()
        })
        .unwrap();
    let quiet = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{quiet}");
    assert!(loud.contains("remaining]"));
    assert!(!quiet.contains("remaining]"), "{quiet}");
    assert!(quiet.contains("ALL TESTS PASSED"), "{quiet}");
}

/// Anything but "yes": nothing changes.
#[test]
fn cancelled_self_test_changes_nothing() {
    let dir = TempDir::new().unwrap();
    let card = card(&dir);
    let before = std::fs::read(&card).unwrap();
    let out = self_test(&card, "no\n", &[]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(std::fs::read(&card).unwrap(), before);
}
