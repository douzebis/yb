// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Spec 0032: yb's documented exit statuses — 2 when a blob is not found,
//! 3 when the store is full — through the `yb` binary, on a simulated
//! YubiKey (`YB_FIXTURE`).

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tempfile::TempDir;
use yb_core::piv::virtual_piv::fixtures;
use yb_core::store::Store;
use yb_core::{store_blob, Compression, Encryption, PivBackend, StoreOptions, VirtualPiv};

const MGMT: &str = "010203040506070801020304050607080102030405060708";

/// A YubiKey with a certificate in slot 0x82 and a 4-object store holding
/// the blob `present`.
fn card(dir: &TempDir) -> PathBuf {
    let piv = VirtualPiv::from_fixture_yaml(fixtures::WITH_KEY).unwrap();
    let reader = piv.reader_name();
    // A certificate, so that encrypted stores work (spec 0037 tests).
    piv.generate_certificate(&reader, 0x82, "CN=Test", MGMT, None)
        .unwrap();
    let mut store = Store::format(&reader, &piv, 4, 0x82, MGMT).unwrap();
    let plain = StoreOptions {
        encryption: Encryption::None,
        compression: Compression::None,
    };
    store_blob(
        &mut store,
        &piv,
        "present",
        b"x",
        plain,
        MGMT,
        Some("654321"),
    )
    .unwrap();
    let path = dir.path().join("card.yaml");
    piv.save_fixture(&path).unwrap();
    path
}

/// Run `yb` on the simulated YubiKey; its exit status.
fn yb(card: &Path, args: &[&str], stdin: &[u8]) -> i32 {
    let mut child = Command::new(env!("CARGO_BIN_EXE_yb"))
        .env("YB_FIXTURE", card)
        .env("YB_PIN", "654321")
        .env_remove("YB_MANAGEMENT_KEY")
        .args(["--allow-defaults", "--quiet"])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut pipe = child.stdin.take().unwrap();
    // A command that does not read its input may close the pipe first.
    let _ = pipe.write_all(stdin);
    drop(pipe);
    child.wait().unwrap().code().unwrap()
}

#[test]
fn not_found_is_status_2() {
    let dir = TempDir::new().unwrap();
    let card = card(&dir);
    assert_eq!(yb(&card, &["fetch", "--stdout", "present"], b""), 0);
    assert_eq!(yb(&card, &["fetch", "--stdout", "absent"], b""), 2);
    assert_eq!(yb(&card, &["fetch", "--stdout", "abs*"], b""), 2);
    assert_eq!(yb(&card, &["rm", "absent"], b""), 2);
    assert_eq!(yb(&card, &["rm", "-f", "absent"], b""), 0);
}

#[test]
fn store_full_is_status_3_and_other_errors_1() {
    let dir = TempDir::new().unwrap();
    let card = card(&dir);
    // Three free objects of at most 3,063 bytes cannot hold 20 kB.
    let big = vec![0x5Au8; 20_000];
    let args = ["store", "--unencrypted", "--no-compress", "--name", "big"];
    assert_eq!(yb(&card, &args, &big), 3);
    // Any other error: 1 (here, a name that is not allowed).
    let bad = ["store", "--unencrypted", "--name", "a/b"];
    assert_eq!(yb(&card, &bad, b"x"), 1);
    assert_eq!(
        yb(&card, &["store", "--unencrypted", "--name", "small"], b"x"),
        0
    );
}

// ---------------------------------------------------------------------------
// Spec 0037: the PIN and the payload on one standard input
// ---------------------------------------------------------------------------

/// Run `yb --pin-stdin` with `stdin` as its whole standard input (no
/// `YB_PIN`); its exit status and standard output.
fn yb_pin_stdin(card: &Path, args: &[&str], stdin: &[u8]) -> (i32, Vec<u8>) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_yb"))
        .env("YB_FIXTURE", card)
        .env_remove("YB_PIN")
        .env_remove("YB_MANAGEMENT_KEY")
        .args(["--allow-defaults", "--quiet", "--pin-stdin"])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut pipe = child.stdin.take().unwrap();
    let _ = pipe.write_all(stdin);
    drop(pipe);
    let out = child.wait_with_output().unwrap();
    (out.status.code().unwrap(), out.stdout)
}

/// Store `payload` after the PIN line `pin_line`, fetch it back with the
/// PIN alone on standard input, and return what came back.
fn round_trip(card: &Path, pin_line: &[u8], payload: &[u8]) -> Vec<u8> {
    let input = [pin_line, payload].concat();
    let store = ["store", "--encrypted", "--no-compress", "-n", "blob2"];
    assert_eq!(yb_pin_stdin(card, &store, &input).0, 0);
    let (code, out) = yb_pin_stdin(card, &["fetch", "-p", "blob2"], b"654321\n");
    assert_eq!(code, 0);
    out
}

/// The payload after the PIN line comes through byte for byte: NUL bytes,
/// `\r\n`, runs of `\n`, no final newline.
#[test]
fn binary_payload_follows_the_pin_line() {
    let dir = TempDir::new().unwrap();
    let card = card(&dir);
    let payload = b"\0KDBX\r\n\n\n\x00\xff line\r\nlast, no newline";
    assert_eq!(round_trip(&card, b"654321\n", payload), payload);
}

/// An empty payload is stored as an empty blob.
#[test]
fn empty_payload_after_the_pin_line() {
    let dir = TempDir::new().unwrap();
    let card = card(&dir);
    assert_eq!(round_trip(&card, b"654321\n", b""), b"");
}

/// A `\r\n` line end is not part of the PIN, and only the first line is.
#[test]
fn pin_line_with_crlf() {
    let dir = TempDir::new().unwrap();
    let card = card(&dir);
    let payload = b"\r\nstarts with a line end";
    assert_eq!(round_trip(&card, b"654321\r\n", payload), payload);
}

/// Input without a newline is all PIN.
#[test]
fn pin_without_newline() {
    let dir = TempDir::new().unwrap();
    let card = card(&dir);
    let (code, out) = yb_pin_stdin(&card, &["fetch", "-p", "present"], b"654321");
    assert_eq!((code, out), (0, b"x".to_vec()));
}

/// `--pin`, removed in 0.7, is refused with its replacement named, and no
/// PIN is used.
#[test]
fn removed_pin_option_is_refused() {
    let dir = TempDir::new().unwrap();
    let card = card(&dir);
    let out = Command::new(env!("CARGO_BIN_EXE_yb"))
        .env("YB_FIXTURE", &card)
        .env_remove("YB_PIN")
        .args([
            "--allow-defaults",
            "--pin",
            "654321",
            "fetch",
            "-p",
            "present",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--pin was removed in yb 0.7"), "{stderr}");
    assert!(stderr.contains("--pin-stdin"), "{stderr}");
}
