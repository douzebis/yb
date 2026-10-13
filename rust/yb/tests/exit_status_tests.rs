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

/// A YubiKey with a 4-object store holding the blob `present`.
fn card(dir: &TempDir) -> PathBuf {
    let piv = VirtualPiv::from_fixture_yaml(fixtures::WITH_KEY).unwrap();
    let reader = piv.reader_name();
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
