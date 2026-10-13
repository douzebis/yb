// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Spec 0036: yb's bash completion, through `clap-complete-rawline` and yb's
//! own command definition.  `complete_line(line, word)` gets what the bash
//! script passes: the raw line up to the cursor, and readline's current word
//! (`$2`, which bash ends at `=`, `:` and other `COMP_WORDBREAKS`).

use clap::CommandFactory;
use clap_complete_rawline::complete_line;
use tempfile::TempDir;
use yb::Cli;
use yb_core::piv::virtual_piv::fixtures;
use yb_core::store::Store;
use yb_core::{store_blob, Compression, Encryption, PivBackend, StoreOptions, VirtualPiv};

const MGMT: &str = "010203040506070801020304050607080102030405060708";

fn complete(line: &str, word: &str, dir: &TempDir) -> Vec<String> {
    complete_line(&mut Cli::command(), line, word, Some(dir.path())).unwrap()
}

#[test]
fn subcommands_and_options() {
    let dir = TempDir::new().unwrap();
    assert!(complete("yb fe", "fe", &dir).contains(&"fetch".to_owned()));
    assert!(complete("yb store --no-c", "--no-c", &dir).contains(&"--no-compress".to_owned()));
}

/// Paths and blob names: one test, as it changes process-wide state (the
/// current directory, which clap_complete's path completer reads, and
/// `YB_FIXTURE`, a simulated YubiKey for the blob-name completer).
#[test]
fn paths_blob_names_and_serial_numbers() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("my file.txt"), b"x").unwrap();
    std::fs::write(dir.path().join("a:b.txt"), b"x").unwrap();
    std::fs::create_dir(dir.path().join("sub dir")).unwrap();
    std::env::set_current_dir(dir.path()).unwrap();

    // `my\ f`: one shell word; readline replaces all of it.
    assert_eq!(complete(r"yb store my\ f", r"my\ f", &dir), ["my file.txt"]);
    // Inside an open quote: readline's word is the text after the quote.
    assert_eq!(complete(r#"yb store "my f"#, "my f", &dir), ["my file.txt"]);
    // After `:`, readline's word starts after it: only `b.txt` is inserted
    // (the patched script of spec 0020 corrupted this line).
    assert_eq!(complete("yb store a:", "", &dir), ["b.txt"]);
    // A directory gets its `/`, so the next Tab goes inside it.
    assert_eq!(complete(r"yb store sub\ d", r"sub\ d", &dir), ["sub dir/"]);

    let piv = VirtualPiv::from_fixture_yaml(fixtures::WITH_KEY).unwrap();
    let reader = piv.reader_name();
    let mut store = Store::format(&reader, &piv, 8, 0x82, MGMT).unwrap();
    let plain = || StoreOptions {
        encryption: Encryption::None,
        compression: Compression::None,
    };
    for name in ["alpha", "my secret"] {
        store_blob(&mut store, &piv, name, b"x", plain(), MGMT, None).unwrap();
    }
    let fixture = dir.path().join("card.yaml");
    piv.save_fixture(&fixture).unwrap();
    std::env::set_var("YB_FIXTURE", &fixture);
    let card_before = std::fs::read(&fixture).unwrap();

    assert_eq!(complete("yb fetch al", "al", &dir), ["alpha"]);
    assert_eq!(complete(r"yb fetch my\ s", r"my\ s", &dir), ["my secret"]);
    assert_eq!(complete(r#"yb fetch "my s"#, "my s", &dir), ["my secret"]);
    // `--serial=8`: readline's word starts after `=` (the patched script of
    // spec 0020 corrupted this line too).  The fixture's serial is 88888888.
    assert_eq!(complete("yb --serial=8", "8", &dir), ["88888888"]);
    assert_eq!(complete("yb --serial ", "", &dir), ["88888888"]);

    // Invariant 0002: completing reads the YubiKey, never writes to it.
    assert_eq!(std::fs::read(&fixture).unwrap(), card_before);

    std::env::remove_var("YB_FIXTURE");
}
