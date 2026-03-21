// SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! CLI-level integration tests.
//!
//! These tests call the CLI command `run()` functions directly with
//! constructed `Args` structs and a `Context` built from `VirtualPiv`.
//! No real YubiKey is required.

use std::path::Path;
use std::sync::Arc;
use tempfile::TempDir;
use yb_core::{list_blobs, store::Store, Context, VirtualPiv};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const MGMT: &str = "010203040506070801020304050607080102030405060708";
const PIN: &str = "123456";

fn fixture(name: &str) -> std::path::PathBuf {
    // Fixtures live in yb-core's test directory.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../yb-core/tests/fixtures")
        .join(name)
}

fn with_key_piv() -> VirtualPiv {
    VirtualPiv::from_fixture(&fixture("with_key.yaml")).unwrap()
}

/// Build a Context backed by the given VirtualPiv, with management key + PIN
/// pre-resolved (simulating what main.rs does after env/TTY resolution).
fn make_ctx(piv: VirtualPiv) -> Context {
    let mut ctx = Context::with_backend(Arc::new(piv), Some(PIN.to_owned()), false).unwrap();
    ctx.management_key = Some(MGMT.to_owned());
    ctx.quiet = true;
    ctx
}

/// Format a store inside the given context's backend.
fn format_store(ctx: &Context) {
    Store::format(
        &ctx.reader,
        ctx.piv.as_ref(),
        8,
        512,
        0x82,
        Some(MGMT),
        None,
    )
    .unwrap();
}

// ---------------------------------------------------------------------------
// store
// ---------------------------------------------------------------------------

use yb::cli::store::{run as store_run, StoreArgs};

#[test]
fn store_single_file_by_basename() {
    let piv = with_key_piv();
    let ctx = make_ctx(piv);
    // Generate a certificate so the encrypted path can read the public key.
    ctx.piv
        .generate_certificate(&ctx.reader, 0x82, "CN=Test", Some(MGMT), None)
        .unwrap();
    format_store(&ctx);

    let tmp = TempDir::new().unwrap();
    let file = tmp.path().join("myblob.txt");
    std::fs::write(&file, b"hello").unwrap();

    let args = StoreArgs {
        files: vec![file],
        name: None,
        encrypted: true,
        unencrypted: false,
    };
    store_run(&ctx, &args).unwrap();

    let store = Store::from_device(&ctx.reader, ctx.piv.as_ref()).unwrap();
    let blobs = list_blobs(&store);
    assert_eq!(blobs.len(), 1);
    assert_eq!(blobs[0].name, "myblob.txt");
    assert!(blobs[0].is_encrypted);
}

#[test]
fn store_single_file_with_name_override() {
    let piv = with_key_piv();
    let ctx = make_ctx(piv);
    format_store(&ctx);

    let tmp = TempDir::new().unwrap();
    let file = tmp.path().join("original.txt");
    std::fs::write(&file, b"data").unwrap();

    let args = StoreArgs {
        files: vec![file],
        name: Some("renamed".to_owned()),
        encrypted: false,
        unencrypted: true,
    };
    store_run(&ctx, &args).unwrap();

    let store = Store::from_device(&ctx.reader, ctx.piv.as_ref()).unwrap();
    let blobs = list_blobs(&store);
    assert_eq!(blobs.len(), 1);
    assert_eq!(blobs[0].name, "renamed");
}

#[test]
fn store_multiple_files() {
    let piv = with_key_piv();
    let ctx = make_ctx(piv);
    format_store(&ctx);

    let tmp = TempDir::new().unwrap();
    let a = tmp.path().join("alpha.txt");
    let b = tmp.path().join("beta.txt");
    std::fs::write(&a, b"aaa").unwrap();
    std::fs::write(&b, b"bbb").unwrap();

    let args = StoreArgs {
        files: vec![a, b],
        name: None,
        encrypted: false,
        unencrypted: true,
    };
    store_run(&ctx, &args).unwrap();

    let store = Store::from_device(&ctx.reader, ctx.piv.as_ref()).unwrap();
    let mut names: Vec<_> = list_blobs(&store).into_iter().map(|b| b.name).collect();
    names.sort();
    assert_eq!(names, vec!["alpha.txt", "beta.txt"]);
}

#[test]
fn store_multiple_files_name_flag_rejected() {
    let piv = with_key_piv();
    let ctx = make_ctx(piv);
    format_store(&ctx);

    let tmp = TempDir::new().unwrap();
    let a = tmp.path().join("a.txt");
    let b = tmp.path().join("b.txt");
    std::fs::write(&a, b"a").unwrap();
    std::fs::write(&b, b"b").unwrap();

    let args = StoreArgs {
        files: vec![a, b],
        name: Some("clash".to_owned()),
        encrypted: false,
        unencrypted: true,
    };
    assert!(store_run(&ctx, &args).is_err());
}

#[test]
fn store_duplicate_basename_rejected() {
    let piv = with_key_piv();
    let ctx = make_ctx(piv);
    format_store(&ctx);

    let tmp = TempDir::new().unwrap();
    let d1 = tmp.path().join("d1");
    let d2 = tmp.path().join("d2");
    std::fs::create_dir_all(&d1).unwrap();
    std::fs::create_dir_all(&d2).unwrap();
    std::fs::write(d1.join("config"), b"one").unwrap();
    std::fs::write(d2.join("config"), b"two").unwrap();

    let args = StoreArgs {
        files: vec![d1.join("config"), d2.join("config")],
        name: None,
        encrypted: false,
        unencrypted: true,
    };
    let err = store_run(&ctx, &args).unwrap_err();
    assert!(err.to_string().contains("duplicate blob name"));
}

// ---------------------------------------------------------------------------
// fetch
// ---------------------------------------------------------------------------

use yb::cli::fetch::{run as fetch_run, FetchArgs};

fn store_plain(ctx: &Context, name: &str, payload: &[u8]) {
    let tmp = TempDir::new().unwrap();
    let file = tmp.path().join(name);
    std::fs::write(&file, payload).unwrap();
    let args = StoreArgs {
        files: vec![file],
        name: Some(name.to_owned()),
        encrypted: false,
        unencrypted: true,
    };
    store_run(ctx, &args).unwrap();
}

#[test]
fn fetch_to_file_default() {
    let piv = with_key_piv();
    let ctx = make_ctx(piv);
    format_store(&ctx);
    store_plain(&ctx, "myblob", b"contents");

    let out_dir = TempDir::new().unwrap();
    let args = FetchArgs {
        patterns: vec!["myblob".to_owned()],
        stdout: false,
        output: None,
        output_dir: Some(out_dir.path().to_path_buf()),
        extract: false,
    };
    fetch_run(&ctx, &args).unwrap();

    let result = std::fs::read(out_dir.path().join("myblob")).unwrap();
    assert_eq!(result, b"contents");
}

#[test]
fn fetch_to_explicit_output() {
    let piv = with_key_piv();
    let ctx = make_ctx(piv);
    format_store(&ctx);
    store_plain(&ctx, "sec", b"secret");

    let out_dir = TempDir::new().unwrap();
    let out_file = out_dir.path().join("out.bin");
    let args = FetchArgs {
        patterns: vec!["sec".to_owned()],
        stdout: false,
        output: Some(out_file.clone()),
        output_dir: None,
        extract: false,
    };
    fetch_run(&ctx, &args).unwrap();
    assert_eq!(std::fs::read(&out_file).unwrap(), b"secret");
}

#[test]
fn fetch_glob_pattern() {
    let piv = with_key_piv();
    let ctx = make_ctx(piv);
    format_store(&ctx);
    store_plain(&ctx, "key-a", b"a");
    store_plain(&ctx, "key-b", b"b");
    store_plain(&ctx, "other", b"c");

    let out_dir = TempDir::new().unwrap();
    let args = FetchArgs {
        patterns: vec!["key-*".to_owned()],
        stdout: false,
        output: None,
        output_dir: Some(out_dir.path().to_path_buf()),
        extract: false,
    };
    fetch_run(&ctx, &args).unwrap();

    assert_eq!(std::fs::read(out_dir.path().join("key-a")).unwrap(), b"a");
    assert_eq!(std::fs::read(out_dir.path().join("key-b")).unwrap(), b"b");
    assert!(!out_dir.path().join("other").exists());
}

#[test]
fn fetch_stdout_multi_match_rejected() {
    let piv = with_key_piv();
    let ctx = make_ctx(piv);
    format_store(&ctx);
    store_plain(&ctx, "x", b"x");
    store_plain(&ctx, "y", b"y");

    let args = FetchArgs {
        patterns: vec!["*".to_owned()],
        stdout: true,
        output: None,
        output_dir: None,
        extract: false,
    };
    assert!(fetch_run(&ctx, &args).is_err());
}

#[test]
fn fetch_missing_blob_errors() {
    let piv = with_key_piv();
    let ctx = make_ctx(piv);
    format_store(&ctx);

    let args = FetchArgs {
        patterns: vec!["ghost".to_owned()],
        stdout: false,
        output: None,
        output_dir: None,
        extract: false,
    };
    assert!(fetch_run(&ctx, &args).is_err());
}

#[test]
fn fetch_output_and_output_dir_mutually_exclusive() {
    let piv = with_key_piv();
    let ctx = make_ctx(piv);
    format_store(&ctx);
    store_plain(&ctx, "b", b"b");

    let tmp = TempDir::new().unwrap();
    let args = FetchArgs {
        patterns: vec!["b".to_owned()],
        stdout: false,
        output: Some(tmp.path().join("out")),
        output_dir: Some(tmp.path().to_path_buf()),
        extract: false,
    };
    assert!(fetch_run(&ctx, &args).is_err());
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

use yb::cli::list::{run as list_run, ListArgs};

#[test]
fn list_empty_store() {
    let piv = with_key_piv();
    let ctx = make_ctx(piv);
    format_store(&ctx);

    let args = ListArgs {
        pattern: None,
        long: false,
        one_per_line: false,
        sort_time: false,
        reverse: false,
    };
    // Should succeed with no output (empty store).
    list_run(&ctx, &args).unwrap();
}

#[test]
fn list_glob_filter() {
    let piv = with_key_piv();
    let ctx = make_ctx(piv);
    format_store(&ctx);
    store_plain(&ctx, "foo-1", b"x");
    store_plain(&ctx, "foo-2", b"x");
    store_plain(&ctx, "bar", b"x");

    // We test that it runs without error; output goes to stdout in tests.
    let args = ListArgs {
        pattern: Some("foo-*".to_owned()),
        long: false,
        one_per_line: false,
        sort_time: false,
        reverse: false,
    };
    list_run(&ctx, &args).unwrap();
}

// ---------------------------------------------------------------------------
// remove
// ---------------------------------------------------------------------------

use yb::cli::remove::{run as remove_run, RemoveArgs};

#[test]
fn remove_single_blob() {
    let piv = with_key_piv();
    let ctx = make_ctx(piv);
    format_store(&ctx);
    store_plain(&ctx, "target", b"data");

    let args = RemoveArgs {
        patterns: vec!["target".to_owned()],
        ignore_missing: false,
    };
    remove_run(&ctx, &args).unwrap();

    let store = Store::from_device(&ctx.reader, ctx.piv.as_ref()).unwrap();
    assert_eq!(list_blobs(&store).len(), 0);
}

#[test]
fn remove_glob_pattern() {
    let piv = with_key_piv();
    let ctx = make_ctx(piv);
    format_store(&ctx);
    store_plain(&ctx, "tmp-a", b"a");
    store_plain(&ctx, "tmp-b", b"b");
    store_plain(&ctx, "keep", b"k");

    let args = RemoveArgs {
        patterns: vec!["tmp-*".to_owned()],
        ignore_missing: false,
    };
    remove_run(&ctx, &args).unwrap();

    let store = Store::from_device(&ctx.reader, ctx.piv.as_ref()).unwrap();
    let names: Vec<_> = list_blobs(&store).into_iter().map(|b| b.name).collect();
    assert_eq!(names, vec!["keep"]);
}

#[test]
fn remove_missing_errors_without_flag() {
    let piv = with_key_piv();
    let ctx = make_ctx(piv);
    format_store(&ctx);

    let args = RemoveArgs {
        patterns: vec!["ghost".to_owned()],
        ignore_missing: false,
    };
    assert!(remove_run(&ctx, &args).is_err());
}

#[test]
fn remove_missing_ok_with_ignore_flag() {
    let piv = with_key_piv();
    let ctx = make_ctx(piv);
    format_store(&ctx);

    let args = RemoveArgs {
        patterns: vec!["ghost".to_owned()],
        ignore_missing: true,
    };
    assert!(remove_run(&ctx, &args).is_ok());
}

#[test]
fn remove_deduplicates_overlapping_patterns() {
    let piv = with_key_piv();
    let ctx = make_ctx(piv);
    format_store(&ctx);
    store_plain(&ctx, "x", b"x");

    // Two patterns both match "x" — should still succeed (removed once).
    let args = RemoveArgs {
        patterns: vec!["x".to_owned(), "*".to_owned()],
        ignore_missing: false,
    };
    remove_run(&ctx, &args).unwrap();

    let store = Store::from_device(&ctx.reader, ctx.piv.as_ref()).unwrap();
    assert_eq!(list_blobs(&store).len(), 0);
}

// ---------------------------------------------------------------------------
// fsck
// ---------------------------------------------------------------------------

use yb::cli::fsck::{run as fsck_run, FsckArgs};

#[test]
fn fsck_clean_store() {
    let piv = with_key_piv();
    let ctx = make_ctx(piv);
    format_store(&ctx);
    store_plain(&ctx, "a", b"data");

    // fsck on a clean store should succeed.
    let args = FsckArgs { verbose: false };
    fsck_run(&ctx, &args).unwrap();
}

// ---------------------------------------------------------------------------
// format (--key-slot parsing)
// ---------------------------------------------------------------------------

use yb::cli::format::{run as format_run, FormatArgs};
use yb_core::store::constants::{DEFAULT_OBJECT_COUNT, DEFAULT_OBJECT_SIZE, DEFAULT_SUBJECT};

#[test]
fn format_key_slot_hex_prefix() {
    let piv = with_key_piv();
    let ctx = make_ctx(piv);
    // Pre-generate a cert in slot 0x82 so verify_certificate passes.
    ctx.piv
        .generate_certificate(&ctx.reader, 0x82, "CN=Test", Some(MGMT), None)
        .unwrap();

    let args = FormatArgs {
        object_count: DEFAULT_OBJECT_COUNT,
        object_size: DEFAULT_OBJECT_SIZE,
        key_slot: "0x82".to_owned(),
        generate: false,
        subject: DEFAULT_SUBJECT.to_owned(),
    };
    format_run(&ctx, &args).unwrap();
}

#[test]
fn format_key_slot_decimal() {
    let piv = with_key_piv();
    let ctx = make_ctx(piv);
    // 130 decimal == 0x82.
    ctx.piv
        .generate_certificate(&ctx.reader, 0x82, "CN=Test", Some(MGMT), None)
        .unwrap();

    let args = FormatArgs {
        object_count: DEFAULT_OBJECT_COUNT,
        object_size: DEFAULT_OBJECT_SIZE,
        key_slot: "130".to_owned(),
        generate: false,
        subject: DEFAULT_SUBJECT.to_owned(),
    };
    format_run(&ctx, &args).unwrap();
}

#[test]
fn format_key_slot_invalid_rejected() {
    let piv = with_key_piv();
    let ctx = make_ctx(piv);

    let args = FormatArgs {
        object_count: DEFAULT_OBJECT_COUNT,
        object_size: DEFAULT_OBJECT_SIZE,
        key_slot: "notanumber".to_owned(),
        generate: false,
        subject: DEFAULT_SUBJECT.to_owned(),
    };
    assert!(format_run(&ctx, &args).is_err());
}
