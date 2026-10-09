// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! CLI-level integration tests.
//!
//! These tests call the CLI command `run()` functions directly with
//! constructed `Args` structs and a `Context` built from `VirtualPiv`.
//! No real YubiKey is required.

use std::sync::Arc;
use tempfile::TempDir;
use yb_core::{list_blobs, piv::virtual_piv::fixtures, store::Store, Context, VirtualPiv};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const MGMT: &str = "010203040506070801020304050607080102030405060708";
/// PIN of the `with_key.yaml` and `aes192.yaml` fixtures (not the factory
/// PIN: they represent a card that has been set up, spec 0024 §4a).
const PIN: &str = "654321";

fn with_key_piv() -> VirtualPiv {
    VirtualPiv::from_fixture_yaml(fixtures::WITH_KEY).unwrap()
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
    Store::format(&ctx.reader, ctx.piv.as_ref(), 8, 0x82, MGMT).unwrap();
}

// ---------------------------------------------------------------------------
// store
// ---------------------------------------------------------------------------

mod store_tests {
    use super::*;
    use yb::cli::store::{run as store_run, StoreArgs};

    #[test]
    fn store_single_file_by_basename() {
        let piv = with_key_piv();
        let ctx = make_ctx(piv);
        // Generate a certificate so the encrypted path can read the public key.
        ctx.piv
            .generate_certificate(&ctx.reader, 0x82, "CN=Test", MGMT, None)
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
            no_compress: false,
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
            no_compress: false,
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
            no_compress: false,
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
            no_compress: false,
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
            no_compress: false,
        };
        let err = store_run(&ctx, &args).unwrap_err();
        assert!(err.to_string().contains("duplicate blob name"));
    }
}

// ---------------------------------------------------------------------------
// fetch
// ---------------------------------------------------------------------------

mod fetch_tests {
    use super::*;
    use yb::cli::fetch::{run as fetch_run, FetchArgs};
    use yb::cli::store::{run as store_run, StoreArgs};

    fn store_plain(ctx: &Context, name: &str, payload: &[u8]) {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join(name);
        std::fs::write(&file, payload).unwrap();
        let args = StoreArgs {
            files: vec![file],
            name: Some(name.to_owned()),
            encrypted: false,
            unencrypted: true,
            no_compress: false,
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
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

mod list_tests {
    use super::*;
    use yb::cli::list::{run as list_run, ListArgs};
    use yb::cli::store::{run as store_run, StoreArgs};

    fn store_plain(ctx: &Context, name: &str, payload: &[u8]) {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join(name);
        std::fs::write(&file, payload).unwrap();
        let args = StoreArgs {
            files: vec![file],
            name: Some(name.to_owned()),
            encrypted: false,
            unencrypted: true,
            no_compress: false,
        };
        store_run(ctx, &args).unwrap();
    }

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
}

// ---------------------------------------------------------------------------
// remove
// ---------------------------------------------------------------------------

mod remove_tests {
    use super::*;
    use yb::cli::remove::{run as remove_run, RemoveArgs};
    use yb::cli::store::{run as store_run, StoreArgs};

    fn store_plain(ctx: &Context, name: &str, payload: &[u8]) {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join(name);
        std::fs::write(&file, payload).unwrap();
        let args = StoreArgs {
            files: vec![file],
            name: Some(name.to_owned()),
            encrypted: false,
            unencrypted: true,
            no_compress: false,
        };
        store_run(ctx, &args).unwrap();
    }

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
}

// ---------------------------------------------------------------------------
// fsck
// ---------------------------------------------------------------------------

mod fsck_tests {
    use super::*;
    use yb::cli::fsck::{run as fsck_run, FsckArgs};
    use yb::cli::store::{run as store_run, StoreArgs};
    use yb::cli::util::{check_blob_signature, SigVerdict};
    use yb_core::store::constants::OBJECT_ID_ZERO;

    fn store_plain(ctx: &Context, name: &str, payload: &[u8]) {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join(name);
        std::fs::write(&file, payload).unwrap();
        let args = StoreArgs {
            files: vec![file],
            name: Some(name.to_owned()),
            encrypted: false,
            unencrypted: true,
            no_compress: false,
        };
        store_run(ctx, &args).unwrap();
    }

    /// Helper: create a store with a key+cert in slot 0x82, store one plain blob,
    /// and return the ctx.  The blob has a valid yb2 signature trailer.
    fn setup_signed_store() -> Context {
        let piv = with_key_piv();
        let ctx = make_ctx(piv);
        ctx.piv
            .generate_certificate(&ctx.reader, 0x82, "CN=Test", MGMT, None)
            .unwrap();
        format_store(&ctx);
        store_plain(&ctx, "blob", b"the payload bytes");
        ctx
    }

    /// Get the P-256 verifying key from the store's slot 0x82 cert.
    fn verifying_key(ctx: &Context) -> p256::ecdsa::VerifyingKey {
        let cert_der = ctx.piv.read_certificate(&ctx.reader, 0x82).unwrap();
        let pk = yb_core::parse_ec_public_key_from_cert_der(&cert_der).unwrap();
        p256::ecdsa::VerifyingKey::from(&pk)
    }

    /// Read the raw PIV object bytes for store object at `index`.
    fn read_raw(ctx: &Context, index: u32) -> Vec<u8> {
        ctx.piv
            .read_object(&ctx.reader, OBJECT_ID_ZERO + index)
            .unwrap()
    }

    /// Write raw PIV object bytes for store object at `index`.
    fn write_raw(ctx: &Context, index: u32, data: &[u8]) {
        ctx.piv
            .write_object(&ctx.reader, OBJECT_ID_ZERO + index, data, MGMT)
            .unwrap();
    }

    #[test]
    fn fsck_clean_store() {
        let piv = with_key_piv();
        let ctx = make_ctx(piv);
        format_store(&ctx);
        store_plain(&ctx, "a", b"data");

        // fsck on a clean store should succeed.
        let args = FsckArgs {
            verbose: false,
            nvm: false,
            check_key: false,
        };
        fsck_run(&ctx, &args).unwrap();
    }

    /// T9a: fsck verbose — run returns Ok on a store that has objects.
    #[test]
    fn fsck_verbose() {
        let piv = with_key_piv();
        let ctx = make_ctx(piv);
        format_store(&ctx);
        store_plain(&ctx, "verbose-blob", b"data");

        let args = FsckArgs {
            verbose: true,
            nvm: false,
            check_key: false,
        };
        fsck_run(&ctx, &args).unwrap();
    }

    /// T9b: detect_anomalies finds duplicate-named heads.
    #[test]
    fn fsck_detect_duplicate_name_anomaly() {
        use yb::cli::fsck::detect_anomalies;
        use yb_core::store::Store;

        let piv = with_key_piv();
        let ctx = make_ctx(piv);
        // Format a 4-object store.
        Store::format(&ctx.reader, ctx.piv.as_ref(), 4, 0x82, MGMT).unwrap();

        // Write two head objects with the same name by manipulating the store
        // in-memory and syncing.
        let mut store = Store::from_device(&ctx.reader, ctx.piv.as_ref()).unwrap();

        // Manually set both objects 0 and 1 as heads named "dup".
        let mut obj0 = store.make_object(yb_core::store::ObjectParams {
            index: 0,
            age: 1,
            chunk_pos: 0,
            next_chunk: 0,
        });
        obj0.blob_size = 1;
        obj0.blob_plain_size = 1;
        obj0.blob_name = "dup".to_owned();
        obj0.set_payload(vec![0]);
        store.objects[0] = obj0;

        let mut obj1 = store.make_object(yb_core::store::ObjectParams {
            index: 1,
            age: 2,
            chunk_pos: 0,
            next_chunk: 1,
        });
        obj1.blob_size = 1;
        obj1.blob_plain_size = 1;
        obj1.blob_name = "dup".to_owned();
        obj1.set_payload(vec![0]);
        store.objects[1] = obj1;
        store.sync(ctx.piv.as_ref(), MGMT).unwrap();

        // Re-read and run detect_anomalies.
        let store2 = Store::from_device(&ctx.reader, ctx.piv.as_ref()).unwrap();
        let warnings = detect_anomalies(&store2);
        assert!(
            !warnings.is_empty(),
            "duplicate blob name should produce a warning"
        );
        assert!(
            warnings.iter().any(|w| w.contains("duplicate")),
            "warning should mention 'duplicate': {warnings:?}"
        );
    }

    /// T9c: detect_anomalies finds an orphaned continuation chunk.
    #[test]
    fn fsck_detect_orphaned_continuation() {
        use yb::cli::fsck::detect_anomalies;
        use yb_core::store::Store;

        let piv = with_key_piv();
        let ctx = make_ctx(piv);
        Store::format(&ctx.reader, ctx.piv.as_ref(), 4, 0x82, MGMT).unwrap();

        let mut store = Store::from_device(&ctx.reader, ctx.piv.as_ref()).unwrap();

        // Object 0: valid single-chunk head "solo".
        let mut obj0 = store.make_object(yb_core::store::ObjectParams {
            index: 0,
            age: 1,
            chunk_pos: 0,
            next_chunk: 0,
        });
        obj0.blob_size = 1;
        obj0.blob_plain_size = 1;
        obj0.blob_name = "solo".to_owned();
        obj0.set_payload(vec![0]);
        store.objects[0] = obj0;

        // Object 1: orphaned continuation (no head points to it).
        let mut obj1 = store.make_object(yb_core::store::ObjectParams {
            index: 1,
            age: 2,
            chunk_pos: 1,
            next_chunk: 1,
        });
        obj1.set_payload(vec![0]);
        store.objects[1] = obj1;
        store.sync(ctx.piv.as_ref(), MGMT).unwrap();

        let store2 = Store::from_device(&ctx.reader, ctx.piv.as_ref()).unwrap();
        let warnings = detect_anomalies(&store2);
        assert!(
            !warnings.is_empty(),
            "orphaned chunk should produce a warning"
        );
        assert!(
            warnings.iter().any(|w| w.contains("orphaned")),
            "warning should mention 'orphaned': {warnings:?}"
        );
    }

    /// T-sig-1: a freshly stored blob has a valid yb2 signature (verdict OK).
    #[test]
    fn fsck_signature_ok_after_store() {
        let ctx = setup_signed_store();
        let vk = verifying_key(&ctx);

        let store = Store::from_device(&ctx.reader, ctx.piv.as_ref()).unwrap();
        let head = store.objects.iter().find(|o| o.is_head()).unwrap();
        let verdict = check_blob_signature(head, &store, Some(&vk));
        assert_eq!(
            verdict,
            SigVerdict::Verified,
            "fresh blob should have verdict VERIFIED"
        );
    }

    /// T-sig-2: flipping a payload byte in the raw PIV object causes fsck CORRUPTED.
    #[test]
    fn fsck_signature_corrupted_on_tampered_payload() {
        let ctx = setup_signed_store();
        let vk = verifying_key(&ctx);

        // The blob "blob" (4-byte name) is stored in object 0.
        // Raw layout: 23 bytes header + 4 bytes name + payload bytes.
        // Flip the first payload byte (offset 27).
        let mut raw = read_raw(&ctx, 0);
        raw[27] ^= 0xFF;
        write_raw(&ctx, 0, &raw);

        let store = Store::from_device(&ctx.reader, ctx.piv.as_ref()).unwrap();
        let head = store.objects.iter().find(|o| o.is_head()).unwrap();
        let verdict = check_blob_signature(head, &store, Some(&vk));
        assert_eq!(
            verdict,
            SigVerdict::Corrupted,
            "tampered payload should yield CORRUPTED"
        );
    }

    /// T-sig-3: flipping a byte in the signature trailer causes fsck CORRUPTED.
    #[test]
    fn fsck_signature_corrupted_on_tampered_signature() {
        let ctx = setup_signed_store();
        let vk = verifying_key(&ctx);

        // Trailer starts at offset 27 + 17 = 44 (header + name + payload).
        // SIG_VERSION is at 44, r starts at 45.  Flip the first byte of r.
        let mut raw = read_raw(&ctx, 0);
        raw[45] ^= 0xFF;
        write_raw(&ctx, 0, &raw);

        let store = Store::from_device(&ctx.reader, ctx.piv.as_ref()).unwrap();
        let head = store.objects.iter().find(|o| o.is_head()).unwrap();
        let verdict = check_blob_signature(head, &store, Some(&vk));
        assert_eq!(
            verdict,
            SigVerdict::Corrupted,
            "tampered signature should yield CORRUPTED"
        );
    }

    /// T-sig-4: a yb1-style blob (no trailer) is UNVERIFIED.
    #[test]
    fn fsck_signature_unverified_for_legacy_blob() {
        let piv = with_key_piv();
        let ctx = make_ctx(piv);
        let cert_der = ctx
            .piv
            .generate_certificate(&ctx.reader, 0x82, "CN=Test", MGMT, None)
            .unwrap();
        format_store(&ctx);

        // Store a blob normally (gets a yb2 signature), then overwrite the raw
        // PIV object with a truncated version that has no trailer — simulating
        // a yb1 object written by an older yb.
        store_plain(&ctx, "legacy", b"legacy data");

        // Read the raw object, keep only the header + name + blob_size bytes,
        // and write it back (dropping the 65-byte trailer).
        let mut raw = read_raw(&ctx, 0);
        // blob_size = 11 ("legacy data"), name = "legacy" (6 bytes).
        // Payload starts at offset 23 + 6 = 29.  Keep up to 29 + 11 = 40 bytes.
        raw.truncate(40);
        write_raw(&ctx, 0, &raw);

        let vk = {
            let pk = yb_core::parse_ec_public_key_from_cert_der(&cert_der).unwrap();
            p256::ecdsa::VerifyingKey::from(&pk)
        };

        let store = Store::from_device(&ctx.reader, ctx.piv.as_ref()).unwrap();
        let head = store.objects.iter().find(|o| o.is_head()).unwrap();
        let verdict = check_blob_signature(head, &store, Some(&vk));
        assert_eq!(
            verdict,
            SigVerdict::Unverified,
            "legacy blob should be UNVERIFIED"
        );
    }
}

// ---------------------------------------------------------------------------
// format (--key-slot parsing)
// ---------------------------------------------------------------------------

mod format_tests {
    use super::*;
    use yb::cli::format::{run as format_run, FormatArgs};
    use yb_core::store::constants::{DEFAULT_OBJECT_COUNT, DEFAULT_SUBJECT};

    #[test]
    fn format_key_slot_hex_prefix() {
        let piv = with_key_piv();
        let ctx = make_ctx(piv);
        // Pre-generate a cert in slot 0x82 so verify_certificate passes.
        ctx.piv
            .generate_certificate(&ctx.reader, 0x82, "CN=Test", MGMT, None)
            .unwrap();

        let args = FormatArgs {
            object_count: Some(DEFAULT_OBJECT_COUNT),
            key_slot: Some("0x82".to_owned()),
            generate: false,
            subject: Some(DEFAULT_SUBJECT.to_owned()),
            protect: false,
            ..Default::default()
        };
        format_run(&ctx, &args).unwrap();
    }

    #[test]
    fn format_key_slot_decimal() {
        let piv = with_key_piv();
        let ctx = make_ctx(piv);
        // 130 decimal == 0x82.
        ctx.piv
            .generate_certificate(&ctx.reader, 0x82, "CN=Test", MGMT, None)
            .unwrap();

        let args = FormatArgs {
            object_count: Some(DEFAULT_OBJECT_COUNT),
            key_slot: Some("130".to_owned()),
            generate: false,
            subject: Some(DEFAULT_SUBJECT.to_owned()),
            protect: false,
            ..Default::default()
        };
        format_run(&ctx, &args).unwrap();
    }

    #[test]
    fn format_key_slot_invalid_rejected() {
        let piv = with_key_piv();
        let ctx = make_ctx(piv);

        let args = FormatArgs {
            object_count: Some(DEFAULT_OBJECT_COUNT),
            key_slot: Some("notanumber".to_owned()),
            generate: false,
            subject: Some(DEFAULT_SUBJECT.to_owned()),
            protect: false,
            ..Default::default()
        };
        assert!(format_run(&ctx, &args).is_err());
    }
}

// ---------------------------------------------------------------------------
// Card setups shared by the spec 0021 and 0022 tests
// ---------------------------------------------------------------------------

mod cards {
    use super::*;
    use yb::cli::store::{run as store_run, StoreArgs};
    use yb_core::auxiliaries::{OBJ_ADMIN_DATA, OBJ_PRINTED};
    use yb_core::MgmtAlgo;

    /// A second 24-byte management key, distinct from `MGMT`.
    pub const OTHER_KEY: &str = "a1a2a3a4a5a6a7a8b1b2b3b4b5b6b7b8c1c2c3c4c5c6c7c8";

    /// ADMIN DATA as written by yb ≤ 0.4.x `format --protect` (flag 0x01),
    /// which is also what ykman writes for a blocked PUK.
    pub const ADMIN_LEGACY: [u8; 5] = [0x80, 0x03, 0x81, 0x01, 0x01];

    /// ADMIN DATA in the standard (ykman) layout: flag 0x02.
    pub const ADMIN_STANDARD: [u8; 5] = [0x80, 0x03, 0x81, 0x01, 0x02];

    /// PRINTED object content holding `key_hex`: `88 { 89 <key> }`.
    pub fn printed(key_hex: &str) -> Vec<u8> {
        let key = hex::decode(key_hex).unwrap();
        let mut inner = vec![0x89, key.len() as u8];
        inner.extend(key);
        let mut out = vec![0x88, inner.len() as u8];
        out.extend(inner);
        out
    }

    pub fn read_admin(ctx: &Context) -> Vec<u8> {
        ctx.piv
            .read_object(&ctx.reader, OBJ_ADMIN_DATA)
            .unwrap_or_default()
    }

    /// Fresh context on the same device, with no explicit management key:
    /// the protection mode is detected at construction.
    pub fn reopen(ctx: &Context) -> Context {
        let mut ctx = Context::with_backend(ctx.piv.clone(), Some(PIN.to_owned()), false).unwrap();
        ctx.quiet = true;
        ctx
    }

    /// A formatted card (8 objects) with a key and certificate in slot
    /// 0x82, and the factory management key.  Also returns the backend, for
    /// fault injection.
    pub fn formatted_card_with_piv() -> (Arc<VirtualPiv>, Context) {
        let piv = Arc::new(with_key_piv());
        let mut ctx = Context::with_backend(piv.clone(), Some(PIN.to_owned()), false).unwrap();
        ctx.management_key = Some(MGMT.to_owned());
        ctx.quiet = true;
        ctx.piv
            .generate_certificate(&ctx.reader, 0x82, "CN=Test", MGMT, None)
            .unwrap();
        format_store(&ctx);
        (piv, ctx)
    }

    pub fn formatted_card() -> Context {
        formatted_card_with_piv().1
    }

    /// A formatted card whose management key is `OTHER_KEY`, stored in
    /// PRINTED, with the given ADMIN DATA content.
    pub fn protected_card_with_piv(admin: &[u8]) -> (Arc<VirtualPiv>, Context) {
        let (vpiv, setup) = formatted_card_with_piv();
        let (piv, reader) = (setup.piv.as_ref(), setup.reader.as_str());
        piv.set_management_key(reader, MGMT, OTHER_KEY, MgmtAlgo::Tdes)
            .unwrap();
        piv.write_object(reader, OBJ_PRINTED, &printed(OTHER_KEY), OTHER_KEY)
            .unwrap();
        piv.write_object(reader, OBJ_ADMIN_DATA, admin, OTHER_KEY)
            .unwrap();
        (vpiv, reopen(&setup))
    }

    pub fn protected_card(admin: &[u8]) -> Context {
        protected_card_with_piv(admin).1
    }

    pub fn store_one(ctx: &Context, name: &str) -> anyhow::Result<()> {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join(name);
        std::fs::write(&file, b"secret").unwrap();
        store_run(
            ctx,
            &StoreArgs {
                files: vec![file],
                name: None,
                encrypted: true,
                unencrypted: false,
                no_compress: false,
            },
        )
    }
}

// ---------------------------------------------------------------------------
// management key algorithm and ADMIN DATA (spec 0021)
// ---------------------------------------------------------------------------

mod mgmt_key_tests {
    use super::cards::*;
    use super::*;
    use yb::cli::format::{run as format_run, FormatArgs};
    use yb_core::auxiliaries::{AdminData, ProtectionMode, OBJ_ADMIN_DATA, OBJ_PRINTED};
    use yb_core::store::constants::{DEFAULT_OBJECT_COUNT, DEFAULT_SUBJECT};
    use yb_core::{KeySource, MgmtAlgo, PivBackend};

    #[test]
    fn format_protect_on_firmware_57_keeps_aes192() {
        let ctx = make_ctx(VirtualPiv::from_fixture_yaml(fixtures::AES192).unwrap());
        let args = FormatArgs {
            object_count: Some(DEFAULT_OBJECT_COUNT),
            key_slot: Some("0x82".to_owned()),
            generate: true,
            subject: Some(DEFAULT_SUBJECT.to_owned()),
            protect: true,
            ..Default::default()
        };
        format_run(&ctx, &args).unwrap();

        assert_eq!(
            ctx.piv.management_key_algorithm(&ctx.reader).unwrap(),
            MgmtAlgo::Aes192
        );
        let admin = AdminData::parse(&read_admin(&ctx)).unwrap();
        assert_eq!(admin.flags, Some(0x02), "standard (ykman) flag");

        // The new key is PIN-protected: writes need only the PIN.
        let ctx = reopen(&ctx);
        assert_eq!(ctx.protection, ProtectionMode::Standard);
        store_one(&ctx, "blob").unwrap();
    }

    #[test]
    fn legacy_flag_is_migrated_on_first_write() {
        let ctx = protected_card(&ADMIN_LEGACY);
        assert_eq!(ctx.protection, ProtectionMode::LegacyOrPukBlocked);

        store_one(&ctx, "blob").unwrap();

        // 0x02 set; 0x01 cleared because the PUK is not blocked.
        let admin = AdminData::parse(&read_admin(&ctx)).unwrap();
        assert_eq!(admin.flags, Some(0x02));
        assert!(!ctx.pending_repairs().any(), "repairs done");
        // Management key and PRINTED are unchanged.
        assert_eq!(
            ctx.piv.read_object(&ctx.reader, OBJ_PRINTED).unwrap(),
            printed(OTHER_KEY)
        );
        // Subsequent invocations see the standard layout.
        assert_eq!(reopen(&ctx).protection, ProtectionMode::Standard);
    }

    /// `format --protect` on a card that is already PIN-protected keeps
    /// its key (spec 0023 §3a), and repairs a legacy flag.
    fn reprotect(admin: &[u8]) {
        let ctx = protected_card(admin);
        let args = FormatArgs {
            object_count: Some(DEFAULT_OBJECT_COUNT),
            key_slot: Some("0x82".to_owned()),
            generate: false,
            subject: Some(DEFAULT_SUBJECT.to_owned()),
            protect: true,
            ..Default::default()
        };
        format_run(&ctx, &args).unwrap();

        // OTHER_KEY is kept, still in PRINTED, with the standard flag.
        assert_eq!(
            ctx.piv.read_object(&ctx.reader, OBJ_PRINTED).unwrap(),
            printed(OTHER_KEY)
        );
        ctx.piv
            .authenticate_management_key(&ctx.reader, OTHER_KEY)
            .unwrap();
        let admin = AdminData::parse(&read_admin(&ctx)).unwrap();
        assert_eq!(admin.flags, Some(0x02));
        store_one(&reopen(&ctx), "blob").unwrap();
    }

    #[test]
    fn format_protect_on_protected_card() {
        reprotect(&[0x80, 0x03, 0x81, 0x01, 0x02]);
    }

    #[test]
    fn format_protect_on_legacy_protected_card() {
        reprotect(&ADMIN_LEGACY);
    }

    #[test]
    fn ykman_layout_is_used_as_is() {
        // Flag 0x02 plus a PIN timestamp (tag 0x83), as ykman writes it.
        let admin = [
            0x80, 0x09, 0x81, 0x01, 0x02, 0x83, 0x04, 0x65, 0x43, 0x21, 0x00,
        ];
        let ctx = protected_card(&admin);
        assert_eq!(ctx.protection, ProtectionMode::Standard);

        store_one(&ctx, "blob").unwrap();

        assert_eq!(read_admin(&ctx), admin.to_vec(), "ADMIN DATA untouched");
    }

    #[test]
    fn puk_blocked_card_is_not_treated_as_protected() {
        // Flag 0x01 but PRINTED is empty: the PUK really is blocked.
        let setup = formatted_card();
        setup
            .piv
            .write_object(&setup.reader, OBJ_ADMIN_DATA, &ADMIN_LEGACY, MGMT)
            .unwrap();
        let ctx = reopen(&setup);
        assert_eq!(ctx.protection, ProtectionMode::LegacyOrPukBlocked);

        // Nothing in PRINTED: the key resolves to the factory default, and
        // no repair is due.
        assert_eq!(ctx.management_key_for_write().unwrap(), MGMT);
        assert_eq!(ctx.management_key_source(), Some(KeySource::FactoryDefault));
        assert!(!ctx.pending_repairs().any());

        // Writes work and ADMIN DATA is untouched.
        store_one(&ctx, "blob").unwrap();
        assert_eq!(read_admin(&ctx), ADMIN_LEGACY.to_vec());
    }

    #[test]
    fn pin_derived_card_is_readable_but_not_writable() {
        // Salt (tag 0x82) present: PIN-derived management key.
        let admin = [
            0x80, 0x09, 0x81, 0x01, 0x00, 0x82, 0x04, 0xAA, 0xBB, 0xCC, 0xDD,
        ];
        let setup = formatted_card();
        setup
            .piv
            .write_object(&setup.reader, OBJ_ADMIN_DATA, &admin, MGMT)
            .unwrap();

        // Context creation (read-only use) succeeds.
        let ctx = reopen(&setup);
        assert_eq!(ctx.protection, ProtectionMode::Derived);
        let store = Store::from_device(&ctx.reader, ctx.piv.as_ref()).unwrap();
        assert!(list_blobs(&store).is_empty());

        let err = ctx.management_key_for_write().unwrap_err();
        assert!(err.to_string().contains("PIN-derived"), "{err}");
        assert!(store_one(&ctx, "blob").is_err());
    }

    #[test]
    fn unparseable_admin_data_refuses_writes() {
        let setup = formatted_card();
        // Tag 0x80 claims 5 bytes but only 1 follows.
        setup
            .piv
            .write_object(&setup.reader, OBJ_ADMIN_DATA, &[0x80, 0x05, 0x81], MGMT)
            .unwrap();
        let ctx = reopen(&setup);
        assert_eq!(ctx.protection, ProtectionMode::Invalid);
        let err = ctx.management_key_for_write().unwrap_err();
        assert!(err.to_string().contains("cannot be parsed"), "{err}");
    }

    #[test]
    fn key_of_wrong_length_is_rejected_before_authentication() {
        let mut ctx = make_ctx(VirtualPiv::from_fixture_yaml(fixtures::AES192).unwrap());
        ctx.management_key = Some("000102030405060708090a0b0c0d0e0f".to_owned());
        let args = FormatArgs {
            object_count: Some(DEFAULT_OBJECT_COUNT),
            key_slot: Some("0x82".to_owned()),
            generate: true,
            subject: Some(DEFAULT_SUBJECT.to_owned()),
            protect: false,
            ..Default::default()
        };
        let err = format_run(&ctx, &args).unwrap_err();
        assert!(
            format!("{err:#}")
                .contains("management key is 16 bytes but the card uses AES-192 (24 bytes)"),
            "{err:#}"
        );
        // Nothing was generated in the slot.
        assert!(ctx.piv.read_certificate(&ctx.reader, 0x82).is_err());
    }

    #[test]
    fn fixture_round_trips_management_key_algorithm() {
        let piv = VirtualPiv::from_fixture_yaml(fixtures::AES192).unwrap();
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("saved.yaml");
        piv.save_fixture(&path).unwrap();
        let reloaded = VirtualPiv::from_fixture(&path).unwrap();
        let reader = reloaded.reader_name();
        assert_eq!(
            reloaded.management_key_algorithm(&reader).unwrap(),
            MgmtAlgo::Aes192
        );
    }
}

// ---------------------------------------------------------------------------
// format sequence and recovery (spec 0022)
// ---------------------------------------------------------------------------

mod format_safety_tests {
    use super::cards::*;
    use super::*;
    use yb::cli::format::{run as format_run, FormatArgs};
    use yb::cli::util::{check_blob_signature, SigVerdict};
    use yb_core::auxiliaries::{read_printed_keys, AdminData, PrintedKeys, OBJ_PRINTED};
    use yb_core::store::constants::DEFAULT_SUBJECT;
    use yb_core::{fetch_blob, parse_ec_public_key_from_cert_der, Fault, SlotKeyCheck};

    fn args(generate: bool, protect: bool) -> FormatArgs {
        FormatArgs {
            object_count: Some(8),
            key_slot: Some("0x82".to_owned()),
            generate,
            subject: Some(DEFAULT_SUBJECT.to_owned()),
            protect,
            ..Default::default()
        }
    }

    /// A card holding one blob; protected (key `OTHER_KEY` in PRINTED) or
    /// not (factory key).  The context has no explicit management key.
    fn card_with_blob(protected: bool) -> (Arc<VirtualPiv>, Context) {
        let (piv, ctx) = if protected {
            protected_card_with_piv(&ADMIN_STANDARD)
        } else {
            let (piv, ctx) = formatted_card_with_piv();
            (piv, reopen(&ctx))
        };
        store_one(&ctx, "precious").unwrap();
        let ctx = reopen(&ctx);
        (piv, ctx)
    }

    fn printed_keys(ctx: &Context) -> PrintedKeys {
        read_printed_keys(&ctx.reader, ctx.piv.as_ref(), PIN).unwrap()
    }

    fn blob_names(ctx: &Context) -> Vec<String> {
        let store = Store::from_device(&ctx.reader, ctx.piv.as_ref()).unwrap();
        list_blobs(&store).into_iter().map(|b| b.name).collect()
    }

    /// Check invariants I1–I4 of spec 0022 §5 after a `yb format` attempt,
    /// once the card is "reconnected".
    fn check_invariants(piv: &VirtualPiv, ctx: &Context, outcome: &anyhow::Result<()>, case: &str) {
        let keys_before = [MGMT.to_owned(), OTHER_KEY.to_owned()];
        piv.clear_faults();
        let after = reopen(ctx);

        // I2: the management key is recoverable from PRINTED or is the
        // factory key; pending repairs are carried out.
        let key = after
            .management_key_for_write()
            .unwrap_or_else(|e| panic!("{case}: I2 violated: {e:#}"));
        after.complete_pending_repairs();
        assert!(
            printed_keys(&after).previous.is_none(),
            "{case}: repair left tag 8A in PRINTED"
        );

        // I1: every blob decrypts, or is reported CORRUPTED.
        let store = Store::from_device(&after.reader, after.piv.as_ref()).unwrap();
        let vk = after
            .piv
            .read_certificate(&after.reader, store.store_key_slot)
            .ok()
            .and_then(|c| parse_ec_public_key_from_cert_der(&c).ok())
            .map(|pk| p256::ecdsa::VerifyingKey::from(&pk));
        for blob in list_blobs(&store) {
            let head = store.find_head(&blob.name).unwrap();
            if check_blob_signature(head, &store, vk.as_ref()) != SigVerdict::Corrupted {
                fetch_blob(
                    &store,
                    after.piv.as_ref(),
                    &after.reader,
                    &blob.name,
                    Some(PIN),
                    false,
                )
                .unwrap_or_else(|e| panic!("{case}: I1 violated for {}: {e:#}", blob.name));
            }
        }

        // I3: success implies the store key matches its certificate.
        if outcome.is_ok() {
            assert_eq!(
                after.check_slot_key(0x82).unwrap(),
                SlotKeyCheck::Match,
                "{case}: I3 violated"
            );
        }

        // I4: no key material in the error.
        if let Err(e) = outcome {
            let text = format!("{e:#}");
            for k in keys_before.iter().chain([&key]) {
                assert!(!text.contains(k.as_str()), "{case}: I4 violated: {text}");
            }
        }
    }

    #[test]
    fn invariants_hold_for_every_fault() {
        let faults = [
            Fault::WriteFails(1), // B1a
            Fault::WriteFails(2), // B1c
            Fault::WriteFails(3), // B1d
            Fault::WriteFails(4), // B2, first object
            Fault::WriteFails(8), // B2, midway
            Fault::SetManagementKeyRejected,
            Fault::SetManagementKeyLostReply,
            Fault::CardLostDuringSetManagementKey { applied: true },
            Fault::CardLostDuringSetManagementKey { applied: false },
            Fault::GenerateCertificateFailsAfterKey,
        ];
        for protected in [false, true] {
            for fault in faults {
                let (piv, ctx) = card_with_blob(protected);
                piv.inject_fault(fault);
                let outcome = format_run(&ctx, &args(true, true));
                let case = format!("protected={protected} fault={fault:?}");
                check_invariants(&piv, &ctx, &outcome, &case);
            }
        }
    }

    /// The key switch only happens on an unprotected card (spec 0023 §3a).
    #[test]
    fn rejected_switch_changes_nothing() {
        let (piv, ctx) = card_with_blob(false);
        piv.inject_fault(Fault::SetManagementKeyRejected);
        let err = format_run(&ctx, &args(true, true)).unwrap_err();
        assert!(
            format!("{err:#}").contains("nothing was changed"),
            "{err:#}"
        );

        // PRINTED restored exactly: absent on the unprotected card.
        assert!(ctx.piv.read_object(&ctx.reader, OBJ_PRINTED).is_err());
        ctx.piv
            .authenticate_management_key(&ctx.reader, MGMT)
            .unwrap();
        assert_eq!(blob_names(&ctx), vec!["precious"]);
    }

    /// After an interrupted switch that did not take effect, PRINTED holds
    /// `89 <new>` (not accepted) and `8A <old>` (the card's key): the key
    /// is not protected by spec 0023 §3a, so `--protect` switches again.
    /// A rejected switch then restores PRINTED as `88 { 89 <old> }`.
    #[test]
    fn rejected_switch_after_interrupted_switch_restores_printed() {
        let (piv, ctx) = card_with_blob(true);
        let stale = yb_core::auxiliaries::encode_printed(MGMT, Some(OTHER_KEY)).unwrap();
        ctx.piv
            .write_object(&ctx.reader, OBJ_PRINTED, &stale, OTHER_KEY)
            .unwrap();
        let ctx = reopen(&ctx);
        piv.inject_fault(Fault::SetManagementKeyRejected);
        let err = format_run(&ctx, &args(false, true)).unwrap_err();
        assert!(
            format!("{err:#}").contains("nothing was changed"),
            "{err:#}"
        );
        assert_eq!(
            ctx.piv.read_object(&ctx.reader, OBJ_PRINTED).unwrap(),
            printed(OTHER_KEY)
        );
        assert_eq!(blob_names(&ctx), vec!["precious"]);
    }

    #[test]
    fn lost_reply_completes_the_switch() {
        let (piv, ctx) = card_with_blob(false);
        piv.inject_fault(Fault::SetManagementKeyLostReply);
        format_run(&ctx, &args(false, true)).unwrap();

        let keys = printed_keys(&ctx);
        assert!(keys.previous.is_none());
        let new_key = keys.current.unwrap();
        assert_ne!(new_key, MGMT);
        ctx.piv
            .authenticate_management_key(&ctx.reader, &new_key)
            .unwrap();
    }

    #[test]
    fn interrupted_switch_is_recovered_by_the_next_write() {
        for applied in [false, true] {
            let case = format!("applied={applied}");
            let (piv, ctx) = card_with_blob(false);
            piv.inject_fault(Fault::CardLostDuringSetManagementKey { applied });
            let err = format_run(&ctx, &args(false, true)).unwrap_err();
            assert!(
                format!("{err:#}").contains("interrupted"),
                "{case}: {err:#}"
            );
            let keys = printed_keys(&ctx);
            assert!(keys.current.is_some() && keys.previous.is_some(), "{case}");

            // Reconnect: an ordinary write recovers and repairs.
            piv.clear_faults();
            let ctx = reopen(&ctx);
            store_one(&ctx, "after").unwrap_or_else(|e| panic!("{case}: {e:#}"));
            let keys = printed_keys(&ctx);
            assert!(keys.previous.is_none(), "{case}: 8A left behind");
            if applied {
                // Protected with the new key.
                let admin = AdminData::parse(&read_admin(&ctx)).unwrap();
                assert_eq!(admin.flags, Some(0x02), "{case}");
                ctx.piv
                    .authenticate_management_key(&ctx.reader, &keys.current.unwrap())
                    .unwrap_or_else(|e| panic!("{case}: {e:#}"));
            } else {
                // Back to the factory key: nothing stored, not protected.
                assert_eq!(keys.current, None, "{case}");
            }
            assert!(blob_names(&ctx).contains(&"after".to_owned()), "{case}");
        }
    }

    #[test]
    fn failed_admin_write_is_repaired_by_the_next_write() {
        // Unprotected card; B1c (2nd write) fails after the key switch.
        let (piv, ctx) = card_with_blob(false);
        piv.inject_fault(Fault::WriteFails(2));
        let err = format_run(&ctx, &args(false, true)).unwrap_err();
        assert!(format!("{err:#}").contains("ADMIN DATA"), "{err:#}");
        assert_eq!(read_admin(&ctx), Vec::<u8>::new(), "flags not written");

        let ctx = reopen(&ctx);
        store_one(&ctx, "after").unwrap();
        assert_eq!(read_admin(&ctx), ADMIN_STANDARD.to_vec());
        assert!(printed_keys(&ctx).previous.is_none());
    }

    #[test]
    fn failed_printed_cleanup_is_only_a_warning() {
        // B1d (3rd write) fails: format succeeds, the next write cleans up.
        let (piv, ctx) = card_with_blob(false);
        piv.inject_fault(Fault::WriteFails(3));
        format_run(&ctx, &args(false, true)).unwrap();
        assert!(printed_keys(&ctx).previous.is_some());

        let ctx = reopen(&ctx);
        store_one(&ctx, "after").unwrap();
        assert!(printed_keys(&ctx).previous.is_none());
    }

    #[test]
    fn failed_certificate_leaves_an_empty_store_that_refuses_writes() {
        let (piv, ctx) = card_with_blob(false);
        piv.inject_fault(Fault::GenerateCertificateFailsAfterKey);
        let err = format_run(&ctx, &args(true, false)).unwrap_err();
        assert!(format!("{err:#}").contains("Do not store data"), "{err:#}");
        assert!(blob_names(&ctx).is_empty(), "store erased before the key");

        let err = store_one(&reopen(&ctx), "x").unwrap_err();
        assert!(
            err.to_string().contains("does not match its certificate"),
            "{err:#}"
        );
    }

    #[test]
    fn mismatched_slot_key_is_rejected_before_any_write() {
        let (piv, ctx) = card_with_blob(false);
        // Replace the slot key but keep the old certificate.
        piv.inject_fault(Fault::GenerateCertificateFailsAfterKey);
        assert!(ctx
            .piv
            .generate_certificate(&ctx.reader, 0x82, "CN=X", MGMT, None)
            .is_err());

        let err = format_run(&ctx, &args(false, false)).unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("nothing was changed"), "{text}");
        assert!(text.contains("does not match its certificate"), "{text}");
        assert_eq!(blob_names(&ctx), vec!["precious"], "store untouched");
    }

    #[test]
    fn wrong_explicit_key_does_not_fall_through() {
        let (_piv, mut ctx) = card_with_blob(true);
        ctx.management_key = Some(MGMT.to_owned()); // the card uses OTHER_KEY
        let err = format_run(&ctx, &args(false, true)).unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("YB_MANAGEMENT_KEY"), "{text}");
        assert!(text.contains("nothing was changed"), "{text}");
        assert_eq!(blob_names(&ctx), vec!["precious"]);
    }
}

// ---------------------------------------------------------------------------
// default-credential policy wiring (spec 0024)
// ---------------------------------------------------------------------------

mod default_policy_tests {
    use super::*;
    use yb::cli::fetch::{run as fetch_run, FetchArgs};
    use yb::cli::format::{run as format_run, FormatArgs};
    use yb::cli::fsck::{run as fsck_run, FsckArgs};
    use yb::cli::list::{run as list_run, ListArgs};
    use yb::cli::remove::{run as remove_run, RemoveArgs};
    use yb_core::auxiliaries::{detect_default_credentials, DefaultCredentials};
    use yb_core::store::constants::DEFAULT_SUBJECT;
    use yb_core::{
        parse_ec_public_key_from_cert_der, store_blob, Compression, Encryption, KeySource,
        MgmtAlgo, PivBackend, SecretOp, StoreOptions,
    };

    const FACTORY_PIN: &str = "123456";
    const FACTORY_PUK: &str = "12345678";

    /// A formatted card holding blob "kept", whose PIN, PUK and management
    /// key are each at the factory value or not, as requested.  The
    /// context gets no PIN and no management key: both must come from the
    /// policy (factory PIN filled in) and the resolver.
    fn card(pin: bool, puk: bool, mgmt: bool) -> (Arc<VirtualPiv>, Context, TempDir) {
        let tmp = TempDir::new().unwrap();
        let yaml = format!(
            "credentials:\n  pin: \"{}\"\n  puk: \"{}\"\n  management_key: \"{}\"\n\
             slots:\n  \"82\":\n    private_key_hex: \
             \"64055b21eefa9776a601bd99b0a5aa45c9d29d8ac0106b83844871bc4a9c748c\"\n",
            if pin { FACTORY_PIN } else { PIN },
            if puk { FACTORY_PUK } else { "87654321" },
            if mgmt { MGMT } else { cards::OTHER_KEY },
        );
        let path = tmp.path().join("card.yaml");
        std::fs::write(&path, yaml).unwrap();
        let piv = Arc::new(VirtualPiv::from_fixture(&path).unwrap());
        let key = if mgmt { MGMT } else { cards::OTHER_KEY };
        let reader = piv.reader_name();
        let user_pin = if pin { FACTORY_PIN } else { PIN };
        // Set the card up directly on the backend, bypassing the policy.
        piv.generate_certificate(&reader, 0x82, "CN=Test", key, Some(user_pin))
            .unwrap();
        let mut store = Store::format(&reader, piv.as_ref(), 8, 0x82, key).unwrap();
        // Encrypted, so that fetching it needs (and checks) the PIN.
        let cert = piv.read_certificate(&reader, 0x82).unwrap();
        let public_key = parse_ec_public_key_from_cert_der(&cert).unwrap();
        let options = StoreOptions {
            encryption: Encryption::Encrypted(&public_key),
            compression: Compression::None,
        };
        store_blob(
            &mut store,
            piv.as_ref(),
            "kept",
            b"x",
            options,
            key,
            Some(user_pin),
        )
        .unwrap();

        // A factory PIN must be filled in by the policy, so it is not given.
        let explicit_pin = (!pin).then(|| PIN.to_owned());
        let mut ctx = Context::with_backend(piv.clone(), explicit_pin, false).unwrap();
        ctx.quiet = true;
        if !mgmt {
            ctx.management_key = Some(cards::OTHER_KEY.to_owned());
        }
        (piv, ctx, tmp)
    }

    fn fmt(protect: bool) -> FormatArgs {
        FormatArgs {
            object_count: Some(8),
            key_slot: Some("0x82".to_owned()),
            generate: false,
            subject: Some(DEFAULT_SUBJECT.to_owned()),
            protect,
            ..Default::default()
        }
    }

    fn fetch_args() -> FetchArgs {
        FetchArgs {
            patterns: vec!["kept".to_owned()],
            stdout: false,
            output: None,
            output_dir: Some(std::env::temp_dir()),
            extract: false,
        }
    }

    #[test]
    fn truthful_default_reporting() {
        let (piv, ctx, _t) = card(true, false, true);
        assert_eq!(
            ctx.defaults,
            DefaultCredentials {
                pin: true,
                puk: false,
                management_key: true
            }
        );
        // Changing the management key clears its flag.
        piv.set_management_key(&ctx.reader, MGMT, cards::OTHER_KEY, MgmtAlgo::Tdes)
            .unwrap();
        assert!(!detect_default_credentials(&ctx.reader, piv.as_ref()).management_key);
    }

    #[test]
    fn default_pin_or_puk_refuses_store_but_not_reads() {
        for (pin, puk) in [(true, false), (false, true)] {
            let case = format!("pin={pin} puk={puk}");
            let (piv, ctx, _t) = card(pin, puk, false);
            let before = piv.write_count();

            let err = cards::store_one(&ctx, "new").unwrap_err();
            assert!(err.to_string().contains("factory-default"), "{case}: {err}");
            assert_eq!(piv.write_count(), before, "{case}: store wrote");

            // Reads and removals only warn.
            list_run(
                &ctx,
                &ListArgs {
                    pattern: None,
                    long: false,
                    one_per_line: false,
                    sort_time: false,
                    reverse: false,
                },
            )
            .unwrap_or_else(|e| panic!("{case}: ls: {e:#}"));
            fsck_run(
                &ctx,
                &FsckArgs {
                    verbose: false,
                    nvm: false,
                    check_key: false,
                },
            )
            .unwrap_or_else(|e| panic!("{case}: fsck: {e:#}"));
            fetch_run(&ctx, &fetch_args()).unwrap_or_else(|e| panic!("{case}: fetch: {e:#}"));
            remove_run(
                &ctx,
                &RemoveArgs {
                    patterns: vec!["kept".to_owned()],
                    ignore_missing: false,
                },
            )
            .unwrap_or_else(|e| panic!("{case}: rm: {e:#}"));
        }
    }

    #[test]
    fn format_protect_refusal_writes_nothing() {
        let (piv, ctx, _t) = card(true, false, true);
        let before = piv.write_count();
        let err = format_run(&ctx, &fmt(true)).unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("nothing was changed"), "{text}");
        assert!(text.contains("factory-default PIN"), "{text}");
        assert_eq!(piv.write_count(), before);

        // Without --protect it only warns.
        format_run(&ctx, &fmt(false)).unwrap();
    }

    #[test]
    fn allow_defaults_turns_refusals_into_warnings() {
        let (_piv, mut ctx, _t) = card(true, true, true);
        ctx.allow_defaults = true;
        cards::store_one(&ctx, "new").unwrap();
        let warnings = ctx.enforce_default_policy(SecretOp::Store).unwrap();
        assert_eq!(
            warnings,
            [
                "Warning: this YubiKey uses the factory-default PIN, PUK and management key; \
              run `yb fsck` for details."
            ]
        );
    }

    #[test]
    fn default_management_key_only_warns_on_store() {
        let (_piv, ctx, _t) = card(false, false, true);
        cards::store_one(&ctx, "new").unwrap();
        assert_eq!(
            ctx.enforce_default_policy(SecretOp::Store).unwrap(),
            [
                "Warning: this YubiKey uses the factory-default management key; run `yb fsck` \
              for details."
            ]
        );
    }

    #[test]
    fn quiet_still_returns_warnings() {
        let (_piv, ctx, _t) = card(true, false, false);
        assert!(ctx.quiet);
        assert_eq!(
            ctx.enforce_default_policy(SecretOp::Fetch).unwrap().len(),
            1
        );
    }

    #[test]
    fn factory_pin_is_filled_in() {
        let (piv, _ctx, _t) = card(true, false, false);
        // No PIN source at all.
        let ctx = Context::with_backend(piv.clone(), None, false).unwrap();
        assert_eq!(ctx.require_pin().unwrap().as_deref(), Some(FACTORY_PIN));
        fetch_run(&ctx, &fetch_args()).unwrap();

        // An explicit PIN wins, even a wrong one.
        let ctx = Context::with_backend(piv.clone(), Some("000000".to_owned()), false).unwrap();
        assert!(fetch_run(&ctx, &fetch_args()).is_err());
    }

    #[test]
    fn factory_management_key_is_resolved_not_injected() {
        let (_piv, mut ctx, _t) = card(false, false, true);
        ctx.allow_defaults = true;
        assert_eq!(ctx.management_key, None);
        cards::store_one(&ctx, "new").unwrap();
        assert_eq!(ctx.management_key_source(), Some(KeySource::FactoryDefault));
        remove_run(
            &ctx,
            &RemoveArgs {
                patterns: vec!["new".to_owned()],
                ignore_missing: false,
            },
        )
        .unwrap();
    }

    #[test]
    fn self_test_policy_refuses_any_default() {
        let (_piv, ctx, _t) = card(false, false, true);
        assert!(ctx.enforce_default_policy(SecretOp::SelfTest).is_err());
    }
}

// ---------------------------------------------------------------------------
// rendered errors, end to end (spec 0025)
// ---------------------------------------------------------------------------

mod error_render_tests {
    use super::*;
    use yb::cli::fetch::{run as fetch_run, FetchArgs};
    use yb::cli::store::{run as store_run, StoreArgs};
    use yb_core::errors::{render, RenderEnv};
    use yb_core::Fault;

    /// Identifying data and secrets that must never appear in errors.
    const FORBIDDEN: [&str; 5] = [
        "88888888",              // with_key.yaml serial
        "Virtual YubiKey 00 01", // with_key.yaml reader
        PIN,
        MGMT,
        cards::OTHER_KEY,
    ];

    fn rendered(e: &anyhow::Error) -> String {
        let text = render(
            e,
            &RenderEnv {
                firmware: Some("5.4.3".to_owned()),
                yb_version: Some("test".to_owned()),
            },
        );
        for f in FORBIDDEN {
            assert!(!text.contains(f), "identifying data {f:?} in:\n{text}");
        }
        text
    }

    /// A set-up card holding one encrypted blob, and a context with the
    /// given PIN.
    fn card_with_blob(pin: &str) -> (Arc<VirtualPiv>, Context) {
        let (piv, setup) = cards::formatted_card_with_piv();
        cards::store_one(&setup, "blob").unwrap();
        let mut ctx = Context::with_backend(piv.clone(), Some(pin.to_owned()), false).unwrap();
        ctx.quiet = true;
        (piv, ctx)
    }

    fn fetch(ctx: &Context) -> anyhow::Result<()> {
        fetch_run(
            ctx,
            &FetchArgs {
                patterns: vec!["blob".to_owned()],
                stdout: false,
                output: None,
                output_dir: Some(std::env::temp_dir()),
                extract: false,
            },
        )
    }

    /// Store `len` incompressible bytes as blob `name` (several chunks).
    fn store_bytes(ctx: &Context, name: &str, len: usize) -> anyhow::Result<()> {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join(name);
        let mut x: u32 = 0x1234_5678;
        let data: Vec<u8> = (0..len)
            .map(|_| {
                x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (x >> 24) as u8
            })
            .collect();
        std::fs::write(&file, data).unwrap();
        store_run(
            ctx,
            &StoreArgs {
                files: vec![file],
                name: None,
                encrypted: true,
                unencrypted: false,
                no_compress: true,
            },
        )
    }

    #[test]
    fn wrong_pin_then_blocked() {
        let (_piv, ctx) = card_with_blob("000000");
        // fetch wraps the card error in context: it becomes the Cause.
        let text = rendered(&fetch(&ctx).unwrap_err());
        assert_eq!(
            text,
            "Error: decrypting blob 'blob'\n  \
             Cause: wrong PIN (2 attempts left before the PIN is blocked).\n  \
             (details: PIN verification → SW 63C2)"
        );

        fetch(&ctx).unwrap_err();
        let text = rendered(&fetch(&ctx).unwrap_err());
        assert!(text.contains("no attempts left"), "{text}");
        let text = rendered(&fetch(&ctx).unwrap_err());
        assert!(
            text.contains("Cause: the PIN is blocked (too many wrong attempts)."),
            "{text}"
        );
        assert!(text.contains("ykman piv access unblock-pin"), "{text}");
        assert!(
            text.ends_with("(details: PIN verification → SW 6983)"),
            "{text}"
        );
    }

    #[test]
    fn wrong_explicit_management_key() {
        let (_piv, mut ctx) = card_with_blob(PIN);
        ctx.management_key = Some(cards::OTHER_KEY.to_owned());
        let text = rendered(&cards::store_one(&ctx, "x").unwrap_err());
        assert!(
            text.starts_with(
                "Error: the YubiKey rejected the management key from YB_MANAGEMENT_KEY\n  \
                 Cause: wrong management key ("
            ),
            "{text}"
        );
        assert!(
            text.ends_with("(details: management key authentication → SW 6982)"),
            "{text}"
        );
    }

    #[test]
    fn storage_full_on_first_write() {
        let (piv, ctx) = card_with_blob(PIN);
        piv.inject_fault(Fault::StorageFull(1));
        let text = rendered(&store_bytes(&ctx, "big", 6000).unwrap_err());
        assert!(
            text.starts_with("Error: the YubiKey's storage is full.\n"),
            "{text}"
        );
        assert!(
            text.contains("Try: `yb fsck --nvm`, then remove blobs."),
            "{text}"
        );
        assert!(text.contains("→ SW 6A84)"), "{text}");
    }

    #[test]
    fn storage_full_midway_notes_partial_update() {
        let (piv, ctx) = card_with_blob(PIN);
        piv.inject_fault(Fault::StorageFull(2));
        let text = rendered(&store_bytes(&ctx, "big", 6000).unwrap_err());
        assert!(
            text.starts_with(
                "Error: the store may be partially updated; run `yb fsck`\n  \
                 Cause: the YubiKey's storage is full (the PIV area's ~51 KB are used up).\n"
            ),
            "{text}"
        );
    }

    #[test]
    fn missing_certificate_explained() {
        // with_key.yaml has a key but no certificate: an encrypted store
        // cannot find the public key.
        let piv = Arc::new(with_key_piv());
        Store::format(&piv.reader_name(), piv.as_ref(), 8, 0x82, MGMT).unwrap();
        let mut ctx = Context::with_backend(piv, Some(PIN.to_owned()), false).unwrap();
        ctx.quiet = true;
        let text = rendered(&cards::store_one(&ctx, "x").unwrap_err());
        assert!(
            text.contains("Cause: no key in slot 0x82 (this YubiKey has not been set up for yb)."),
            "{text}"
        );
        assert!(
            text.ends_with("(details: read certificate of slot 0x82 → SW 6A82)"),
            "{text}"
        );
    }
}

// ---------------------------------------------------------------------------
// guided format, --plan and the fsck YubiKey section (spec 0023)
// ---------------------------------------------------------------------------

mod guided_tests {
    use super::cards::*;
    use super::*;
    use std::collections::VecDeque;
    use yb::cli::format::{run_with_output as format_with_output, FormatArgs};
    use yb::cli::fsck::{check as fsck_check, FsckArgs};
    use yb::cli::guided::{run as guided_run, Cancelled, Prompter};
    use yb_core::auxiliaries::{
        detect_default_credentials, read_printed_keys, AdminData, ProtectionMode,
    };
    use yb_core::store::constants::OBJECT_ID_ZERO;
    use yb_core::{Fault, MgmtAlgo, PivBackend, SlotKeyCheck};

    const NEW_PIN: &str = "271828";
    const NEW_PUK: &str = "31415926";

    /// Answers the flow's questions from a script, and records what it
    /// says and asks.
    struct Script {
        answers: VecDeque<String>,
        transcript: Vec<String>,
    }

    impl Script {
        fn new(answers: &[&str]) -> Self {
            Self {
                answers: answers.iter().map(|a| (*a).to_owned()).collect(),
                transcript: Vec::new(),
            }
        }

        fn text(&self) -> String {
            self.transcript.join("\n")
        }

        fn next(&mut self, prompt: &str) -> anyhow::Result<String> {
            self.transcript.push(prompt.to_owned());
            self.answers
                .pop_front()
                .ok_or_else(|| anyhow::anyhow!("script exhausted at: {prompt}"))
        }
    }

    impl Prompter for Script {
        fn say(&mut self, text: &str) {
            self.transcript.push(text.to_owned());
        }
        fn ask(&mut self, prompt: &str) -> anyhow::Result<String> {
            self.next(prompt)
        }
        fn ask_secret(&mut self, prompt: &str) -> anyhow::Result<String> {
            self.next(prompt)
        }
    }

    /// Run the guided flow; the script must be used up exactly.
    fn guided(ctx: &mut Context, answers: &[&str]) -> (anyhow::Result<()>, Script) {
        let mut script = Script::new(answers);
        let outcome = guided_run(ctx, &mut script);
        assert!(
            script.answers.is_empty(),
            "unused answers {:?}\n{}",
            script.answers,
            script.text()
        );
        (outcome, script)
    }

    fn is_cancelled(outcome: &anyhow::Result<()>) -> bool {
        matches!(outcome, Err(e) if e.downcast_ref::<Cancelled>().is_some())
    }

    /// A card from a YAML fixture string (credentials, slots, objects).
    fn card_from_yaml(yaml: &str) -> (Arc<VirtualPiv>, TempDir) {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("card.yaml");
        std::fs::write(&path, yaml).unwrap();
        (Arc::new(VirtualPiv::from_fixture(&path).unwrap()), tmp)
    }

    fn context(piv: &Arc<VirtualPiv>, pin: Option<&str>) -> Context {
        let mut ctx = Context::with_backend(piv.clone(), pin.map(str::to_owned), false).unwrap();
        ctx.quiet = true;
        ctx
    }

    /// The card is set up for yb: PIN-protected management key, the
    /// store is usable with `pin` only.
    fn assert_ready(piv: &Arc<VirtualPiv>, pin: &str) {
        let ctx = context(piv, Some(pin));
        assert_eq!(ctx.protection, ProtectionMode::Standard);
        assert_eq!(ctx.check_slot_key(0x82).unwrap(), SlotKeyCheck::Match);
        store_one(&ctx, "after").unwrap();
    }

    #[test]
    fn factory_fresh_card() {
        let piv = Arc::new(VirtualPiv::new());
        let mut ctx = context(&piv, None);
        let (outcome, script) = guided(&mut ctx, &[NEW_PIN, NEW_PIN, NEW_PUK, NEW_PUK, "", "y"]);
        outcome.unwrap_or_else(|e| panic!("{e:#}\n{}", script.text()));
        let text = script.text();
        assert!(text.contains("Your PIN is the factory default"), "{text}");
        assert!(text.contains("Your PUK is the factory default"), "{text}");
        assert!(
            text.contains(
                "Plan for YubiKey 99999999:\n\
                 \x20 1. Change PIN\n\
                 \x20 2. Change PUK\n\
                 \x20 3. Replace the management key with a random one (3DES), kept on the \
                 YubiKey and unlocked by the PIN\n\
                 \x20 4. Create the store: 32 objects, key slot 0x82\n\
                 \x20 5. Generate a new key in slot 0x82\n"
            ),
            "{text}"
        );

        let reader = piv.reader_name();
        assert_eq!(
            detect_default_credentials(&reader, piv.as_ref()),
            Default::default(),
            "no factory credential left"
        );
        assert_eq!(ctx.known_pin().as_deref(), Some(NEW_PIN));
        assert_eq!(
            Store::from_device(&reader, piv.as_ref())
                .unwrap()
                .object_count,
            32
        );
        assert_ready(&piv, NEW_PIN);
    }

    #[test]
    fn set_up_card_keeps_its_key() {
        let (piv, setup) = formatted_card_with_piv();
        store_one(&setup, "old").unwrap();
        let cert_before = piv.read_certificate(&setup.reader, 0x82).unwrap();
        let mut ctx = context(&piv, Some(PIN));
        // Keep the key, 16 objects, confirm with the serial (a blob dies).
        let (outcome, script) = guided(&mut ctx, &["k", "16", " 88888888 "]);
        outcome.unwrap_or_else(|e| panic!("{e:#}\n{}", script.text()));
        let text = script.text();
        assert!(
            text.contains("ERASE store — destroys 1 blob: old"),
            "{text}"
        );
        assert!(
            text.contains("This will destroy 1 blob (old) on YubiKey 88888888."),
            "{text}"
        );
        assert_eq!(
            piv.read_certificate(&ctx.reader, 0x82).unwrap(),
            cert_before
        );
        assert_ready(&piv, PIN);
    }

    #[test]
    fn generating_a_key_needs_the_right_serial() {
        let (piv, setup) = formatted_card_with_piv();
        let before = piv.write_count();
        let mut ctx = context(&piv, Some(PIN));
        let (outcome, script) = guided(&mut ctx, &["g", "", "12345678"]);
        assert!(is_cancelled(&outcome), "{outcome:?}");
        assert!(script
            .text()
            .ends_with("Nothing was changed on the YubiKey."));
        assert_eq!(piv.write_count(), before);

        // The right serial goes through.
        let cert_before = piv.read_certificate(&setup.reader, 0x82).unwrap();
        let mut ctx = context(&piv, Some(PIN));
        let (outcome, _) = guided(&mut ctx, &["g", "", "88888888"]);
        outcome.unwrap();
        assert_ne!(
            piv.read_certificate(&ctx.reader, 0x82).unwrap(),
            cert_before
        );
        assert_ready(&piv, PIN);
    }

    #[test]
    fn mismatched_key_asks_before_replacing() {
        let (piv, setup) = formatted_card_with_piv();
        // Replace the slot key, keeping the old certificate.
        piv.inject_fault(Fault::GenerateCertificateFailsAfterKey);
        assert!(setup
            .piv
            .generate_certificate(&setup.reader, 0x82, "CN=X", MGMT, None)
            .is_err());
        let before = piv.write_count();

        let mut ctx = context(&piv, Some(PIN));
        let (outcome, script) = guided(&mut ctx, &["n"]);
        assert!(is_cancelled(&outcome), "{outcome:?}");
        assert!(
            script
                .text()
                .contains("Warning: the key in slot 0x82 does not match its certificate."),
            "{}",
            script.text()
        );
        assert_eq!(piv.write_count(), before);

        let mut ctx = context(&piv, Some(PIN));
        let (outcome, script) = guided(&mut ctx, &["y", "", "88888888"]);
        outcome.unwrap_or_else(|e| panic!("{e:#}\n{}", script.text()));
        assert!(script
            .text()
            .contains("REPLACE the key in slot 0x82 with a new one"));
        assert_ready(&piv, PIN);
    }

    #[test]
    fn unusable_certificate_asks_before_replacing() {
        // Slot 0x82 holds a key and data that is not a certificate.
        let (piv, _t) = card_from_yaml(
            "credentials:\n  pin: \"654321\"\n  puk: \"87654321\"\n\
             slots:\n  \"82\":\n    private_key_hex: \
             \"64055b21eefa9776a601bd99b0a5aa45c9d29d8ac0106b83844871bc4a9c748c\"\n    \
             cert_der_hex: \"3003020101\"\n",
        );
        let mut ctx = context(&piv, Some(PIN));
        let (outcome, script) = guided(&mut ctx, &[""]);
        assert!(is_cancelled(&outcome), "{outcome:?}");
        let text = script.text();
        assert!(
            text.contains("Warning: the certificate in slot 0x82 cannot be parsed."),
            "{text}"
        );
        assert!(
            text.contains("It may be used by another application."),
            "{text}"
        );
        assert_eq!(piv.write_count(), 0);
    }

    #[test]
    fn wrong_current_pin_stops_at_once() {
        let piv = Arc::new(with_key_piv());
        let mut ctx = context(&piv, None);
        let (outcome, _) = guided(&mut ctx, &["000000"]);
        let text = format!("{:#}", outcome.unwrap_err());
        assert!(text.contains("nothing was changed"), "{text}");
        assert_eq!(piv.write_count(), 0);
    }

    #[test]
    fn unreadable_store_needs_the_serial() {
        let (piv, setup) = formatted_card_with_piv();
        piv.write_object(&setup.reader, OBJECT_ID_ZERO, b"garbage", MGMT)
            .unwrap();
        let mut ctx = context(&piv, Some(PIN));
        let (outcome, script) = guided(&mut ctx, &["k", "", "y"]);
        assert!(is_cancelled(&outcome), "a plain yes is not enough");
        assert!(script
            .text()
            .contains("This will destroy the unreadable store on YubiKey 88888888."));
    }

    #[test]
    fn blocked_pin_stops_before_any_question() {
        let (piv, _t) = card_from_yaml(
            "credentials:\n  pin: \"654321\"\n  puk: \"87654321\"\n  pin_retries: 0\n",
        );
        let mut ctx = context(&piv, Some(PIN));
        let (outcome, _) = guided(&mut ctx, &[]);
        let text = yb_core::errors::render(&outcome.unwrap_err(), &Default::default());
        assert!(text.contains("the PIN is blocked"), "{text}");
        assert!(text.contains("ykman piv access unblock-pin"), "{text}");
        assert_eq!(piv.write_count(), 0);
    }

    #[test]
    fn allow_defaults_keeps_the_factory_pin_and_puk() {
        let piv = Arc::new(VirtualPiv::new());
        let mut ctx = context(&piv, None);
        ctx.allow_defaults = true;
        ctx.quiet = false;
        let (outcome, script) = guided(&mut ctx, &["", "y"]);
        outcome.unwrap_or_else(|e| panic!("{e:#}\n{}", script.text()));
        let text = script.text();
        assert!(!text.contains("Change PIN"), "{text}");
        assert!(text.contains("The factory PIN/PUK were kept"), "{text}");
        let defaults = detect_default_credentials(&piv.reader_name(), piv.as_ref());
        assert!(defaults.pin && defaults.puk && !defaults.management_key);
    }

    #[test]
    fn complexity_rejection_asks_again() {
        let piv = Arc::new(VirtualPiv::new());
        piv.inject_fault(Fault::ChangeReferenceComplexity);
        let mut ctx = context(&piv, None);
        let (outcome, script) = guided(
            &mut ctx,
            &[
                "111111", "111111", NEW_PUK, NEW_PUK, "", "y", NEW_PIN, NEW_PIN,
            ],
        );
        outcome.unwrap_or_else(|e| panic!("{e:#}\n{}", script.text()));
        assert!(
            script
                .text()
                .contains("the new PIN does not meet this YubiKey's complexity requirement"),
            "{}",
            script.text()
        );
        assert_ready(&piv, NEW_PIN);
    }

    #[test]
    fn legacy_flag_is_repaired_and_the_key_kept() {
        let (piv, _) = protected_card_with_piv(&ADMIN_LEGACY);
        let mut ctx = context(&piv, Some(PIN));
        let (outcome, script) = guided(&mut ctx, &["k", "", "y"]);
        outcome.unwrap_or_else(|e| panic!("{e:#}\n{}", script.text()));
        assert!(script
            .text()
            .contains("Keep the management key stored on the YubiKey (3DES)"));
        let admin = AdminData::parse(&read_admin(&ctx)).unwrap();
        assert_eq!(admin.flags, Some(0x02));
        let keys = read_printed_keys(&ctx.reader, piv.as_ref(), PIN).unwrap();
        assert_eq!(keys.current.as_deref(), Some(OTHER_KEY));
        assert_ready(&piv, PIN);
    }

    #[test]
    fn firmware_57_keeps_aes192() {
        let piv = Arc::new(VirtualPiv::from_fixture_yaml(fixtures::AES192).unwrap());
        let mut ctx = context(&piv, Some(PIN));
        // The key in slot 0x82 has no certificate: replaced, so the serial.
        let (outcome, script) = guided(&mut ctx, &["", "77777777"]);
        outcome.unwrap_or_else(|e| panic!("{e:#}\n{}", script.text()));
        assert!(script.text().contains("with a random one (AES-192)"));
        assert_eq!(
            piv.management_key_algorithm(&ctx.reader).unwrap(),
            MgmtAlgo::Aes192
        );
        assert_ready(&piv, PIN);
    }

    #[test]
    fn unknown_management_key_is_asked_for() {
        // Unprotected card whose key is neither stored nor the factory key.
        let (piv, setup) = formatted_card_with_piv();
        piv.set_management_key(&setup.reader, MGMT, OTHER_KEY, MgmtAlgo::Tdes)
            .unwrap();
        let mut ctx = context(&piv, Some(PIN));
        let (outcome, script) = guided(&mut ctx, &["k", OTHER_KEY, "", "y"]);
        outcome.unwrap_or_else(|e| panic!("{e:#}\n{}", script.text()));
        // The fsck hint (spec 0027 §8) is not shown: the flow stores the key.
        assert!(!script.text().contains("rotate-management-key"));
        assert_ready(&piv, PIN);
    }

    #[test]
    fn guided_mode_needs_no_format_flag() {
        assert!(FormatArgs::default().has_no_format_flags());
        let flagged = [
            FormatArgs {
                generate: true,
                ..Default::default()
            },
            FormatArgs {
                protect: true,
                ..Default::default()
            },
            FormatArgs {
                object_count: Some(32),
                ..Default::default()
            },
            FormatArgs {
                key_slot: Some("0x82".to_owned()),
                ..Default::default()
            },
            FormatArgs {
                subject: Some("CN=x".to_owned()),
                ..Default::default()
            },
            FormatArgs {
                yes: true,
                ..Default::default()
            },
            FormatArgs {
                plan: true,
                ..Default::default()
            },
        ];
        for args in flagged {
            assert!(!args.has_no_format_flags(), "{args:?}");
        }
    }

    // --plan (spec 0023 §7)

    fn plan_args(generate: bool, protect: bool) -> FormatArgs {
        FormatArgs {
            generate,
            protect,
            plan: true,
            ..Default::default()
        }
    }

    #[test]
    fn plan_writes_nothing_and_matches_the_guided_plan() {
        let (piv, setup) = formatted_card_with_piv();
        store_one(&setup, "old").unwrap();
        let before = piv.write_count();

        let ctx = context(&piv, Some(PIN));
        let mut out = Vec::new();
        format_with_output(&ctx, &plan_args(true, true), &mut out).unwrap();
        assert_eq!(piv.write_count(), before);
        let plan = String::from_utf8(out).unwrap();
        let plan = &plan[plan.find("Plan for").unwrap()..];

        // Same choices in the guided flow: generate, 32 objects; then say no.
        let mut ctx = context(&piv, Some(PIN));
        let (outcome, script) = guided(&mut ctx, &["g", "", "no"]);
        assert!(is_cancelled(&outcome));
        assert!(
            script.text().contains(plan),
            "{plan}\n---\n{}",
            script.text()
        );
        assert_eq!(piv.write_count(), before);
    }

    #[test]
    fn plan_fails_like_the_real_command() {
        let piv = Arc::new(with_key_piv()); // key without certificate
        let ctx = context(&piv, Some(PIN));
        let mut out = Vec::new();
        let err = format_with_output(&ctx, &plan_args(false, false), &mut out).unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("nothing was changed"), "{text}");
        assert!(text.contains("no certificate in slot 0x82"), "{text}");
        assert_eq!(piv.write_count(), 0);
    }

    // fsck YubiKey section (spec 0023 §2)

    fn fsck(ctx: &Context, check_key: bool) -> (bool, String) {
        let mut out = Vec::new();
        let args = FsckArgs {
            verbose: false,
            nvm: false,
            check_key,
        };
        let healthy = fsck_check(ctx, &args, &mut out).unwrap();
        (healthy, String::from_utf8(out).unwrap())
    }

    #[test]
    fn fsck_on_a_factory_card_without_store() {
        let piv = Arc::new(VirtualPiv::new());
        let ctx = context(&piv, None);
        let (healthy, text) = fsck(&ctx, true);
        assert!(healthy, "{text}");
        assert!(
            text.contains("  PIN              warning: factory default (3/3 tries left)"),
            "{text}"
        );
        assert!(
            text.ends_with("Store: none — run `yb format` to create one\n"),
            "{text}"
        );
        assert_eq!(piv.write_count(), 0);
    }

    #[test]
    fn fsck_check_key_reports_a_mismatch() {
        let (piv, setup) = formatted_card_with_piv();
        piv.inject_fault(Fault::GenerateCertificateFailsAfterKey);
        let _ = setup
            .piv
            .generate_certificate(&setup.reader, 0x82, "CN=X", MGMT, None);
        let before = piv.write_count();
        let ctx = context(&piv, Some(PIN));

        let (healthy, text) = fsck(&ctx, false);
        assert!(healthy, "not checked without --check-key: {text}");
        assert!(text.contains("not checked (use --check-key)"), "{text}");

        let (healthy, text) = fsck(&ctx, true);
        assert!(!healthy);
        assert!(
            text.contains("Key/certificate  ERROR: the key does not match its certificate"),
            "{text}"
        );
        assert_eq!(piv.write_count(), before);
    }

    #[test]
    fn fsck_unreadable_store_is_an_error() {
        let (piv, setup) = formatted_card_with_piv();
        piv.write_object(&setup.reader, OBJECT_ID_ZERO, b"garbage", MGMT)
            .unwrap();
        let (healthy, text) = fsck(&context(&piv, Some(PIN)), false);
        assert!(!healthy);
        assert!(text.contains("Store: unreadable ("), "{text}");
    }

    /// The store part is what `yb fsck` printed before spec 0023.
    #[test]
    fn fsck_store_output_is_unchanged() {
        let (piv, setup) = formatted_card_with_piv();
        store_one(&setup, "blob").unwrap();
        let (healthy, text) = fsck(&context(&piv, Some(PIN)), false);
        assert!(healthy);
        let store_part = &text[text.find("Store:").unwrap()..];
        let size = Store::from_device(&setup.reader, piv.as_ref())
            .unwrap()
            .objects[0]
            .object_size();
        assert_eq!(
            store_part,
            format!(
                "Store: 8 objects, slot 0x82, age 1\n\
                 Blobs: 1 stored, 7 objects free (~{size} bytes used by store)\n\
                 \n\
                 \x20 blob                           VERIFIED\n\
                 \n\
                 Integrity: 1 verified, 0 unverified, 0 corrupted\n"
            )
        );
    }
}

// ---------------------------------------------------------------------------
// yb rotate-management-key (spec 0027)
// ---------------------------------------------------------------------------

mod rotation_tests {
    use super::cards::*;
    use super::*;
    use yb::cli::fsck::{check as fsck_check, FsckArgs};
    use yb::cli::rotate_management_key::{run as rotate_run, RotateManagementKeyArgs};
    use yb_core::auxiliaries::{
        encode_printed, read_printed_keys, AdminData, PrintedKeys, ProtectionMode, OBJ_ADMIN_DATA,
        OBJ_PRINTED,
    };
    use yb_core::{fetch_blob, Fault, MgmtAlgo, PivBackend};

    /// A third 24-byte key, neither `MGMT` nor `OTHER_KEY`.
    const THIRD_KEY: &str = "d1d2d3d4d5d6d7d8e1e2e3e4e5e6e7e8f1f2f3f4f5f6f7f8";

    fn rotate(ctx: &Context) -> anyhow::Result<()> {
        rotate_run(ctx, &RotateManagementKeyArgs {})
    }

    fn printed_keys(ctx: &Context) -> PrintedKeys {
        read_printed_keys(&ctx.reader, ctx.piv.as_ref(), PIN).unwrap()
    }

    /// The card keeps a new key, only in tag 89, with the standard flag;
    /// blob "kept" still decrypts and writes need only the PIN.
    fn assert_rotated(ctx: &Context, old_key: &str) {
        let keys = printed_keys(ctx);
        let new_key = keys.current.expect("new key in PRINTED");
        assert_ne!(new_key, old_key);
        assert_eq!(keys.previous, None, "tag 8A dropped");
        ctx.piv
            .authenticate_management_key(&ctx.reader, &new_key)
            .unwrap();
        let admin = AdminData::parse(&read_admin(ctx)).unwrap();
        assert_eq!(admin.flags, Some(0x02));

        let after = reopen(ctx);
        assert_eq!(after.protection, ProtectionMode::Standard);
        let store = Store::from_device(&after.reader, after.piv.as_ref()).unwrap();
        fetch_blob(
            &store,
            after.piv.as_ref(),
            &after.reader,
            "kept",
            Some(PIN),
            false,
        )
        .unwrap();
        store_one(&after, "after").unwrap();
    }

    #[test]
    fn rotates_a_stored_key() {
        let (_piv, setup) = protected_card_with_piv(&ADMIN_STANDARD);
        store_one(&setup, "kept").unwrap();
        let ctx = reopen(&setup);
        rotate(&ctx).unwrap();
        assert_rotated(&ctx, OTHER_KEY);
    }

    #[test]
    fn stores_the_factory_key_replacement_and_keeps_the_store() {
        let (piv, setup) = formatted_card_with_piv();
        store_one(&setup, "kept").unwrap();
        let ctx = reopen(&setup);
        let store_objects = || -> Vec<Vec<u8>> {
            (0..8)
                .map(|i| piv.read_object(&ctx.reader, 0x5F_0000 + i).unwrap())
                .collect()
        };
        let before = store_objects();
        rotate(&ctx).unwrap();
        assert_eq!(store_objects(), before, "store untouched");
        assert_rotated(&ctx, MGMT);
    }

    #[test]
    fn stores_an_explicit_key_replacement() {
        let (piv, setup) = formatted_card_with_piv();
        store_one(&setup, "kept").unwrap();
        piv.set_management_key(&setup.reader, MGMT, OTHER_KEY, MgmtAlgo::Tdes)
            .unwrap();
        let mut ctx = reopen(&setup);
        ctx.management_key = Some(OTHER_KEY.to_owned());
        rotate(&ctx).unwrap();
        assert_rotated(&ctx, OTHER_KEY);
    }

    #[test]
    fn repairs_the_legacy_flag() {
        let (piv, setup) = protected_card_with_piv(&ADMIN_STANDARD);
        store_one(&setup, "kept").unwrap();
        // Set the legacy flag after the store, whose write would repair it.
        piv.write_object(&setup.reader, OBJ_ADMIN_DATA, &ADMIN_LEGACY, OTHER_KEY)
            .unwrap();
        let ctx = reopen(&setup);
        assert_eq!(ctx.protection, ProtectionMode::LegacyOrPukBlocked);
        rotate(&ctx).unwrap();
        assert_rotated(&ctx, OTHER_KEY);
    }

    #[test]
    fn keeps_aes192() {
        let mut ctx = make_ctx(VirtualPiv::from_fixture_yaml(fixtures::AES192).unwrap());
        ctx.management_key = None;
        rotate(&ctx).unwrap();
        assert_eq!(
            ctx.piv.management_key_algorithm(&ctx.reader).unwrap(),
            MgmtAlgo::Aes192
        );
        assert_eq!(reopen(&ctx).protection, ProtectionMode::Standard);
    }

    #[test]
    fn factory_pin_refuses_without_writing() {
        let piv = Arc::new(VirtualPiv::new());
        let mut ctx = Context::with_backend(piv.clone(), None, false).unwrap();
        ctx.quiet = true;
        let err = rotate(&ctx).unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("nothing was changed"), "{text}");
        assert!(text.contains("factory-default PIN and PUK"), "{text}");
        assert_eq!(piv.write_count(), 0);

        ctx.allow_defaults = true;
        rotate(&ctx).unwrap();
    }

    /// Spec 0022 invariants I2 and I4 at every fault point; the store is
    /// never touched.
    #[test]
    fn invariants_hold_for_every_fault() {
        let faults = [
            Fault::WriteFails(1), // B1a
            Fault::WriteFails(2), // B1c
            Fault::WriteFails(3), // B1d
            Fault::SetManagementKeyRejected,
            Fault::SetManagementKeyLostReply,
            Fault::CardLostDuringSetManagementKey { applied: true },
            Fault::CardLostDuringSetManagementKey { applied: false },
        ];
        for stored in [false, true] {
            for fault in faults {
                let case = format!("stored={stored} fault={fault:?}");
                let (piv, setup) = if stored {
                    protected_card_with_piv(&ADMIN_STANDARD)
                } else {
                    formatted_card_with_piv()
                };
                store_one(&setup, "kept").unwrap();
                let ctx = reopen(&setup);
                piv.inject_fault(fault);
                let outcome = rotate(&ctx);

                // I4, and spec 0027 §3b: no key material, no advice to run
                // the store-erasing `yb format --protect`.
                if let Err(ref e) = outcome {
                    let text = format!("{e:#}");
                    for key in [MGMT, OTHER_KEY] {
                        assert!(!text.contains(key), "{case}: I4 violated: {text}");
                    }
                    assert!(!text.contains("format --protect"), "{case}: {text}");
                }

                // I2: after reconnecting, the key is found, and the next
                // write repairs what is left.
                piv.clear_faults();
                let after = reopen(&ctx);
                store_one(&after, "after").unwrap_or_else(|e| panic!("{case}: {e:#}"));
                assert_eq!(printed_keys(&after).previous, None, "{case}");
                assert!(
                    list_blobs(&Store::from_device(&after.reader, after.piv.as_ref()).unwrap())
                        .iter()
                        .any(|b| b.name == "kept"),
                    "{case}: store touched"
                );
            }
        }
    }

    /// Spec 0027 §3b: B1d failing is not an error; the next write drops
    /// the old key from PRINTED.
    #[test]
    fn failed_cleanup_is_silent_and_repaired_later() {
        let (piv, setup) = protected_card_with_piv(&ADMIN_STANDARD);
        let ctx = reopen(&setup);
        piv.inject_fault(Fault::WriteFails(3));
        rotate(&ctx).unwrap();
        assert_eq!(printed_keys(&ctx).previous.as_deref(), Some(OTHER_KEY));
        store_one(&reopen(&ctx), "after").unwrap();
        assert_eq!(printed_keys(&ctx).previous, None);
    }

    /// Spec 0027 §3a: a stored key given through YB_MANAGEMENT_KEY stays
    /// in PRINTED after a rejected switch.
    #[test]
    fn rejected_switch_keeps_a_stored_explicit_key() {
        let (piv, setup) = protected_card_with_piv(&ADMIN_STANDARD);
        let mut ctx = reopen(&setup);
        ctx.management_key = Some(OTHER_KEY.to_owned());
        piv.inject_fault(Fault::SetManagementKeyRejected);
        let err = rotate(&ctx).unwrap_err();
        assert!(
            format!("{err:#}").contains("nothing was changed"),
            "{err:#}"
        );
        assert_eq!(
            piv.read_object(&ctx.reader, OBJ_PRINTED).unwrap(),
            printed(OTHER_KEY)
        );
    }

    /// Spec 0027 §3a: when tag 8A holds the only copy of the card's key,
    /// a rejected switch writes it back.
    #[test]
    fn rejected_switch_keeps_a_key_only_in_8a() {
        let (piv, setup) = protected_card_with_piv(&ADMIN_STANDARD);
        let stale = encode_printed(THIRD_KEY, Some(OTHER_KEY)).unwrap();
        piv.write_object(&setup.reader, OBJ_PRINTED, &stale, OTHER_KEY)
            .unwrap();
        let ctx = reopen(&setup);
        piv.inject_fault(Fault::SetManagementKeyRejected);
        assert!(rotate(&ctx).is_err());
        assert_eq!(
            piv.read_object(&ctx.reader, OBJ_PRINTED).unwrap(),
            printed(OTHER_KEY)
        );
    }

    /// Spec 0027 §8: `yb fsck` suggests the command, in plain words, when
    /// the key is neither kept on the YubiKey nor the factory key.
    #[test]
    fn fsck_hint() {
        let fsck = |ctx: &Context| {
            let mut out = Vec::new();
            let args = FsckArgs {
                verbose: false,
                nvm: false,
                check_key: false,
            };
            let healthy = fsck_check(ctx, &args, &mut out).unwrap();
            (healthy, String::from_utf8(out).unwrap())
        };
        let (piv, setup) = formatted_card_with_piv();

        // Factory key: no hint.
        let (_, text) = fsck(&reopen(&setup));
        assert!(!text.contains("rotate-management-key"), "{text}");

        piv.set_management_key(&setup.reader, MGMT, OTHER_KEY, MgmtAlgo::Tdes)
            .unwrap();
        let (healthy, text) = fsck(&reopen(&setup));
        assert!(healthy, "a hint is not a warning");
        assert!(
            text.contains(
                "  Management key   3DES, not stored on the YubiKey\n\
                 \x20                  yb store and yb remove need it each time \
                 (YB_MANAGEMENT_KEY).\n\
                 \x20                  To have yb keep it on the YubiKey, unlocked by your PIN:\n\
                 \x20                  yb rotate-management-key\n"
            ),
            "{text}"
        );
        assert!(!text.contains("protect"), "no jargon: {text}");
    }
}
