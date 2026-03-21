// SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Subprocess CLI tests for the `yb` binary.
//!
//! Each test invokes the compiled `yb` binary via `std::process::Command`
//! with `YB_FIXTURE` pointing to a per-test copy of the `with_key.yaml`
//! fixture.  This exercises argument parsing, env-var resolution, exit codes,
//! and stdout/stderr content — the layers that the direct-call tests in
//! `rust/yb/tests/cli_tests.rs` do not reach.
//!
//! Requires the `integration-tests` feature (same as `hardware_piv_tests`).

#![cfg(feature = "integration-tests")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MGMT: &str = "010203040506070801020304050607080102030405060708";
const PIN: &str = "123456";
const FIXTURE_SRC: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../yb-core/tests/fixtures/with_key.yaml"
);

// ---------------------------------------------------------------------------
// Binary path
// ---------------------------------------------------------------------------

/// Path to the `yb` binary under test.
///
/// In the NixOS VM the pre-built binary is injected via `YB_BIN`.
/// In a local `cargo test` run we derive the path from the workspace
/// target directory (CARGO_BIN_EXE_yb is only set by Cargo for tests in
/// the same crate as the binary).
fn yb_bin() -> PathBuf {
    if let Ok(p) = std::env::var("YB_BIN") {
        return PathBuf::from(p);
    }
    // Derive from manifest dir: ../../target/debug/yb
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .join("..") // rust/
        .join("target")
        .join("debug")
        .join("yb")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// One test's private state: a temp dir containing a copy of with_key.yaml.
struct Fixture {
    dir: TempDir,
}

impl Fixture {
    /// Copy with_key.yaml into a fresh TempDir.
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        std::fs::copy(FIXTURE_SRC, dir.path().join("fixture.yaml")).unwrap();
        Self { dir }
    }

    fn path(&self) -> PathBuf {
        self.dir.path().join("fixture.yaml")
    }

    /// Run `yb` with this fixture and the given args/extra env vars.
    fn run(&self, extra_env: &[(&str, &str)], args: &[&str]) -> Output {
        let mut cmd = Command::new(yb_bin());
        cmd.env("YB_FIXTURE", self.path())
            .env("YB_SKIP_DEFAULT_CHECK", "1")
            .env("YB_MANAGEMENT_KEY", MGMT)
            .env("YB_PIN", PIN);
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        cmd.args(args).output().expect("failed to run yb binary")
    }

    /// Run and assert exit 0; return (stdout, stderr).
    fn ok(&self, extra_env: &[(&str, &str)], args: &[&str]) -> (String, String) {
        let out = self.run(extra_env, args);
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(
            out.status.success(),
            "expected exit 0 for {:?}\nstdout: {stdout}\nstderr: {stderr}",
            args
        );
        (stdout, stderr)
    }

    /// Run and assert exit non-zero; return (stdout, stderr).
    fn err(&self, extra_env: &[(&str, &str)], args: &[&str]) -> (String, String) {
        let out = self.run(extra_env, args);
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(
            !out.status.success(),
            "expected non-zero exit for {:?}\nstdout: {stdout}\nstderr: {stderr}",
            args
        );
        (stdout, stderr)
    }

    /// Format the store (-g generates key + cert in slot 0x82).
    fn format(&self) {
        self.ok(&[], &["format", "-g"]);
    }

    /// Store a file (unencrypted) and return its path.
    fn store_file(&self, name: &str, content: &[u8]) -> PathBuf {
        let path = self.dir.path().join(name);
        std::fs::write(&path, content).unwrap();
        self.ok(&[], &["store", "-u", path.to_str().unwrap()]);
        path
    }
}

/// Write `content` to a temp file inside `dir` and return its path.
fn tmp_file(dir: &Path, name: &str, content: &[u8]) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, content).unwrap();
    p
}

// ---------------------------------------------------------------------------
// format
// ---------------------------------------------------------------------------

#[test]
fn format_creates_store() {
    let f = Fixture::new();
    f.format();
    // A subsequent list should succeed (store is valid).
    f.ok(&[], &["list"]);
}

// ---------------------------------------------------------------------------
// store / list
// ---------------------------------------------------------------------------

#[test]
fn store_and_list() {
    let f = Fixture::new();
    f.format();
    f.store_file("hello.txt", b"world");

    let (stdout, _) = f.ok(&[], &["list"]);
    assert!(stdout.contains("hello.txt"), "list output: {stdout}");
}

#[test]
fn store_multiple_files_list() {
    let f = Fixture::new();
    f.format();

    let a = tmp_file(f.dir.path(), "alpha.bin", b"aaa");
    let b = tmp_file(f.dir.path(), "beta.bin", b"bbb");
    f.ok(
        &[],
        &["store", "-u", a.to_str().unwrap(), b.to_str().unwrap()],
    );

    let (stdout, _) = f.ok(&[], &["list"]);
    assert!(stdout.contains("alpha.bin"));
    assert!(stdout.contains("beta.bin"));
}

#[test]
fn store_name_override() {
    let f = Fixture::new();
    f.format();
    let p = tmp_file(f.dir.path(), "original.txt", b"data");
    f.ok(&[], &["store", "-u", "-n", "renamed", p.to_str().unwrap()]);

    let (stdout, _) = f.ok(&[], &["list"]);
    assert!(stdout.contains("renamed"));
    assert!(!stdout.contains("original.txt"));
}

// ---------------------------------------------------------------------------
// fetch
// ---------------------------------------------------------------------------

#[test]
fn store_and_fetch_stdout() {
    let f = Fixture::new();
    f.format();
    f.store_file("msg.txt", b"hello world");

    let (stdout, _) = f.ok(&[], &["fetch", "-p", "msg.txt"]);
    assert_eq!(stdout.as_bytes(), b"hello world");
}

#[test]
fn store_and_fetch_to_output_dir() {
    let f = Fixture::new();
    f.format();
    f.store_file("data.bin", b"payload");

    let out_dir = TempDir::new().unwrap();
    f.ok(
        &[],
        &["fetch", "-O", out_dir.path().to_str().unwrap(), "data.bin"],
    );

    let written = std::fs::read(out_dir.path().join("data.bin")).unwrap();
    assert_eq!(written, b"payload");
}

#[test]
fn fetch_glob_pattern() {
    let f = Fixture::new();
    f.format();
    f.store_file("key-a", b"a");
    f.store_file("key-b", b"b");
    f.store_file("other", b"c");

    let out_dir = TempDir::new().unwrap();
    f.ok(
        &[],
        &["fetch", "-O", out_dir.path().to_str().unwrap(), "key-*"],
    );

    assert_eq!(std::fs::read(out_dir.path().join("key-a")).unwrap(), b"a");
    assert_eq!(std::fs::read(out_dir.path().join("key-b")).unwrap(), b"b");
    assert!(!out_dir.path().join("other").exists());
}

#[test]
fn store_encrypted_fetch_with_pin() {
    let f = Fixture::new();
    f.format();

    // Store encrypted (default).
    let p = tmp_file(f.dir.path(), "secret.txt", b"topsecret");
    f.ok(&[], &["store", p.to_str().unwrap()]);

    // Fetch with PIN from YB_PIN (already set by Fixture::run).
    let (stdout, _) = f.ok(&[], &["fetch", "-p", "secret.txt"]);
    assert_eq!(stdout.as_bytes(), b"topsecret");
}

#[test]
fn fetch_missing_exits_1() {
    let f = Fixture::new();
    f.format();
    f.err(&[], &["fetch", "ghost"]);
}

#[test]
fn fetch_stdout_multi_match_exits_1() {
    let f = Fixture::new();
    f.format();
    f.store_file("x", b"x");
    f.store_file("y", b"y");
    f.err(&[], &["fetch", "--stdout", "*"]);
}

// ---------------------------------------------------------------------------
// remove
// ---------------------------------------------------------------------------

#[test]
fn remove_single_blob() {
    let f = Fixture::new();
    f.format();
    f.store_file("target", b"data");

    f.ok(&[], &["remove", "target"]);

    let (stdout, _) = f.ok(&[], &["list"]);
    assert!(!stdout.contains("target"));
}

#[test]
fn remove_glob() {
    let f = Fixture::new();
    f.format();
    f.store_file("tmp-a", b"a");
    f.store_file("tmp-b", b"b");
    f.store_file("keep", b"k");

    f.ok(&[], &["remove", "tmp-*"]);

    let (stdout, _) = f.ok(&[], &["list"]);
    assert!(!stdout.contains("tmp-a"));
    assert!(!stdout.contains("tmp-b"));
    assert!(stdout.contains("keep"));
}

#[test]
fn remove_missing_exits_1() {
    let f = Fixture::new();
    f.format();
    f.err(&[], &["remove", "ghost"]);
}

#[test]
fn remove_ignore_missing() {
    let f = Fixture::new();
    f.format();
    f.ok(&[], &["remove", "-f", "ghost"]);
}

// ---------------------------------------------------------------------------
// fsck
// ---------------------------------------------------------------------------

#[test]
fn fsck_clean_store() {
    let f = Fixture::new();
    f.format();
    f.store_file("blob", b"data");

    let (stdout, _) = f.ok(&[], &["fsck"]);
    assert!(stdout.contains("Status: OK"), "fsck output: {stdout}");
}

#[test]
fn fsck_verbose() {
    let f = Fixture::new();
    f.format();

    let (stdout, _) = f.ok(&[], &["fsck", "-v"]);
    assert!(stdout.contains("Object 0:"), "fsck -v output: {stdout}");
    assert!(stdout.contains("Status: OK"));
}

// ---------------------------------------------------------------------------
// list flags
// ---------------------------------------------------------------------------

#[test]
fn list_long_format() {
    let f = Fixture::new();
    f.format();
    f.store_file("blob", b"data");

    let (stdout, _) = f.ok(&[], &["list", "-l"]);
    // Long format has flag char + chunks + date + size + name.
    assert!(stdout.contains("blob"), "list -l output: {stdout}");
    // Flag char 'P' because we stored unencrypted.
    assert!(stdout.contains('P'), "expected P flag: {stdout}");
}

#[test]
fn list_sort_reverse() {
    let f = Fixture::new();
    f.format();
    f.store_file("aaa", b"a");
    f.store_file("zzz", b"z");

    let (fwd, _) = f.ok(&[], &["list"]);
    let (rev, _) = f.ok(&[], &["list", "-r"]);

    let fwd_names: Vec<&str> = fwd.lines().collect();
    let rev_names: Vec<&str> = rev.lines().collect();
    assert_eq!(
        fwd_names,
        rev_names.iter().rev().cloned().collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// argument / flag tests
// ---------------------------------------------------------------------------

#[test]
fn quiet_suppresses_stderr() {
    let f = Fixture::new();
    f.format();
    let p = tmp_file(f.dir.path(), "q.txt", b"data");
    let (_, stderr) = f.ok(&[], &["-q", "store", "-u", p.to_str().unwrap()]);
    assert!(
        stderr.is_empty(),
        "expected empty stderr with -q, got: {stderr}"
    );
}

#[test]
fn pin_from_env() {
    let f = Fixture::new();
    f.format();
    let p = tmp_file(f.dir.path(), "enc.txt", b"secret");
    // Store encrypted.
    f.ok(&[], &["store", p.to_str().unwrap()]);
    // Fetch with YB_PIN (Fixture::run sets it automatically).
    let (stdout, _) = f.ok(&[], &["fetch", "-p", "enc.txt"]);
    assert_eq!(stdout.as_bytes(), b"secret");
}

#[test]
fn pin_from_stdin() {
    let f = Fixture::new();
    f.format();
    let p = tmp_file(f.dir.path(), "enc2.txt", b"pintest");
    f.ok(&[], &["store", p.to_str().unwrap()]);

    // Pipe PIN via --pin-stdin; unset YB_PIN so it doesn't interfere.
    let out = Command::new(yb_bin())
        .env("YB_FIXTURE", f.path())
        .env("YB_SKIP_DEFAULT_CHECK", "1")
        .env("YB_MANAGEMENT_KEY", MGMT)
        .env_remove("YB_PIN")
        .args(["--pin-stdin", "fetch", "-p", "enc2.txt"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    use std::io::Write as _;
    let mut child = out;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{PIN}\n").as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(stdout.as_bytes(), b"pintest");
}

#[test]
fn deprecated_pin_flag_warns() {
    let f = Fixture::new();
    f.format();
    f.store_file("x", b"x");

    // Use --pin explicitly (deprecated flag).
    let out = Command::new(yb_bin())
        .env("YB_FIXTURE", f.path())
        .env("YB_SKIP_DEFAULT_CHECK", "1")
        .env("YB_MANAGEMENT_KEY", MGMT)
        .env_remove("YB_PIN")
        .args(["--pin", PIN, "list"])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success());
    assert!(
        stderr.contains("--pin is deprecated"),
        "expected deprecation warning, got: {stderr}"
    );
}

#[test]
fn deprecated_key_flag_warns() {
    let f = Fixture::new();
    f.format();

    let out = Command::new(yb_bin())
        .env("YB_FIXTURE", f.path())
        .env("YB_SKIP_DEFAULT_CHECK", "1")
        .env_remove("YB_MANAGEMENT_KEY")
        .args(["--key", MGMT, "list"])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success());
    assert!(
        stderr.contains("--key is deprecated"),
        "expected deprecation warning, got: {stderr}"
    );
}

#[test]
fn deprecated_extract_flag_warns() {
    let f = Fixture::new();
    f.format();
    f.store_file("e", b"e");

    let out_dir = TempDir::new().unwrap();
    let out = f.run(
        &[],
        &["fetch", "-x", "-O", out_dir.path().to_str().unwrap(), "e"],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success());
    assert!(
        stderr.contains("--extract is deprecated"),
        "expected deprecation warning, got: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// error paths
// ---------------------------------------------------------------------------

#[test]
fn store_no_name_stdin_exits_1() {
    let f = Fixture::new();
    f.format();
    // No files and no --name: must error.
    f.err(&[], &["store"]);
}

#[test]
fn store_duplicate_basename_exits_1() {
    let f = Fixture::new();
    f.format();

    let d1 = f.dir.path().join("d1");
    let d2 = f.dir.path().join("d2");
    std::fs::create_dir_all(&d1).unwrap();
    std::fs::create_dir_all(&d2).unwrap();
    std::fs::write(d1.join("clash"), b"one").unwrap();
    std::fs::write(d2.join("clash"), b"two").unwrap();

    let (_, stderr) = f.err(
        &[],
        &[
            "store",
            "-u",
            d1.join("clash").to_str().unwrap(),
            d2.join("clash").to_str().unwrap(),
        ],
    );
    assert!(stderr.contains("duplicate blob name"), "stderr: {stderr}");
}

// ---------------------------------------------------------------------------
// shell completions
// ---------------------------------------------------------------------------

/// Run `yb` in dynamic-completion mode and return the completion candidates.
///
/// The clap_complete dynamic protocol re-invokes the binary with
/// `YB_COMPLETE=<shell>`, `_CLAP_COMPLETE_INDEX=<cursor_pos>`, and the full
/// command line (including argv[0]) appended after `--`.
///
/// Example: completing `yb fetch ho` maps to:
///   args_after_dashdash = ["yb", "fetch", "ho"]
///   cursor_index        = 2   (0-based index of "ho" in that list)
fn complete(
    fixture: &Fixture,
    shell: &str,
    cursor_index: usize,
    args_after_dashdash: &[&str],
) -> String {
    let out = Command::new(yb_bin())
        .env("YB_FIXTURE", fixture.path())
        .env("YB_SKIP_DEFAULT_CHECK", "1")
        .env("YB_MANAGEMENT_KEY", MGMT)
        .env("YB_PIN", PIN)
        .env("YB_COMPLETE", shell)
        .env("_CLAP_COMPLETE_INDEX", cursor_index.to_string())
        .env("_CLAP_COMPLETE_SPACE", "false")
        .arg("--")
        .args(args_after_dashdash)
        .output()
        .expect("failed to run yb for completion");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn completion_script_bash_exits_0() {
    let f = Fixture::new();
    let out = Command::new(yb_bin())
        .env("YB_FIXTURE", f.path())
        .env("YB_COMPLETE", "bash")
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("_clap_complete_yb"),
        "expected bash completion function, got: {stdout}"
    );
}

#[test]
fn completion_script_zsh_exits_0() {
    let f = Fixture::new();
    let out = Command::new(yb_bin())
        .env("YB_FIXTURE", f.path())
        .env("YB_COMPLETE", "zsh")
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("#compdef yb"),
        "expected zsh completion script, got: {stdout}"
    );
}

#[test]
fn completion_script_fish_exits_0() {
    let f = Fixture::new();
    let out = Command::new(yb_bin())
        .env("YB_FIXTURE", f.path())
        .env("YB_COMPLETE", "fish")
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("YB_COMPLETE=fish"),
        "expected fish completion script, got: {stdout}"
    );
}

#[test]
fn completion_subcommands_listed() {
    // Completing "yb <Tab>" should return subcommand names.
    let f = Fixture::new();
    let candidates = complete(&f, "bash", 1, &["yb", ""]);
    assert!(candidates.contains("store"), "subcommands: {candidates}");
    assert!(candidates.contains("fetch"), "subcommands: {candidates}");
    assert!(candidates.contains("list"), "subcommands: {candidates}");
    assert!(candidates.contains("remove"), "subcommands: {candidates}");
    assert!(candidates.contains("format"), "subcommands: {candidates}");
    assert!(candidates.contains("fsck"), "subcommands: {candidates}");
}

#[test]
fn completion_blob_names_fetch() {
    // After storing a blob, completing "yb fetch <Tab>" should return its name.
    let f = Fixture::new();
    f.format();
    f.store_file("alpha.txt", b"a");
    f.store_file("beta.txt", b"b");

    let candidates = complete(&f, "bash", 2, &["yb", "fetch", ""]);
    assert!(candidates.contains("alpha.txt"), "candidates: {candidates}");
    assert!(candidates.contains("beta.txt"), "candidates: {candidates}");
}

#[test]
fn completion_blob_names_prefix_filtered() {
    // Completing "yb fetch al<Tab>" should return only matching blobs.
    let f = Fixture::new();
    f.format();
    f.store_file("alpha.txt", b"a");
    f.store_file("beta.txt", b"b");

    let candidates = complete(&f, "bash", 2, &["yb", "fetch", "al"]);
    assert!(candidates.contains("alpha.txt"), "candidates: {candidates}");
    assert!(
        !candidates.contains("beta.txt"),
        "unexpected match: {candidates}"
    );
}

#[test]
fn completion_blob_names_list() {
    let f = Fixture::new();
    f.format();
    f.store_file("myblob", b"data");

    let candidates = complete(&f, "bash", 2, &["yb", "list", ""]);
    assert!(candidates.contains("myblob"), "candidates: {candidates}");
}

#[test]
fn completion_blob_names_remove() {
    let f = Fixture::new();
    f.format();
    f.store_file("removeme", b"x");

    let candidates = complete(&f, "bash", 2, &["yb", "remove", ""]);
    assert!(candidates.contains("removeme"), "candidates: {candidates}");
}

#[test]
fn completion_no_blobs_returns_empty() {
    // A formatted but empty store should return no blob-name candidates.
    let f = Fixture::new();
    f.format();

    let candidates = complete(&f, "bash", 2, &["yb", "fetch", ""]);
    // Only flags should appear, not blob names.
    assert!(
        !candidates.lines().any(|l| !l.starts_with('-')),
        "expected only flags, got: {candidates}"
    );
}

// ---------------------------------------------------------------------------
// list-readers
// ---------------------------------------------------------------------------

#[test]
fn list_readers_with_fixture() {
    let f = Fixture::new();
    // list-readers does not need a formatted store.
    let (stdout, _) = f.ok(&[], &["list-readers"]);
    // The with_key fixture's reader is "Virtual YubiKey 00 01".
    assert!(
        stdout.contains("Virtual YubiKey"),
        "list-readers output: {stdout}"
    );
}
