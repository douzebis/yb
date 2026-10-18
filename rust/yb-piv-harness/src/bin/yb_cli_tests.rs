// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
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
//! A binary (libtest-mimic) built with the `integration-tests` feature,
//! like `hardware_piv_tests` (spec 0029 §4).  Run with:
//!   cargo build -p yb
//!   cargo run -p yb-piv-harness --features integration-tests --bin yb_cli_tests

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MGMT: &str = "010203040506070801020304050607080102030405060708";
/// PIN of the `with_key.yaml` fixture (not the factory PIN, spec 0024 §4a).
const PIN: &str = "654321";

/// The `with_key.yaml` fixture, compiled into `yb-core`, so that this
/// binary needs no source tree at run time (spec 0029 §5).
use yb_core::piv::virtual_piv::fixtures::WITH_KEY as WITH_KEY_FIXTURE;

// ---------------------------------------------------------------------------
// Binary path
// ---------------------------------------------------------------------------

/// Path to the `yb` binary under test.
///
/// It must be built with the `test-fixture` feature, without which yb
/// ignores `YB_FIXTURE` (spec 0034 G3).  In the NixOS VM it is injected via
/// `YB_BIN`.  Locally, `cargo build -p yb --features test-fixture` builds
/// it where this derives the path from the workspace target directory
/// (CARGO_BIN_EXE_yb is only set by Cargo for tests in the same crate as
/// the binary).
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
    /// Write with_key.yaml into a fresh TempDir.
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("fixture.yaml"), WITH_KEY_FIXTURE).unwrap();
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

fn format_creates_store() {
    let f = Fixture::new();
    f.format();
    // A subsequent list should succeed (store is valid).
    f.ok(&[], &["list"]);
}

// ---------------------------------------------------------------------------
// store / list
// ---------------------------------------------------------------------------

fn store_and_list() {
    let f = Fixture::new();
    f.format();
    f.store_file("hello.txt", b"world");

    let (stdout, _) = f.ok(&[], &["list"]);
    assert!(stdout.contains("hello.txt"), "list output: {stdout}");
}

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

fn store_and_fetch_stdout() {
    let f = Fixture::new();
    f.format();
    f.store_file("msg.txt", b"hello world");

    let (stdout, _) = f.ok(&[], &["fetch", "-p", "msg.txt"]);
    assert_eq!(stdout.as_bytes(), b"hello world");
}

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

fn fetch_missing_exits_1() {
    let f = Fixture::new();
    f.format();
    f.err(&[], &["fetch", "ghost"]);
}

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

fn remove_single_blob() {
    let f = Fixture::new();
    f.format();
    f.store_file("target", b"data");

    f.ok(&[], &["remove", "target"]);

    let (stdout, _) = f.ok(&[], &["list"]);
    assert!(!stdout.contains("target"));
}

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

fn remove_missing_exits_1() {
    let f = Fixture::new();
    f.format();
    f.err(&[], &["remove", "ghost"]);
}

fn remove_ignore_missing() {
    let f = Fixture::new();
    f.format();
    f.ok(&[], &["remove", "-f", "ghost"]);
}

// ---------------------------------------------------------------------------
// fsck
// ---------------------------------------------------------------------------

fn fsck_clean_store() {
    let f = Fixture::new();
    f.format();
    f.store_file("blob", b"data");

    let (stdout, _) = f.ok(&[], &["fsck"]);
    assert!(stdout.contains("Integrity:"), "fsck output: {stdout}");
    assert!(stdout.contains("VERIFIED"), "fsck output: {stdout}");
}

fn fsck_verbose() {
    let f = Fixture::new();
    f.format();

    let (stdout, _) = f.ok(&[], &["fsck", "-v"]);
    assert!(stdout.contains("Object 0:"), "fsck -v output: {stdout}");
}

// ---------------------------------------------------------------------------
// list flags
// ---------------------------------------------------------------------------

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

fn store_no_name_stdin_exits_1() {
    let f = Fixture::new();
    f.format();
    // No files and no --name: must error.
    f.err(&[], &["store"]);
}

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

/// Run `yb` in dynamic-completion mode, as the bash script of
/// clap-complete-rawline does (spec 0036), and return the candidates, one
/// per line.
///
/// The script calls `YB_COMPLETE=bash yb -- <line> <word>`: `line` is the
/// command line up to the cursor (`COMP_LINE`), `word` readline's current
/// word (`$2`).  Example: completing `yb fetch ho` passes
/// `line = "yb fetch ho"`, `word = "ho"`.
fn complete(fixture: &Fixture, line: &str, word: &str) -> String {
    let out = Command::new(yb_bin())
        .env("YB_FIXTURE", fixture.path())
        .env("YB_SKIP_DEFAULT_CHECK", "1")
        .env("YB_MANAGEMENT_KEY", MGMT)
        .env("YB_PIN", PIN)
        .env("YB_COMPLETE", "bash")
        .arg("--")
        .args([line, word])
        .output()
        .expect("failed to run yb for completion");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

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
        stdout.contains("_clap_complete_rawline_yb"),
        "expected bash completion function, got: {stdout}"
    );
}

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

fn completion_subcommands_listed() {
    // Completing "yb <Tab>" should return subcommand names.
    let f = Fixture::new();
    let candidates = complete(&f, "yb ", "");
    assert!(candidates.contains("store"), "subcommands: {candidates}");
    assert!(candidates.contains("fetch"), "subcommands: {candidates}");
    assert!(candidates.contains("list"), "subcommands: {candidates}");
    assert!(candidates.contains("remove"), "subcommands: {candidates}");
    assert!(candidates.contains("format"), "subcommands: {candidates}");
    assert!(candidates.contains("fsck"), "subcommands: {candidates}");
}

fn completion_blob_names_fetch() {
    // After storing a blob, completing "yb fetch <Tab>" should return its name.
    let f = Fixture::new();
    f.format();
    f.store_file("alpha.txt", b"a");
    f.store_file("beta.txt", b"b");

    let candidates = complete(&f, "yb fetch ", "");
    assert!(candidates.contains("alpha.txt"), "candidates: {candidates}");
    assert!(candidates.contains("beta.txt"), "candidates: {candidates}");
}

fn completion_blob_names_prefix_filtered() {
    // Completing "yb fetch al<Tab>" should return only matching blobs.
    let f = Fixture::new();
    f.format();
    f.store_file("alpha.txt", b"a");
    f.store_file("beta.txt", b"b");

    let candidates = complete(&f, "yb fetch al", "al");
    assert!(candidates.contains("alpha.txt"), "candidates: {candidates}");
    assert!(
        !candidates.contains("beta.txt"),
        "unexpected match: {candidates}"
    );
}

fn completion_blob_names_list() {
    let f = Fixture::new();
    f.format();
    f.store_file("myblob", b"data");

    let candidates = complete(&f, "yb list ", "");
    assert!(candidates.contains("myblob"), "candidates: {candidates}");
}

fn completion_blob_names_remove() {
    let f = Fixture::new();
    f.format();
    f.store_file("removeme", b"x");

    let candidates = complete(&f, "yb remove ", "");
    assert!(candidates.contains("removeme"), "candidates: {candidates}");
}

fn completion_no_blobs_returns_empty() {
    // A formatted but empty store should return no blob-name candidates.
    let f = Fixture::new();
    f.format();

    let candidates = complete(&f, "yb fetch ", "");
    // Only flags should appear, not blob names.
    assert!(
        !candidates.lines().any(|l| !l.starts_with('-')),
        "expected only flags, got: {candidates}"
    );
}

// ---------------------------------------------------------------------------
// list-readers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Runner (libtest-mimic: libtest's output and flags, spec 0029 §4)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Post-quantum stores (spec 0028)
// ---------------------------------------------------------------------------

/// The emulated YubiKey's serial (the fixture's) and the user's own
/// management key (the factory one is refused for post-quantum stores).
const PQ_SERIAL: u32 = 88_888_888;
const OWN_MGMT: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718";

/// A simulated YubiKey with a post-quantum store, and the FIDO2 emulator
/// served to the yb processes (`YB_FIDO2_SOCKET`).  The FIDO2 PIN is the
/// fixture's PIN, given as `YB_PIN`.
struct PqFixture {
    fx: Fixture,
    server: yb_fido2_emulator::server::Server,
}

impl PqFixture {
    /// The card with the user's own management key, and the emulator (no
    /// FIDO2 PIN yet); no post-quantum store.
    fn bare() -> Self {
        use yb_core::fido2::socket::SOCKET_ENV;
        use yb_core::piv::{MgmtAlgo, PivBackend, VirtualPiv};

        let fx = Fixture::new();
        let server = yb_fido2_emulator::server::Server::start(
            &fx.dir.path().join("fido2.sock"),
            Some(PQ_SERIAL),
        )
        .unwrap();
        // For the work done here, through the same emulator.
        std::env::set_var(SOCKET_ENV, &server.path);
        let piv = VirtualPiv::from_fixture(&fx.path()).unwrap();
        let reader = piv.reader_name();
        piv.set_management_key(&reader, MGMT, OWN_MGMT, MgmtAlgo::Tdes)
            .unwrap();
        piv.save_fixture(&fx.path()).unwrap();
        Self { fx, server }
    }

    /// Set the emulator's FIDO2 PIN (the fixture's PIN).
    fn set_fido2_pin(&self) -> yb_core::fido2::Device {
        let dev = yb_core::fido2::pairing::open_yubikey(PQ_SERIAL, 1, &|| {}).unwrap();
        dev.set_pin(PIN).unwrap();
        dev
    }

    /// A post-quantum store, made through the library.
    fn new() -> Self {
        use yb_core::orchestrator::post_quantum::create_post_quantum_store;
        use yb_core::piv::{MgmtAlgo, PivBackend, VirtualPiv};

        let f = Self::bare();
        let dev = f.set_fido2_pin();
        let piv = VirtualPiv::from_fixture(&f.fx.path()).unwrap();
        let reader = piv.reader_name();
        create_post_quantum_store(
            &piv,
            &reader,
            &dev,
            PIN,
            OWN_MGMT,
            MgmtAlgo::Tdes,
            16,
            &|| {},
        )
        .unwrap();
        drop(dev);
        piv.save_fixture(&f.fx.path()).unwrap();
        f
    }

    fn run(&self, extra_env: &[(&str, &str)], args: &[&str]) -> Output {
        let socket = self.server.path.to_str().unwrap().to_owned();
        let mut env = vec![("YB_FIDO2_SOCKET", socket.as_str())];
        env.extend_from_slice(extra_env);
        self.fx.run(&env, args)
    }

    /// Run, expect `code`; return (stdout, stderr).
    fn expect(&self, code: i32, extra_env: &[(&str, &str)], args: &[&str]) -> (String, String) {
        let out = self.run(extra_env, args);
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert_eq!(
            out.status.code(),
            Some(code),
            "{args:?}\nstdout: {stdout}\nstderr: {stderr}"
        );
        (stdout, stderr)
    }

    fn file(&self, name: &str, content: &[u8]) -> String {
        tmp_file(self.fx.dir.path(), name, content)
            .to_str()
            .unwrap()
            .to_owned()
    }

    /// Change one byte of object `id` of the simulated card.
    fn corrupt_object(&self, id: u32, offset: usize) {
        use yb_core::piv::{PivBackend, VirtualPiv};
        let piv = VirtualPiv::from_fixture(&self.fx.path()).unwrap();
        let reader = piv.reader_name();
        let mut raw = piv.read_object(&reader, id).unwrap();
        raw[offset] ^= 0x01;
        piv.write_object(&reader, id, &raw, OWN_MGMT).unwrap();
        piv.save_fixture(&self.fx.path()).unwrap();
    }
}

fn pq_store_fetch_one_touch_per_blob() {
    let f = PqFixture::new();
    let secret = f.file("secret.txt", &b"pq secret ".repeat(300));
    let public = f.file("public.txt", b"public text");
    let before = f.server.touches();
    let (_, err) = f.expect(0, &[], &["store", &secret]);
    assert!(err.contains("Touch your YubiKey"), "{err}");
    f.expect(0, &[], &["store", "-u", &public]);
    assert_eq!(f.server.touches() - before, 2, "one touch per stored blob");

    let (out, _) = f.expect(0, &[], &["fetch", "-p", "secret.txt"]);
    assert_eq!(out.as_bytes(), b"pq secret ".repeat(300));
    let (out, _) = f.expect(0, &[], &["fetch", "-p", "public.txt"]);
    assert_eq!(out, "public text");
    assert_eq!(f.server.touches() - before, 4, "one touch per fetched blob");

    let (out, _) = f.expect(0, &[], &["ls"]);
    assert_eq!(out, "public.txt\nsecret.txt\n");
    let (out, _) = f.expect(0, &[], &["ls", "-l"]);
    assert!(out.starts_with("post-quantum store\n"), "{out}");
}

fn pq_remove() {
    let f = PqFixture::new();
    let path = f.file("gone.txt", b"bye");
    f.expect(0, &[], &["store", "-u", &path]);
    let before = f.server.touches();
    f.expect(0, &[], &["rm", "gone.txt"]);
    assert_eq!(f.server.touches() - before, 1, "one touch for rm");
    let (out, _) = f.expect(0, &[], &["ls"]);
    assert_eq!(out, "");
}

/// Spec 0045: fsck reports by application; by default it asks for no PIN
/// and no touch (a wrong YB_PIN is never tried); `--seals` checks the
/// credential, the management key and the seals.
fn pq_fsck() {
    let f = PqFixture::new();
    let path = f.file("doc.txt", b"document");
    f.expect(0, &[], &["store", &path]);
    let touches = f.server.touches();
    let (out, _) = f.expect(0, &[("YB_PIN", "000000")], &["fsck"]);
    assert_eq!(f.server.touches(), touches, "fsck touched the YubiKey");
    for line in [
        "\nPIV application — holds the store's objects\n",
        "— not used by this store",
        "\nFIDO2 application — protects this store\n",
        "  PIN              set, 8/8 tries left\n",
        "-byte ID, not checked\n",
        "Store: post-quantum, 16 objects",
        "  Management key   a copy, wrapped by FIDO2 (3DES), not checked\n",
        "CHECKSUM OK",
        "Not checked: credential, management key, seals — check with `yb fsck --seals` (needs the \
         FIDO2 PIN)\n",
    ] {
        assert!(out.contains(line), "missing {line:?} in:\n{out}");
    }
    assert!(!out.contains("Store key"), "{out}");
    assert!(!out.contains("Checked with the FIDO2 PIN"), "{out}");

    let (out, err) = f.expect(0, &[], &["fsck", "--seals"]);
    // The touches announced before the PIN, then numbered (spec 0051 S4).
    assert!(err.contains("Checking the seals: "), "{err}");
    assert!(
        err.contains("Touch your YubiKey (1/")
            && err.contains(" to check the credential and the management key…"),
        "{err}"
    );
    assert!(err.contains(" to check the seal of "), "{err}");
    for line in [
        "-byte ID, checked below",
        "Checked with the FIDO2 PIN:\n",
        "  Credential       answers\n",
        "  Management key   matches the card\n",
        "seal OK",
    ] {
        assert!(out.contains(line), "missing {line:?} in:\n{out}");
    }
    assert!(!out.contains("Not checked:"), "{out}");
}

/// Spec 0045: the FIDO2 PIN's state, read without using an attempt; with 3
/// or fewer left it is a warning, and `--no-check` is suggested once it is
/// blocked or the FIDO2 application reset.
fn pq_fsck_fido2_pin_state() {
    let f = PqFixture::new();
    let path = f.file("doc.txt", b"document");
    f.expect(0, &[], &["store", "-u", &path]);
    for _ in 0..5 {
        f.server.replug();
        f.expect(1, &[("YB_PIN", "000000")], &["fetch", "-p", "doc.txt"]);
    }
    f.server.replug();
    let (out, _) = f.expect(0, &[], &["fsck"]);
    assert!(out.contains("warning: set, 3/8 tries left"), "{out}");
    let (out, _) = f.expect(0, &[], &["fsck"]);
    assert!(
        out.contains("warning: set, 3/8 tries left"),
        "an attempt was used:\n{out}"
    );

    // A FIDO2 reset: no PIN; the unencrypted blob stays readable.
    let reset = yb_fido2_emulator::server::Server::start(
        &f.fx.dir.path().join("reset.sock"),
        Some(PQ_SERIAL),
    )
    .unwrap();
    let socket = reset.path.to_str().unwrap().to_owned();
    let (out, _) = f.expect(1, &[("YB_FIDO2_SOCKET", socket.as_str())], &["fsck"]);
    assert!(out.contains("ERROR: not set (FIDO2 reset?)"), "{out}");
    assert!(out.contains("yb fetch --no-check"), "{out}");
}

/// A corrupted blob: `ls` and `fetch` exit 4, before any touch.
fn pq_corruption_exits_4() {
    let f = PqFixture::new();
    let path = f.file("doc.txt", &[0x42; 500]);
    f.expect(0, &[], &["store", "-u", &path]);
    f.corrupt_object(0x5F_0001, 60);
    let before = f.server.touches();
    let (out, _) = f.expect(4, &[], &["ls"]);
    assert!(out.contains("CORRUPTED"), "{out}");
    let (_, err) = f.expect(4, &[], &["fetch", "-p", "doc.txt"]);
    assert!(err.contains("corrupted"), "{err}");
    assert_eq!(f.server.touches(), before, "no touch for a corrupted blob");
}

/// Invariant 0015: after a PIV reset (objects written back with the factory
/// key), fetch and store exit 4 and nothing is written.
fn pq_piv_reset_exits_4() {
    use yb_core::piv::{PivBackend, VirtualPiv};
    let f = PqFixture::new();
    let path = f.file("doc.txt", b"kept");
    f.expect(0, &[], &["store", &path]);

    let piv = VirtualPiv::from_fixture(&f.fx.path()).unwrap();
    let reader = piv.reader_name();
    let saved: Vec<(u32, Vec<u8>)> = (0..=16u32)
        .filter_map(|i| {
            piv.read_object(&reader, 0x5F_0000 + i)
                .ok()
                .map(|r| (0x5F_0000 + i, r))
        })
        .collect();
    piv.reset_piv(&reader).unwrap();
    for (id, raw) in &saved {
        piv.write_object(
            &reader,
            *id,
            raw,
            "010203040506070801020304050607080102030405060708",
        )
        .unwrap();
    }
    piv.save_fixture(&f.fx.path()).unwrap();
    // The card's objects (the write counter is not saved in the fixture).
    let objects = |piv: &VirtualPiv| -> Vec<Option<Vec<u8>>> {
        (0..=32u32)
            .map(|i| piv.read_object(&reader, 0x5F_0000 + i).ok())
            .collect()
    };
    let before = objects(&piv);

    let (_, err) = f.expect(4, &[], &["fetch", "-p", "doc.txt"]);
    assert!(err.contains("management key does not match"), "{err}");
    let new = f.file("new.txt", b"x");
    f.expect(4, &[], &["store", &new]);
    let piv = VirtualPiv::from_fixture(&f.fx.path()).unwrap();
    assert!(objects(&piv) == before, "a store after a PIV reset wrote");
}

fn pq_refused_touch() {
    let f = PqFixture::new();
    let path = f.file("doc.txt", b"data");
    f.server.set_touch(false);
    let (_, err) = f.expect(1, &[], &["store", &path]);
    assert!(err.contains("not touched"), "{err}");
    f.server.set_touch(true);
    let (out, _) = f.expect(0, &[], &["ls"]);
    assert_eq!(out, "", "a refused touch stored something");
}

/// D10: with 3 FIDO2 PIN attempts or fewer left, yb refuses to try the PIN
/// unless --allow-low-pin-attempts (invariant 0017).
fn pq_low_pin_attempts() {
    let f = PqFixture::new();
    let path = f.file("doc.txt", b"data");
    f.expect(0, &[], &["store", "-u", &path]);
    for _ in 0..5 {
        f.server.replug();
        let (_, err) = f.expect(1, &[("YB_PIN", "000000")], &["fetch", "-p", "doc.txt"]);
        assert!(err.contains("wrong FIDO2 PIN"), "{err}");
    }
    f.server.replug();
    let (_, err) = f.expect(1, &[], &["fetch", "-p", "doc.txt"]);
    assert!(err.contains("only 3 FIDO2 PIN attempts left"), "{err}");
    let (out, _) = f.expect(
        0,
        &[],
        &["--allow-low-pin-attempts", "fetch", "-p", "doc.txt"],
    );
    assert_eq!(out, "data");
}

/// Spec 0044: with 3 FIDO2 PIN attempts left, a fetch of unencrypted blobs
/// suggests `--no-check` before any PIN is tried; `--no-check` reads them
/// with no PIN and no touch, refuses encrypted blobs, and still detects
/// corruption (exit 4).
fn pq_no_check() {
    let f = PqFixture::new();
    let public = f.file("pub.txt", b"public");
    let secret = f.file("sec.txt", b"secret");
    f.expect(0, &[], &["store", "-u", &public]);
    f.expect(0, &[], &["store", &secret]);
    for _ in 0..5 {
        f.server.replug();
        f.expect(1, &[("YB_PIN", "000000")], &["fetch", "-p", "pub.txt"]);
    }
    f.server.replug();
    let (_, err) = f.expect(1, &[], &["fetch", "-p", "pub.txt"]);
    assert!(err.contains("only 3 FIDO2 PIN attempts left"), "{err}");
    assert!(err.contains("yb fetch --no-check"), "no hint: {err}");
    // No hint for an encrypted blob: --no-check cannot read it.
    let (_, err) = f.expect(1, &[], &["fetch", "-p", "sec.txt"]);
    assert!(!err.contains("--no-check"), "{err}");

    let touches = f.server.touches();
    let (out, err) = f.expect(0, &[], &["--quiet", "fetch", "--no-check", "-p", "pub.txt"]);
    assert_eq!(out, "public");
    assert!(err.contains("checksum only"), "no warning: {err}");
    assert_eq!(
        f.server.touches(),
        touches,
        "--no-check touched the YubiKey"
    );
    let (_, err) = f.expect(1, &[], &["fetch", "--no-check", "-p", "sec.txt"]);
    assert!(err.contains("is encrypted"), "{err}");

    // The attempts were not used: the right PIN still works.
    let (out, _) = f.expect(
        0,
        &[],
        &["--allow-low-pin-attempts", "fetch", "-p", "pub.txt"],
    );
    assert_eq!(out, "public");

    f.corrupt_object(0x5F_0001, 60);
    f.expect(4, &[], &["fetch", "--no-check", "-p", "pub.txt"]);
}

/// Spec 0044: after a FIDO2 reset (a fresh emulator: no PIN, no
/// credential), unencrypted blobs are still read with `--no-check`.
fn pq_no_check_after_fido2_reset() {
    let f = PqFixture::new();
    let public = f.file("pub.txt", b"public");
    f.expect(0, &[], &["store", "-u", &public]);
    // A new server powers the emulator on afresh: a FIDO2 reset.
    let reset = yb_fido2_emulator::server::Server::start(
        &f.fx.dir.path().join("reset.sock"),
        Some(PQ_SERIAL),
    )
    .unwrap();
    let socket = reset.path.to_str().unwrap().to_owned();
    let env = [("YB_FIDO2_SOCKET", socket.as_str())];
    let (_, err) = f.expect(1, &env, &["fetch", "-p", "pub.txt"]);
    assert!(err.contains("yb fetch --no-check"), "no hint: {err}");
    let (out, _) = f.expect(0, &env, &["fetch", "--no-check", "-p", "pub.txt"]);
    assert_eq!(out, "public");
}

/// Spec 0044 G5: a legacy store reads unencrypted blobs without the PIN (a
/// wrong one is never tried), and `--no-check` refuses encrypted blobs.
fn legacy_unencrypted_fetch_needs_no_pin() {
    let f = Fixture::new();
    f.format();
    f.store_file("pub.txt", b"public");
    let wrong = [("YB_PIN", "000000")];
    let (out, _) = f.ok(&wrong, &["fetch", "-p", "pub.txt"]);
    assert_eq!(out, "public");
    let (out, _) = f.ok(&wrong, &["fetch", "--no-check", "-p", "pub.txt"]);
    assert_eq!(out, "public");
    let (out, _) = f.ok(&[], &["fsck"]);
    assert!(
        out.contains("3/3 tries left"),
        "a PIN attempt was used: {out}"
    );

    let secret = f.dir.path().join("sec.txt");
    std::fs::write(&secret, b"secret").unwrap();
    f.ok(&[], &["store", secret.to_str().unwrap()]);
    let (_, err) = f.err(&[], &["fetch", "--no-check", "-p", "sec.txt"]);
    assert!(err.contains("is encrypted"), "{err}");
}

fn pq_format_flags() {
    let f = PqFixture::bare();
    drop(f.set_fido2_pin());
    let path = f.file("old.txt", b"old");
    let own = [("YB_MANAGEMENT_KEY", OWN_MGMT)];
    f.expect(0, &own, &["format", "-g"]);
    f.expect(0, &own, &["store", "-u", &path]);
    let before = f.server.touches();
    let (_, err) = f.expect(0, &own, &["format", "--post-quantum", "--yes", "-c", "8"]);
    assert!(err.contains("will be destroyed: old.txt"), "{err}");
    assert_eq!(f.server.touches() - before, 2, "format: two touches");
    let (out, _) = f.expect(0, &[], &["fsck"]);
    assert!(out.contains("Store: post-quantum, 8 objects"), "{out}");
    let doc = f.file("doc.txt", b"after format");
    f.expect(0, &[], &["store", &doc]);
    let (out, _) = f.expect(0, &[], &["fetch", "-p", "doc.txt"]);
    assert_eq!(out, "after format");
}

fn pq_format_refusals() {
    let f = PqFixture::bare();
    // The factory management key is refused.
    let factory = [("YB_MANAGEMENT_KEY", MGMT)];
    let (_, err) = f.expect(1, &factory, &["format", "--post-quantum", "--yes"]);
    assert!(err.contains("factory default"), "{err}");
    // No FIDO2 PIN: set one first.
    let own = [("YB_MANAGEMENT_KEY", OWN_MGMT)];
    let (_, err) = f.expect(1, &own, &["format", "--post-quantum", "--yes"]);
    assert!(err.contains("no FIDO2 PIN is set"), "{err}");
    // Legacy options are refused with --post-quantum.
    drop(f.set_fido2_pin());
    let (_, err) = f.expect(1, &own, &["format", "--post-quantum", "-g"]);
    assert!(err.contains("legacy stores"), "{err}");
    // Nothing was written: still no store.
    use yb_core::piv::{PivBackend, VirtualPiv};
    let piv = VirtualPiv::from_fixture(&f.fx.path()).unwrap();
    assert!(
        piv.read_object(&piv.reader_name(), 0x5F_0000).is_err(),
        "a refused format wrote"
    );
}

fn pq_rotate_management_key_refused() {
    let f = PqFixture::new();
    let (_, err) = f.expect(1, &[], &["rotate-management-key"]);
    assert!(err.contains("yb management-key set"), "{err}");
}

/// The user changes the management key with another tool: fetch exits 4
/// until `yb management-key set` (D7, D11).
fn pq_management_key_set() {
    use yb_core::piv::{MgmtAlgo, PivBackend, VirtualPiv};
    const NEW_MGMT: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a6978";
    let f = PqFixture::new();
    let path = f.file("doc.txt", b"kept");
    f.expect(0, &[], &["store", &path]);
    let piv = VirtualPiv::from_fixture(&f.fx.path()).unwrap();
    piv.set_management_key(&piv.reader_name(), OWN_MGMT, NEW_MGMT, MgmtAlgo::Tdes)
        .unwrap();
    piv.save_fixture(&f.fx.path()).unwrap();

    f.expect(4, &[], &["fetch", "-p", "doc.txt"]);
    let (_, err) = f.expect(
        1,
        &[("YB_MANAGEMENT_KEY", MGMT)],
        &["management-key", "set"],
    );
    assert!(err.contains("factory default"), "{err}");
    let (_, err) = f.expect(
        1,
        &[("YB_MANAGEMENT_KEY", OWN_MGMT)],
        &["management-key", "set"],
    );
    assert!(err.contains("rejects"), "{err}");
    f.expect(
        0,
        &[("YB_MANAGEMENT_KEY", NEW_MGMT)],
        &["management-key", "set"],
    );
    let (out, _) = f.expect(0, &[], &["fetch", "-p", "doc.txt"]);
    assert_eq!(out, "kept");
}

/// Scripted answers for the guided format, run in-process.
struct Script {
    answers: std::collections::VecDeque<String>,
    transcript: Vec<String>,
}

impl yb::cli::guided::Prompter for Script {
    fn say(&mut self, text: &str) {
        self.transcript.push(text.to_owned());
    }
    fn ask(&mut self, prompt: &str) -> anyhow::Result<String> {
        self.transcript.push(prompt.to_owned());
        self.answers
            .pop_front()
            .ok_or_else(|| anyhow::anyhow!("no answer for {prompt:?}"))
    }
    fn ask_secret(&mut self, prompt: &str) -> anyhow::Result<String> {
        self.ask(prompt)
    }
}

/// The guided format, post-quantum, in-process: set a FIDO2 PIN, type the
/// management key, default object count, confirm.
fn pq_guided_format() {
    use std::sync::Arc;
    use yb_core::piv::{PivBackend, VirtualPiv};
    let f = PqFixture::bare();
    let piv = Arc::new(VirtualPiv::from_fixture(&f.fx.path()).unwrap());
    std::env::set_var("YB_SKIP_DEFAULT_CHECK", "1");
    let mut ctx = yb_core::Context::with_backend(piv.clone(), None, false).unwrap();
    let mut script = Script {
        answers: ["1", "654321", "654321", OWN_MGMT, "", "y"]
            .iter()
            .map(|a| a.to_string())
            .collect(),
        transcript: Vec::new(),
    };
    let before = f.server.touches();
    yb::cli::guided::run(&mut ctx, &mut script)
        .unwrap_or_else(|e| panic!("{e:#}\n{}", script.transcript.join("\n")));
    assert!(script.answers.is_empty(), "unused answers");
    let text = script.transcript.join("\n");
    assert!(text.contains("post-quantum (recommended)"), "{text}");
    assert!(text.contains("no unblocking code"), "{text}");
    assert_eq!(f.server.touches() - before, 2, "format: two touches");
    piv.save_fixture(&f.fx.path()).unwrap();
    let (out, _) = f.expect(0, &[], &["fsck"]);
    assert!(out.contains("Store: post-quantum, 32 objects"), "{out}");
}

fn main() {
    macro_rules! test {
        ($f:ident) => {
            libtest_mimic::Trial::test(stringify!($f), || {
                $f();
                Ok(())
            })
        };
    }
    let tests = vec![
        test!(format_creates_store),
        test!(pq_store_fetch_one_touch_per_blob),
        test!(pq_remove),
        test!(pq_fsck),
        test!(pq_fsck_fido2_pin_state),
        test!(pq_corruption_exits_4),
        test!(pq_piv_reset_exits_4),
        test!(pq_refused_touch),
        test!(pq_low_pin_attempts),
        test!(pq_no_check),
        test!(pq_no_check_after_fido2_reset),
        test!(legacy_unencrypted_fetch_needs_no_pin),
        test!(pq_format_flags),
        test!(pq_format_refusals),
        test!(pq_rotate_management_key_refused),
        test!(pq_management_key_set),
        test!(pq_guided_format),
        test!(store_and_list),
        test!(store_multiple_files_list),
        test!(store_name_override),
        test!(store_and_fetch_stdout),
        test!(store_and_fetch_to_output_dir),
        test!(fetch_glob_pattern),
        test!(store_encrypted_fetch_with_pin),
        test!(fetch_missing_exits_1),
        test!(fetch_stdout_multi_match_exits_1),
        test!(remove_single_blob),
        test!(remove_glob),
        test!(remove_missing_exits_1),
        test!(remove_ignore_missing),
        test!(fsck_clean_store),
        test!(fsck_verbose),
        test!(list_long_format),
        test!(list_sort_reverse),
        test!(quiet_suppresses_stderr),
        test!(pin_from_env),
        test!(pin_from_stdin),
        test!(deprecated_pin_flag_warns),
        test!(deprecated_key_flag_warns),
        test!(deprecated_extract_flag_warns),
        test!(store_no_name_stdin_exits_1),
        test!(store_duplicate_basename_exits_1),
        test!(completion_script_bash_exits_0),
        test!(completion_script_zsh_exits_0),
        test!(completion_script_fish_exits_0),
        test!(completion_subcommands_listed),
        test!(completion_blob_names_fetch),
        test!(completion_blob_names_prefix_filtered),
        test!(completion_blob_names_list),
        test!(completion_blob_names_remove),
        test!(completion_no_blobs_returns_empty),
        test!(list_readers_with_fixture),
    ];
    libtest_mimic::run(&libtest_mimic::Arguments::from_args(), tests).exit();
}
