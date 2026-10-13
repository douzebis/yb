// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

use anyhow::{anyhow, bail, Result};
use clap::Args;
use std::io::{BufRead as _, Read as _, Write as _};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use yb_core::{
    auxiliaries::read_printed_keys,
    piv::{PinRef, PivBackend},
    store::Store,
    test_utils::{OpType, Operation, OperationGenerator, ToyFilesystem},
    Context,
};

use crate::cli::store::objects_for;
use crate::cli::util::ExitStatus;

#[derive(Args, Debug)]
pub struct SelfTestArgs {
    /// Number of store/fetch/remove/list operations to run.
    #[arg(long = "count", default_value_t = 200)]
    pub count: usize,

    /// RNG seed for reproducible operation sequences.
    #[arg(long = "seed", default_value_t = 42)]
    pub seed: u64,

    /// Keep blobs after a successful test (skip cleanup).
    #[arg(long = "no-cleanup")]
    pub no_cleanup: bool,

    /// Suppress LED flashing during confirmation prompt.
    #[arg(long = "no-flash")]
    pub no_flash: bool,
}

// ---------------------------------------------------------------------------
// Per-operation statistics
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Stats {
    store: (usize, usize), // (total, passed)
    fetch: (usize, usize),
    remove: (usize, usize),
    list: (usize, usize),
    failures: Vec<String>,
}

impl Stats {
    fn record(&mut self, op: &OpType, ok: bool, msg: &str) {
        let slot = match op {
            OpType::Store => &mut self.store,
            OpType::Fetch => &mut self.fetch,
            OpType::Remove => &mut self.remove,
            OpType::List => &mut self.list,
        };
        slot.0 += 1;
        if ok {
            slot.1 += 1;
        } else {
            self.failures.push(msg.to_owned());
        }
    }

    fn total(&self) -> usize {
        self.store.0 + self.fetch.0 + self.remove.0 + self.list.0
    }

    fn passed(&self) -> usize {
        self.store.1 + self.fetch.1 + self.remove.1 + self.list.1
    }

    fn all_passed(&self) -> bool {
        self.failures.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Subprocess executor
// ---------------------------------------------------------------------------

/// What a `yb` child process returned.
struct Output {
    code: i32,
    stdout: Vec<u8>,
    stderr: String,
}

impl Output {
    fn describe(&self) -> String {
        format!("exit status {}: {}", self.code, self.stderr.trim())
    }
}

/// Runs `yb` as a user would, on the selected YubiKey, with the self-test's
/// PIN.  On a simulated YubiKey (`YB_FIXTURE`), which parent and children
/// share through its file, the parent's view is saved before each child
/// and reloaded after it.
struct Executor<'a> {
    yb_bin: PathBuf,
    serial: u32,
    piv: &'a dyn PivBackend,
    fixture: Option<PathBuf>,
}

impl Executor<'_> {
    fn run(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<Output> {
        if let Some(path) = &self.fixture {
            self.piv.save_fixture(path)?;
        }
        let output = self.spawn(args, stdin);
        if let Some(path) = &self.fixture {
            self.piv.load_fixture(path)?;
        }
        output
    }

    fn spawn(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<Output> {
        let mut child = Command::new(&self.yb_bin)
            .args(["--serial", &self.serial.to_string()])
            .args(args)
            .env("YB_PIN", PIN)
            .env_remove("YB_MANAGEMENT_KEY")
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        // Feed stdin and drain the pipes from threads, so that no pipe
        // fills up while the parent waits.
        let writer = child.stdin.take().map(|mut pipe| {
            let data = stdin.unwrap_or_default().to_vec();
            std::thread::spawn(move || pipe.write_all(&data))
        });
        let mut out_pipe = child.stdout.take().expect("piped stdout");
        let mut err_pipe = child.stderr.take().expect("piped stderr");
        let out_reader = std::thread::spawn(move || {
            let mut buf = Vec::new();
            out_pipe.read_to_end(&mut buf).map(|_| buf)
        });
        let err_reader = std::thread::spawn(move || {
            let mut buf = Vec::new();
            err_pipe.read_to_end(&mut buf).map(|_| buf)
        });

        let deadline = Instant::now() + CHILD_TIMEOUT;
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                bail!(
                    "`yb {}` did not finish within {} s",
                    args.join(" "),
                    CHILD_TIMEOUT.as_secs()
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        if let Some(writer) = writer {
            // A child that exits without reading its input is not an error
            // here; its exit status says what happened.
            let _ = writer.join();
        }
        let stdout = out_reader.join().expect("stdout reader")?;
        let stderr = err_reader.join().expect("stderr reader")?;
        Ok(Output {
            code: status.code().unwrap_or(-1),
            stdout,
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        })
    }

    /// A set-up step that must succeed.
    fn run_checked(&self, args: &[&str]) -> Result<()> {
        let out = self.run(args, None)?;
        if out.code != 0 {
            bail!("`yb {}` failed, {}", args.join(" "), out.describe());
        }
        Ok(())
    }

    /// `Ok(false)`: `yb` reported the store full (exit status 3).
    fn store(&self, name: &str, payload: &[u8], encrypted: bool) -> Result<bool> {
        let enc_flag = if encrypted {
            "--encrypted"
        } else {
            "--unencrypted"
        };
        let out = self.run(&["store", enc_flag, "--name", name], Some(payload))?;
        match out.code {
            0 => Ok(true),
            c if c == ExitStatus::StoreFull as i32 => Ok(false),
            _ => bail!("{}", out.describe()),
        }
    }

    /// `Ok(None)`: `yb` reported the blob not found (exit status 2).
    fn fetch(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let out = self.run(&["fetch", "--stdout", name], None)?;
        match out.code {
            0 => Ok(Some(out.stdout)),
            c if c == ExitStatus::NotFound as i32 => Ok(None),
            _ => bail!("{}", out.describe()),
        }
    }

    /// `Ok(false)`: `yb` reported the blob not found (exit status 2).
    fn remove(&self, name: &str) -> Result<bool> {
        let out = self.run(&["rm", name], None)?;
        match out.code {
            0 => Ok(true),
            c if c == ExitStatus::NotFound as i32 => Ok(false),
            _ => bail!("{}", out.describe()),
        }
    }

    fn list(&self) -> Result<Vec<String>> {
        let out = self.run(&["ls"], None)?;
        if out.code != 0 {
            bail!("{}", out.describe());
        }
        let names = String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|l| l.trim().to_owned())
            .filter(|l| !l.is_empty())
            .collect();
        Ok(names)
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// The credentials the self-test sets after the reset (spec 0032 G6).
const PIN: &str = "654321";
const PUK: &str = "87654321";
const FACTORY_PIN: &str = "123456";
const FACTORY_PUK: &str = "12345678";

const OBJECT_COUNT: &str = "20";
const CHILD_TIMEOUT: Duration = Duration::from_secs(30);

pub fn run(ctx: &mut Context, args: &SelfTestArgs) -> Result<()> {
    let serial = ctx.serial;
    let version = ctx.firmware.clone();
    let quiet = ctx.quiet;
    let say = |line: &str| {
        if !quiet {
            eprintln!("{line}");
        }
    };

    // Confirmation prompt — flash the LED at 5 Hz while waiting for 'yes'.
    print_warning(serial, &version, args.count);

    let _flash: Option<Box<dyn yb_core::piv::FlashHandle>> = if !args.no_flash {
        eprintln!("YubiKey LED is flashing to help you identify the correct device.");
        eprintln!();
        // Reuse the flash handle from the picker if available so the LED
        // continues without a gap; otherwise start a fresh flash.
        let existing = ctx.take_flash();
        if existing.is_some() {
            existing
        } else {
            Some(ctx.piv.start_flash(&ctx.reader, 100, 100))
        }
    } else {
        drop(ctx.take_flash()); // stop picker flash if --no-flash
        None
    };

    eprint!("Type 'yes' to proceed: ");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    drop(_flash); // stop flashing once user responds
    if line.trim() != "yes" {
        eprintln!("Self-test cancelled.");
        std::process::exit(1);
    }
    eprintln!();

    // Every card operation below acts on the selected YubiKey only (G1).
    let (reader, piv) = (ctx.reader.as_str(), ctx.piv.as_ref());
    let executor = Executor {
        yb_bin: std::env::current_exe()?,
        serial,
        piv,
        fixture: std::env::var_os("YB_FIXTURE").map(PathBuf::from),
    };
    // NVM measurements need a real YubiKey's memory.
    let measure_nvm = executor.fixture.is_none();

    // Start from a reset, relying on no existing credential (G6), then set
    // up the configuration users run: own PIN and PUK, management key kept
    // on the YubiKey, unlocked by the PIN.
    say("Resetting the PIV application...");
    piv.reset_piv(reader)?;
    piv.change_reference(reader, PinRef::Pin, FACTORY_PIN, PIN)?;
    piv.change_reference(reader, PinRef::Puk, FACTORY_PUK, PUK)?;
    say(&format!("PIN set to {PIN}, PUK to {PUK}."));
    executor.run_checked(&["--quiet", "rotate-management-key"])?;
    say("Management key kept on the YubiKey, unlocked by the PIN.");

    // Format through `yb`, so that it is tested too.
    say(&format!("Formatting YubiKey (serial={serial})..."));
    let format_start = Instant::now();
    executor.run_checked(&[
        "--quiet",
        "format",
        "--generate",
        "--object-count",
        OBJECT_COUNT,
    ])?;
    say(&format!(
        "Format complete ({:.1}s).",
        format_start.elapsed().as_secs_f64()
    ));
    say("");

    let mgmt_key = read_printed_keys(reader, piv, PIN)?
        .current
        .ok_or_else(|| anyhow!("the management key is not kept on the YubiKey"))?;

    let measure = |when: &str| -> Result<Option<usize>> {
        if !measure_nvm {
            return Ok(None);
        }
        say(&format!("Measuring free NVM {when}..."));
        let free = yb_core::nvm::measure_free_nvm(reader, &mgmt_key, !quiet)?;
        say(&format!("Free NVM {when}: {free} bytes."));
        say("");
        Ok(Some(free))
    };
    let free_after_format = measure("after format (baseline)")?;

    // Run operations.  The generator's capacity is the store's object count:
    // beyond it, stores are refused as full, and checked (G4).
    let capacity = Store::from_device(reader, piv)?.object_count as usize;
    let mut toy = ToyFilesystem::new();
    let mut gen = OperationGenerator::new(args.seed, capacity);
    let ops = gen.generate(args.count, 0.5);

    let mut stats = Stats::default();
    let run_start = Instant::now();
    let mut completed = 0usize;

    say(&format!(
        "Running {} operations (seed={})...",
        args.count, args.seed
    ));
    say("");

    for (i, op) in ops.iter().enumerate() {
        let remaining = args.count - (i + 1);
        let desc = match op.op_type {
            OpType::Store => format!("STORE({})", op.name),
            OpType::Fetch => format!("FETCH({})", op.name),
            OpType::Remove => format!("REMOVE({})", op.name),
            OpType::List => "LIST".to_owned(),
        };
        if !quiet {
            eprint!(
                "[{:3}/{}, {:3} remaining]  {:30}... ",
                i + 1,
                args.count,
                remaining,
                desc
            );
            std::io::stderr().flush()?;
        }

        let result = run_op(&executor, &mut toy, op, reader, piv);
        let (ok, msg) = match result {
            Ok(Verdict::Pass) => (true, String::new()),
            Ok(Verdict::Full { needed, free }) => {
                if !quiet {
                    eprint!("FULL (needs {needed} object(s), {free} free) ");
                }
                (true, String::new())
            }
            Ok(Verdict::Mismatch(m)) => (false, format!("Op #{} {desc}: {m}", i + 1)),
            Err(e) => (false, format!("Op #{} {desc}: {e:#}", i + 1)),
        };

        stats.record(&op.op_type, ok, &msg);
        completed += 1;

        if ok {
            if !quiet {
                eprintln!("OK");
            }
        } else {
            if !quiet {
                eprintln!("FAIL");
            }
            eprintln!("  Error: {msg}");
            eprintln!();
            eprintln!(
                "Stopping at operation {}/{}.  State preserved.",
                i + 1,
                args.count
            );
            break;
        }
    }

    let duration = run_start.elapsed().as_secs_f64();

    // Clean up on success: remove every blob, measure the memory given
    // back, then reset the PIV application again.
    if stats.all_passed() && !args.no_cleanup {
        measure("after ops")?;
        say("Cleaning up...");
        for name in executor.list()? {
            executor.remove(&name)?;
        }
        say("Store emptied.");
        say("");
        if let (Some(after), Some(baseline)) = (measure("after cleanup")?, free_after_format) {
            say(&format!(
                "NVM delta (cleanup − format): {:+} bytes.",
                after as isize - baseline as isize
            ));
            say("");
        }
        say("Resetting the PIV application...");
        piv.reset_piv(reader)?;
        if let Some(path) = &executor.fixture {
            piv.save_fixture(path)?;
        }
        say("PIV application reset to its factory state.");
    } else {
        eprintln!();
        eprintln!("NOTE: YubiKey state preserved (PIN {PIN}, PUK {PUK}).");
        eprintln!("      Run 'yb --serial {serial} fsck' or 'yb --serial {serial} ls' to inspect.");
    }

    // Report.
    eprintln!();
    print_report(&stats, serial, &version, args, completed, duration);

    if !stats.all_passed() {
        std::process::exit(1);
    }
    Ok(())
}

/// The outcome of one operation, compared with the model.
enum Verdict {
    Pass,
    /// `yb` reported the store full, and it was (G4).
    Full {
        needed: usize,
        free: usize,
    },
    /// `yb` and the model disagree.
    Mismatch(String),
}

/// Run one operation and compare its outcome with the model.  An error is
/// any outcome other than the expected ones (G3).
fn run_op(
    executor: &Executor,
    toy: &mut ToyFilesystem,
    op: &Operation,
    reader: &str,
    piv: &dyn PivBackend,
) -> Result<Verdict> {
    match op.op_type {
        OpType::Store => {
            if executor.store(&op.name, &op.payload, op.encrypted)? {
                toy.store(&op.name, op.payload.clone(), 0);
                return Ok(Verdict::Pass);
            }
            // "Store full" only if it was: checked against the store as
            // read here, with the same count as `yb store` (G4).
            let mut store = Store::from_device(reader, piv)?;
            store.sanitize();
            let needed = objects_for(&store, &op.name, op.payload.len(), op.encrypted);
            let free = store.free_count();
            if needed > free {
                Ok(Verdict::Full { needed, free })
            } else {
                Ok(Verdict::Mismatch(format!(
                    "yb reported the store full, but the blob needs {needed} object(s) \
                     and {free} are free"
                )))
            }
        }
        OpType::Fetch => {
            let got = executor.fetch(&op.name)?;
            let expected = toy.fetch(&op.name).map(|(p, _)| p.as_slice());
            if got.as_deref() == expected {
                return Ok(Verdict::Pass);
            }
            let size = |p: Option<&[u8]>| {
                p.map_or("not found".to_owned(), |p| format!("{} bytes", p.len()))
            };
            Ok(Verdict::Mismatch(format!(
                "expected {}, got {}",
                size(expected),
                size(got.as_deref())
            )))
        }
        OpType::Remove => {
            let removed = executor.remove(&op.name)?;
            let expected = toy.remove(&op.name);
            if removed == expected {
                return Ok(Verdict::Pass);
            }
            Ok(Verdict::Mismatch(format!(
                "expected removed={expected}, got removed={removed}"
            )))
        }
        OpType::List => {
            let mut actual = executor.list()?;
            let expected = toy.list();
            actual.sort();
            if actual == expected {
                return Ok(Verdict::Pass);
            }
            Ok(Verdict::Mismatch(format!(
                "expected {expected:?}, got {actual:?}"
            )))
        }
    }
}

fn print_warning(serial: u32, version: &str, count: usize) {
    let bar = "═".repeat(70);
    eprintln!("{bar}");
    eprintln!("WARNING: DESTRUCTIVE OPERATION");
    eprintln!("{bar}");
    eprintln!();
    eprintln!("YubiKey to test:");
    eprintln!("  Serial:  {serial}");
    eprintln!("  Version: {version}");
    eprintln!();
    eprintln!("This self-test will:");
    eprintln!("  1. RESET the YubiKey's PIV application");
    eprintln!("  2. Set PIN {PIN}, PUK {PUK}, a management key kept on the");
    eprintln!("     YubiKey, and format a store");
    eprintln!("  3. Run {count} store/fetch/remove/list operations, stopping on");
    eprintln!("     the first error (the YubiKey is then left as it is)");
    eprintln!("  4. On success, reset the PIV application again");
    eprintln!();
    eprintln!("ALL PIV DATA WILL BE PERMANENTLY LOST: every key and certificate");
    eprintln!("(e.g. SSH or signing keys in slots 9a, 9c), not only yb's store.");
    eprintln!("OTP, FIDO2 and OATH are not affected.");
    eprintln!();
}

fn print_report(
    stats: &Stats,
    serial: u32,
    version: &str,
    args: &SelfTestArgs,
    completed: usize,
    duration: f64,
) {
    let bar = "═".repeat(70);
    eprintln!("{bar}");
    eprintln!("YB SELF-TEST REPORT");
    eprintln!("{bar}");
    eprintln!();
    eprintln!("Device:   serial={serial}  version={version}");
    eprintln!("Seed:     {}", args.seed);
    eprintln!("Count:    {} requested, {completed} completed", args.count);
    eprintln!("Duration: {duration:.1}s");
    eprintln!();
    eprintln!("Results:");
    let rows = [
        ("STORE", stats.store),
        ("FETCH", stats.fetch),
        ("REMOVE", stats.remove),
        ("LIST", stats.list),
    ];
    for (name, (total, passed)) in &rows {
        if *total > 0 {
            eprintln!(
                "  {name:<8} {total:3} ops   {passed:3} passed   {:3} failed",
                total - passed
            );
        }
    }
    let div = "─".repeat(42);
    eprintln!("  {div}");
    eprintln!(
        "  TOTAL    {:3} ops   {:3} passed   {:3} failed",
        stats.total(),
        stats.passed(),
        stats.total() - stats.passed()
    );
    eprintln!();
    if stats.all_passed() {
        eprintln!("Result: ALL TESTS PASSED");
    } else {
        eprintln!("Result: TESTS FAILED");
        if !stats.failures.is_empty() {
            eprintln!();
            eprintln!("Failed operations:");
            for (i, f) in stats.failures.iter().take(10).enumerate() {
                eprintln!("  {}. {f}", i + 1);
            }
            if stats.failures.len() > 10 {
                eprintln!("  ... and {} more", stats.failures.len() - 10);
            }
        }
    }
    eprintln!("{bar}");
}
