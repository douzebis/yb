// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

use anyhow::{bail, Result};
use clap::Args;
use std::io::{BufRead as _, Write as _};
use std::path::PathBuf;
use std::process::Command;
use yb_core::{
    test_utils::{OpType, OperationGenerator, ToyFilesystem},
    Context,
};

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

struct Executor {
    yb_bin: PathBuf,
    serial: u32,
    pin: String,
    mgmt_key: String,
}

impl Executor {
    fn run(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<(i32, Vec<u8>, String)> {
        let mut cmd = Command::new(&self.yb_bin);
        cmd.args(["--serial", &self.serial.to_string()])
            .env("YB_PIN", &self.pin)
            .env("YB_MANAGEMENT_KEY", &self.mgmt_key)
            .args(args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        if stdin.is_some() {
            cmd.stdin(std::process::Stdio::piped());
        }
        let mut child = cmd.spawn()?;
        if let Some(data) = stdin {
            child.stdin.as_mut().unwrap().write_all(data)?;
        }
        let out = child.wait_with_output()?;
        let code = out.status.code().unwrap_or(1);
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        Ok((code, out.stdout, stderr))
    }

    fn store(&self, name: &str, payload: &[u8], encrypted: bool) -> Result<StoreResult> {
        let enc_flag = if encrypted {
            "--encrypted"
        } else {
            "--unencrypted"
        };
        let (code, _, stderr) = self.run(&["store", enc_flag, "--name", name], Some(payload))?;
        if code == 0 {
            return Ok(StoreResult::Ok);
        }
        if stderr.to_lowercase().contains("store is full") {
            return Ok(StoreResult::Full);
        }
        Ok(StoreResult::Err(format!("exit {code}: {}", stderr.trim())))
    }

    fn fetch(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let (code, stdout, _) = self.run(&["fetch", "--stdout", name], None)?;
        if code == 0 {
            Ok(Some(stdout))
        } else {
            Ok(None)
        }
    }

    fn remove(&self, name: &str) -> Result<bool> {
        let (code, _, _) = self.run(&["rm", name], None)?;
        Ok(code == 0)
    }

    fn list(&self) -> Result<Vec<String>> {
        let (code, stdout, _) = self.run(&["ls"], None)?;
        if code != 0 {
            bail!("yb ls failed");
        }
        let names = String::from_utf8_lossy(&stdout)
            .lines()
            .map(|l| l.trim().to_owned())
            .filter(|l| !l.is_empty())
            .collect();
        Ok(names)
    }
}

enum StoreResult {
    Ok,
    Full,
    Err(String),
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub fn run(ctx: &Context, args: &SelfTestArgs) -> Result<()> {
    let serial = ctx.serial;
    let version = {
        let devices = ctx.piv.list_devices()?;
        devices
            .iter()
            .find(|d| d.serial == serial)
            .map(|d| d.version.clone())
            .unwrap_or_else(|| "unknown".to_owned())
    };

    // Confirmation prompt — flash the LED at 5 Hz while waiting for 'yes'.
    print_warning(serial, &version, args.count);

    let _flash = if !args.no_flash {
        eprintln!("YubiKey LED is flashing to help you identify the correct device.");
        eprintln!();
        // 5 Hz (200 ms) — conveys urgency during destructive operation prompt.
        let reader = ctx
            .piv
            .list_devices()?
            .into_iter()
            .find(|d| d.serial == serial)
            .map(|d| d.reader)
            .unwrap_or_default();
        Some(ctx.piv.start_flash(&reader, 200))
    } else {
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

    // Resolve credentials.
    let pin = ctx
        .require_pin()?
        .ok_or_else(|| anyhow::anyhow!("PIN is required for self-test"))?;

    let mgmt_key = ctx.management_key_for_write()?.unwrap_or_else(|| {
        // Default YubiKey management key.
        "010203040506070801020304050607080102030405060708".to_owned()
    });

    // Format via subprocess so key generation happens through the full CLI stack.
    eprintln!("Formatting YubiKey (serial={serial})...");
    let format_start = std::time::Instant::now();
    {
        let yb_bin = std::env::current_exe()?;
        let status = Command::new(&yb_bin)
            .args(["--serial", &serial.to_string()])
            .env("YB_PIN", &pin)
            .env("YB_MANAGEMENT_KEY", &mgmt_key)
            .args(["format", "--generate", "--object-count", "16"])
            .status()?;
        if !status.success() {
            bail!("format failed");
        }
    }
    eprintln!(
        "Format complete ({:.1}s).",
        format_start.elapsed().as_secs_f64()
    );
    eprintln!();

    // Run operations.
    let yb_bin = std::env::current_exe()?;
    let executor = Executor {
        yb_bin,
        serial,
        pin,
        mgmt_key,
    };
    let mut toy = ToyFilesystem::new();
    let mut gen = OperationGenerator::new(args.seed, 15);
    let ops = gen.generate(args.count, 0.5);

    let mut stats = Stats::default();
    let run_start = std::time::Instant::now();
    let mut completed = 0usize;

    eprintln!("Running {} operations (seed={})...", args.count, args.seed);
    eprintln!();

    'ops: for (i, op) in ops.iter().enumerate() {
        let remaining = args.count - (i + 1);
        let desc = match op.op_type {
            OpType::Store => format!("STORE({})", op.name),
            OpType::Fetch => format!("FETCH({})", op.name),
            OpType::Remove => format!("REMOVE({})", op.name),
            OpType::List => "LIST".to_owned(),
        };
        eprint!(
            "[{:3}/{}, {:3} remaining]  {:30}... ",
            i + 1,
            args.count,
            remaining,
            desc
        );
        std::io::stderr().flush()?;

        let (ok, msg) = match op.op_type {
            OpType::Store => {
                let prev = toy.fetch(&op.name).map(|(p, m)| (p.clone(), *m));
                let was_present = prev.is_some();
                toy.store(&op.name, op.payload.clone(), 0);

                match executor.store(&op.name, &op.payload, op.encrypted)? {
                    StoreResult::Ok => (true, String::new()),
                    StoreResult::Full => {
                        // Roll back toy update.
                        if let Some((old_payload, old_mtime)) = prev {
                            toy.store(&op.name, old_payload, old_mtime);
                        } else if !was_present {
                            toy.remove(&op.name);
                        }
                        (true, String::new())
                    }
                    StoreResult::Err(e) => {
                        // Roll back.
                        if let Some((old_payload, old_mtime)) = prev {
                            toy.store(&op.name, old_payload, old_mtime);
                        } else if !was_present {
                            toy.remove(&op.name);
                        }
                        (false, format!("Op #{} STORE({}): {}", i + 1, op.name, e))
                    }
                }
            }
            OpType::Fetch => {
                let result = executor.fetch(&op.name)?;
                let expected = toy.fetch(&op.name).map(|(p, _)| p.as_slice());
                if result.as_deref() == expected {
                    (true, String::new())
                } else {
                    let got = result
                        .as_ref()
                        .map(|v| v.len())
                        .map(|n| format!("{n} bytes"))
                        .unwrap_or_else(|| "None".to_owned());
                    let exp = expected
                        .map(|p| format!("{} bytes", p.len()))
                        .unwrap_or_else(|| "None".to_owned());
                    (
                        false,
                        format!(
                            "Op #{} FETCH({}): expected {exp}, got {got}",
                            i + 1,
                            op.name
                        ),
                    )
                }
            }
            OpType::Remove => {
                let removed = executor.remove(&op.name)?;
                let expected = toy.remove(&op.name);
                if removed == expected {
                    (true, String::new())
                } else {
                    (
                        false,
                        format!(
                            "Op #{} REMOVE({}): expected {expected}, got {removed}",
                            i + 1,
                            op.name
                        ),
                    )
                }
            }
            OpType::List => {
                let mut actual = executor.list()?;
                let expected = toy.list();
                actual.sort();
                if actual == expected {
                    (true, String::new())
                } else {
                    (
                        false,
                        format!("Op #{} LIST: expected {expected:?}, got {actual:?}", i + 1),
                    )
                }
            }
        };

        stats.record(&op.op_type, ok, &msg);
        completed += 1;

        if ok {
            eprintln!("OK");
        } else {
            eprintln!("FAIL");
            eprintln!("  Error: {msg}");
            eprintln!();
            eprintln!(
                "Stopping at operation {}/{}.  State preserved.",
                i + 1,
                args.count
            );
            eprintln!("Run 'yb --serial {serial} fsck -v' to inspect.");
            break 'ops;
        }
    }

    let duration = run_start.elapsed().as_secs_f64();

    // Cleanup on success.
    if stats.all_passed() && !args.no_cleanup {
        eprintln!();
        eprintln!("Cleaning up...");
        let names = executor.list()?;
        for name in &names {
            executor.remove(name)?;
        }
        eprintln!("Store emptied.");
    } else if !stats.all_passed() {
        eprintln!();
        eprintln!("NOTE: YubiKey state preserved for debugging.");
        eprintln!("      Run 'yb --serial {serial} ls' to inspect.");
    }

    // Report.
    eprintln!();
    print_report(&stats, serial, &version, args, completed, duration);

    if !stats.all_passed() {
        std::process::exit(1);
    }
    Ok(())
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
    eprintln!("  1. FORMAT the YubiKey  (destroys all existing blob data)");
    eprintln!("  2. Run {count} store/fetch/remove/list operations");
    eprintln!("  3. Stop on the first error");
    eprintln!();
    eprintln!("ALL EXISTING BLOB DATA WILL BE PERMANENTLY LOST.");
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
