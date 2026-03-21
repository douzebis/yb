// SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{engine::ArgValueCompleter, CompleteEnv};
use yb::cli;
use yb::complete::complete_serials;
use yb_core::Context;

// ---------------------------------------------------------------------------
// Top-level CLI definition
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(name = "yb", about = "Secure blob storage on a YubiKey", version)]
struct Cli {
    /// YubiKey serial number.
    #[arg(short = 's', long = "serial", add = ArgValueCompleter::new(complete_serials))]
    serial: Option<u32>,

    /// PC/SC reader name (legacy; prefer --serial).
    #[arg(short = 'r', long = "reader")]
    reader: Option<String>,

    /// Suppress informational output.
    #[arg(short = 'q', long = "quiet")]
    quiet: bool,

    /// Read PIN from stdin (one line).
    #[arg(long = "pin-stdin")]
    pin_stdin: bool,

    /// Enable debug output.
    #[arg(long = "debug")]
    debug: bool,

    /// Allow insecure default credentials (not recommended).
    #[arg(long = "allow-defaults")]
    allow_defaults: bool,

    /// YubiKey PIN [deprecated: use YB_PIN, --pin-stdin, or interactive prompt].
    #[arg(long = "pin", hide = true)]
    pin_deprecated: Option<String>,

    /// Management key [deprecated: use YB_MANAGEMENT_KEY].
    #[arg(short = 'k', long = "key", hide = true)]
    key_deprecated: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Provision PIV objects and optionally generate an ECDH key.
    Format(cli::format::FormatArgs),
    /// Store a blob on the YubiKey.
    Store(cli::store::StoreArgs),
    /// Retrieve one or more blobs.
    Fetch(cli::fetch::FetchArgs),
    /// List blobs (alias: ls).
    #[command(alias = "ls")]
    List(cli::list::ListArgs),
    /// Remove a blob (alias: rm).
    #[command(alias = "rm")]
    Remove(cli::remove::RemoveArgs),
    /// Filesystem check — dump store metadata.
    Fsck(cli::fsck::FsckArgs),
    /// List PC/SC readers.
    ListReaders(cli::list_readers::ListReadersArgs),
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    CompleteEnv::with_factory(Cli::command)
        .var("YB_COMPLETE")
        .complete();

    let cli = Cli::parse();

    let result = run(cli);
    if let Err(e) = result {
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    // S7: list-readers bypasses Context construction (works without a YubiKey).
    if let Commands::ListReaders(args) = cli.command {
        return cli::list_readers::run(&args);
    }

    // S1: Emit deprecation warnings for legacy flags.
    if cli.pin_deprecated.is_some() {
        eprintln!("Warning: --pin is deprecated; use YB_PIN, --pin-stdin, or interactive prompt");
    }
    if cli.key_deprecated.is_some() {
        eprintln!("Warning: --key is deprecated; use YB_MANAGEMENT_KEY");
    }

    // S1: Resolve PIN — priority: --pin-stdin > --pin (deprecated) > YB_PIN > TTY prompt > None.
    let pin = resolve_pin(cli.pin_stdin, cli.pin_deprecated)?;

    // S1: Resolve management key — priority: --key (deprecated) > YB_MANAGEMENT_KEY > None.
    let management_key = resolve_management_key(cli.key_deprecated);

    let ctx = Context::new(
        cli.serial,
        cli.reader,
        management_key,
        pin,
        cli.debug,
        cli.quiet,
        cli.allow_defaults,
    )?;

    let result = match cli.command {
        Commands::Format(args) => cli::format::run(&ctx, &args),
        Commands::Store(args) => cli::store::run(&ctx, &args),
        Commands::Fetch(args) => cli::fetch::run(&ctx, &args),
        Commands::List(args) => cli::list::run(&ctx, &args),
        Commands::Remove(args) => cli::remove::run(&ctx, &args),
        Commands::Fsck(args) => cli::fsck::run(&ctx, &args),
        Commands::ListReaders(_) => unreachable!("handled above"),
    };

    // When running under YB_FIXTURE (subprocess tests), persist any mutations
    // (key generation, object writes) back to the fixture file so the next
    // subprocess invocation starts from the updated state.
    if let Ok(path) = std::env::var("YB_FIXTURE") {
        ctx.piv.save_fixture(std::path::Path::new(&path))?;
    }

    result
}

// ---------------------------------------------------------------------------
// PIN / key resolution (S1)
// ---------------------------------------------------------------------------

/// Resolve the PIN from explicit flags, env var, or TTY prompt.
fn resolve_pin(pin_stdin: bool, pin_deprecated: Option<String>) -> Result<Option<String>> {
    // 1. --pin-stdin: read one line from stdin.
    if pin_stdin {
        use std::io::BufRead as _;
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        let pin = line
            .trim_end_matches('\n')
            .trim_end_matches('\r')
            .to_owned();
        return Ok(Some(pin));
    }

    // 2. --pin (deprecated).
    if let Some(p) = pin_deprecated {
        return Ok(Some(p));
    }

    // 3. YB_PIN environment variable.
    if let Ok(v) = std::env::var("YB_PIN") {
        if !v.is_empty() {
            return Ok(Some(v));
        }
    }

    // 4. Interactive TTY prompt (only when stderr is a TTY).
    if atty::is(atty::Stream::Stderr) {
        match rpassword::prompt_password("Enter YubiKey PIN: ") {
            Ok(pin) if !pin.is_empty() => return Ok(Some(pin)),
            Ok(_) => {}  // empty → treat as not provided
            Err(_) => {} // no TTY available or other error → skip
        }
    }

    // 5. No PIN available — operations that need it will fail with a clear message.
    Ok(None)
}

/// Resolve the management key from deprecated flag or env var.
fn resolve_management_key(key_deprecated: Option<String>) -> Option<String> {
    if let Some(k) = key_deprecated {
        return Some(k);
    }
    if let Ok(v) = std::env::var("YB_MANAGEMENT_KEY") {
        if !v.is_empty() {
            return Some(v);
        }
    }
    None
}
