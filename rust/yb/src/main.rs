// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

use anyhow::Result;
use clap::{CommandFactory, Parser};
use clap_complete::CompleteEnv;
use yb::cli;
use yb::{Cli, Commands};
use yb_core::{context::OutputOptions, Context};

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
    // list-readers bypasses Context construction (works without a YubiKey).
    if let Commands::ListReaders(args) = cli.command {
        return cli::list_readers::run(&args);
    }

    // Emit deprecation warnings for legacy flags.
    if cli.pin_deprecated.is_some() {
        eprintln!("Warning: --pin is deprecated; use YB_PIN, --pin-stdin, or interactive prompt");
    }
    if cli.key_deprecated.is_some() {
        eprintln!("Warning: --key is deprecated; use YB_MANAGEMENT_KEY");
    }

    let (pin, pin_fn) = make_pin_resolver(cli.pin_stdin, cli.pin_deprecated)?;
    let management_key = resolve_management_key(cli.key_deprecated);

    let ctx = Context::new(
        cli.serial,
        cli.reader,
        management_key,
        pin,
        pin_fn,
        OutputOptions {
            debug: cli.debug,
            quiet: cli.quiet,
        },
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
        #[cfg(feature = "self-test")]
        Commands::SelfTest(args) => cli::self_test::run(&ctx, &args),
    };

    if let Ok(path) = std::env::var("YB_FIXTURE") {
        ctx.piv.save_fixture(std::path::Path::new(&path))?;
    }

    result
}

// ---------------------------------------------------------------------------
// PIN / key resolution
// ---------------------------------------------------------------------------

type PinFn = Box<dyn Fn() -> Result<Option<String>>>;

fn make_pin_resolver(
    pin_stdin: bool,
    pin_deprecated: Option<String>,
) -> Result<(Option<String>, PinFn)> {
    if pin_stdin {
        use std::io::BufRead as _;
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        let pin = line
            .trim_end_matches('\n')
            .trim_end_matches('\r')
            .to_owned();
        return Ok((Some(pin), Box::new(|| Ok(None))));
    }

    if let Some(p) = pin_deprecated {
        return Ok((Some(p), Box::new(|| Ok(None))));
    }

    if let Ok(v) = std::env::var("YB_PIN") {
        if !v.is_empty() {
            return Ok((Some(v), Box::new(|| Ok(None))));
        }
    }

    Ok((
        None,
        Box::new(|| {
            if atty::is(atty::Stream::Stderr) {
                match rpassword::prompt_password("Enter YubiKey PIN: ") {
                    Ok(p) if !p.is_empty() => return Ok(Some(p)),
                    Ok(_) => {}
                    Err(_) => {}
                }
            }
            Ok(None)
        }),
    ))
}

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
