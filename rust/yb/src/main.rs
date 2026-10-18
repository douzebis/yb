// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

use anyhow::Result;
use clap::{CommandFactory, Parser};
use clap_complete::CompleteEnv;
use std::sync::{Arc, OnceLock};
use yb::cli;
use yb::{Cli, Commands};
use yb_core::{
    context::OutputOptions,
    errors::{render, RenderEnv},
    Context, ContextOptions, DeviceInfo, DevicePicker, PivBackend, Zeroizing,
};

/// Firmware of the selected YubiKey, once known.  Only the report for
/// unexpected errors shows it (spec 0025 §2).
static FIRMWARE: OnceLock<String> = OnceLock::new();

fn main() {
    // Bash from the raw command line, no `COMP_WORDS` splitting (spec 0036).
    CompleteEnv::with_factory(Cli::command)
        .var("YB_COMPLETE")
        .shells(clap_complete_rawline::shells())
        .complete();

    let cli = Cli::parse();
    // Another program holding the YubiKey makes yb wait (spec 0048).
    if !cli.quiet {
        yb_core::piv::set_wait_notice(|| {
            eprintln!("yb: waiting for another program using the YubiKey…");
        });
    }

    let result = run(cli);
    if let Err(e) = result {
        // The guided flow already said that nothing was changed.
        if e.downcast_ref::<cli::guided::Cancelled>().is_some() {
            std::process::exit(1);
        }
        let env = RenderEnv {
            firmware: FIRMWARE.get().cloned(),
            yb_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
        };
        eprintln!("{}", render(&e, &env));
        std::process::exit(cli::util::exit_status(&e));
    }
}

fn run(cli: Cli) -> Result<()> {
    // Commands that bypass Context construction.
    if let Commands::ListReaders(args) = cli.command {
        return cli::list_readers::run(&args);
    }
    if let Commands::Select(args) = cli.command {
        return cli::select::run(&args);
    }

    // Removed in 0.7, as 0.5 and 0.6 announced: a secret on the command line
    // is visible to other users.  Refused, naming the replacement.
    if cli.pin_removed.is_some() {
        anyhow::bail!(
            "--pin was removed in yb 0.7 (a PIN on the command line is visible to other users): \
             use YB_PIN, --pin-stdin, or the prompt"
        );
    }
    if cli.key_removed.is_some() {
        anyhow::bail!(
            "--key was removed in yb 0.7 (a key on the command line is visible to other users): \
             use YB_MANAGEMENT_KEY, or keep the key on the YubiKey (yb rotate-management-key)"
        );
    }

    let (pin, pin_fn) = make_pin_resolver(cli.pin_stdin)?;
    let management_key = resolve_management_key();
    let device_picker = make_device_picker();

    let ctx = Context::new(
        ContextOptions {
            serial: cli.serial,
            reader: cli.reader,
            management_key,
            pin,
            allow_defaults: cli.allow_defaults,
        },
        pin_fn,
        device_picker,
        OutputOptions {
            debug: cli.debug,
            quiet: cli.quiet,
        },
    )?;

    let _ = FIRMWARE.set(ctx.firmware.clone());

    let mut ctx = ctx;
    // Post-quantum stores (spec 0028): the FIDO2 PIN's own prompt, the
    // touch message, the attempts flag.
    ctx.fido2_pin_fn = Box::new(|| {
        if atty::is(atty::Stream::Stderr) {
            if let Ok(p) = rpassword::prompt_password("FIDO2 PIN: ") {
                if !p.is_empty() {
                    return Ok(Some(p));
                }
            }
        }
        Ok(None)
    });
    if !cli.quiet {
        ctx.on_touch = Box::new(|| eprintln!("Touch your YubiKey…"));
    }
    ctx.allow_low_pin_attempts = cli.allow_low_pin_attempts;
    let result = match cli.command {
        // Bare `yb format` from a terminal is guided (spec 0023 §3).
        Commands::Format(args)
            if args.has_no_format_flags()
                && atty::is(atty::Stream::Stdin)
                && atty::is(atty::Stream::Stderr) =>
        {
            cli::guided::run(&mut ctx, &mut cli::guided::TtyPrompter)
        }
        Commands::Format(args) => cli::format::run(&ctx, &args),
        Commands::Store(args) => cli::store::run(&ctx, &args),
        Commands::Fetch(args) => cli::fetch::run(&ctx, &args),
        Commands::List(args) => cli::list::run(&ctx, &args),
        Commands::Remove(args) => cli::remove::run(&ctx, &args),
        Commands::Fsck(args) => cli::fsck::run(&ctx, &args),
        Commands::RotateManagementKey(args) => cli::rotate_management_key::run(&ctx, &args),
        Commands::ManagementKey(args) => cli::management_key::run(&ctx, &args),
        Commands::ListReaders(_) | Commands::Select(_) => unreachable!("handled above"),
        #[cfg(feature = "self-test")]
        Commands::SelfTest(args) => cli::self_test::run(&mut ctx, &args),
    };

    if let Some(path) = yb_core::fixture_path() {
        ctx.piv.save_fixture(&path)?;
    }

    result
}

// ---------------------------------------------------------------------------
// Device picker
// ---------------------------------------------------------------------------

fn make_device_picker() -> DevicePicker {
    if atty::is(atty::Stream::Stderr) {
        Box::new(|piv: &Arc<dyn PivBackend>, devices: &[DeviceInfo]| {
            cli::picker::run_picker(piv, devices)
        })
    } else {
        Box::new(|_piv: &Arc<dyn PivBackend>, devices: &[DeviceInfo]| {
            eprintln!("Multiple YubiKeys found. Use --serial to select one:");
            for d in devices {
                eprintln!(
                    "  serial={} version={} reader={}",
                    d.serial, d.version, d.reader
                );
            }
            anyhow::bail!("ambiguous device selection — use --serial or --reader")
        })
    }
}

// ---------------------------------------------------------------------------
// PIN / key resolution
// ---------------------------------------------------------------------------

type PinFn = Box<dyn Fn() -> Result<Option<String>>>;

fn make_pin_resolver(pin_stdin: bool) -> Result<(Option<String>, PinFn)> {
    if pin_stdin {
        // Spec 0037: the PIN is the first line of standard input, read
        // here, before any command runs; a payload read from standard
        // input (`yb store`) is everything after it, byte for byte.  Both
        // reads go through the process's one shared stdin buffer.
        use std::io::BufRead as _;
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        let pin = line
            .trim_end_matches('\n')
            .trim_end_matches('\r')
            .to_owned();
        return Ok((Some(pin), Box::new(|| Ok(None))));
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
                match rpassword::prompt_password("PIV PIN: ") {
                    Ok(p) if !p.is_empty() => return Ok(Some(p)),
                    Ok(_) => {}
                    Err(_) => {}
                }
            }
            Ok(None)
        }),
    ))
}

/// The management key from `YB_MANAGEMENT_KEY`, held in zeroizing memory
/// from here on (spec 0034 G1).
fn resolve_management_key() -> Option<Zeroizing<String>> {
    let v = Zeroizing::new(std::env::var("YB_MANAGEMENT_KEY").ok()?);
    (!v.is_empty()).then_some(v)
}
