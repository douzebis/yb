// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Formatting a post-quantum store (spec 0028, "Commands"): with flags
//! (`yb format --post-quantum`) or guided.
//!
//! The store uses the YubiKey's own management key, never the factory one
//! (D7): yb wraps it with FIDO2 and does not change it.  Then: the FIDO2
//! credential (one touch), the management key wrapped (one touch), the
//! empty chunks, the descriptor last (D13).

use anyhow::{bail, Context as _, Result};
use yb_core::auxiliaries::{read_printed_keys, ProtectionMode, DEFAULT_MANAGEMENT_KEY};
use yb_core::errors::YbError;
use yb_core::fido2::{pairing, Device};
use yb_core::orchestrator::post_quantum::create_post_quantum_store;
use yb_core::report::StorePresence;
use yb_core::{Context, MgmtAlgo, Zeroizing};

use crate::cli::format::{EraseStep, FormatArgs};
use crate::cli::guided::Prompter;
use crate::cli::util::quote_name;

/// yb's minimum for a new FIDO2 PIN (the YubiKey accepts 4).
const MIN_NEW_PIN: usize = 6;
const NOTHING_CHANGED: &str = "nothing was changed on the YubiKey";

const PIN_WARNING: &str = "The FIDO2 PIN has no unblocking code: 8 wrong PINs block it for \
                           good, and only a FIDO2 reset clears it, which destroys this store.  \
                           Keep backups.";

/// The management key, checked: accepted by the card, not the factory key
/// (D7).  Returns its algorithm.
fn check_management_key(ctx: &Context, key: &str) -> Result<MgmtAlgo> {
    if key.trim().eq_ignore_ascii_case(DEFAULT_MANAGEMENT_KEY) {
        return Err(YbError::new("the management key is the factory default")
            .why("a post-quantum store uses the YubiKey's own management key")
            .fix("change it first, e.g. `ykman piv access change-management-key`")
            .into());
    }
    ctx.piv
        .authenticate_management_key(&ctx.reader, key)
        .context("the YubiKey rejected the management key")?;
    ctx.piv.management_key_algorithm(&ctx.reader)
}

/// Say what the format destroys (shown even with --quiet).
fn erase_notice(store: &StorePresence) {
    match EraseStep::from_store(store) {
        EraseStep::Blobs(names) => {
            for name in names {
                eprintln!("will be destroyed: {}", quote_name(&name));
            }
        }
        EraseStep::Unreadable => {
            eprintln!("Warning: the existing store cannot be parsed; it will be erased")
        }
        EraseStep::NoStore | EraseStep::Empty => {}
    }
}

/// Create the store.
fn apply(
    ctx: &Context,
    device: &Device,
    pin: &str,
    management_key: &str,
    algo: MgmtAlgo,
    object_count: u8,
) -> Result<()> {
    create_post_quantum_store(
        ctx.piv.as_ref(),
        &ctx.reader,
        device,
        pin,
        management_key,
        algo,
        object_count,
        &*ctx.on_touch,
    )
    .context("formatting the post-quantum store")?;
    if !ctx.quiet {
        eprintln!(
            "Formatted a post-quantum store of {object_count} objects on YubiKey {}.  Keep \
             backups: a FIDO2 or PIV reset destroys it.",
            ctx.serial
        );
    }
    Ok(())
}

/// `yb format --post-quantum`: the management key from YB_MANAGEMENT_KEY
/// (the PIV PIN is never used), the FIDO2 PIN given non-interactively or
/// prompted; a FIDO2 PIN must already be set.
pub fn run_flags(ctx: &Context, args: &FormatArgs) -> Result<()> {
    if args.key_slot.is_some() || args.generate || args.subject.is_some() || args.protect {
        bail!("--key-slot, --generate, --subject and --protect are for legacy stores, not with --post-quantum");
    }
    let object_count = args
        .object_count
        .unwrap_or(yb_core::store::constants::DEFAULT_OBJECT_COUNT);
    if !(1..=32).contains(&object_count) {
        bail!("object-count must be 1–32");
    }
    let Some(key) = ctx.management_key.clone() else {
        return Err(YbError::new("the management key is needed")
            .fix("set YB_MANAGEMENT_KEY, or run `yb format` in a terminal (guided)")
            .into());
    };
    let algo = check_management_key(ctx, &key).context(NOTHING_CHANGED)?;
    let store = StorePresence::probe(&ctx.reader, ctx.piv.as_ref());
    if args.plan {
        println!(
            "Plan: a post-quantum store of {object_count} objects on YubiKey {}: create a FIDO2 \
             credential (touch), wrap the management key ({}) with it (touch), erase and \
             write the objects, the descriptor last.",
            ctx.serial,
            algo.name()
        );
        return Ok(());
    }
    let session = ctx
        .post_quantum_session()
        .map_err(|e| match e.downcast_ref::<yb_core::fido2::Fido2Error>() {
            Some(yb_core::fido2::Fido2Error::PinNotSet) => anyhow::Error::from(
                YbError::new("no FIDO2 PIN is set on this YubiKey")
                    .fix("set one first (`ykman fido access change-pin`), or run `yb format` in a terminal (guided)"),
            ),
            _ => e,
        })
        .context(NOTHING_CHANGED)?;
    erase_notice(&store);
    apply(
        ctx,
        &session.device,
        session.pin(),
        &key,
        algo,
        object_count,
    )
}

/// The guided format, once the user chose a post-quantum store.
pub fn run_guided(ctx: &mut Context, p: &mut dyn Prompter, store: &StorePresence) -> Result<()> {
    // 1. The FIDO2 side of this YubiKey.
    let piv_yubikeys = ctx.piv.list_devices().map(|d| d.len()).unwrap_or(1);
    let device =
        pairing::open_yubikey(ctx.serial, piv_yubikeys, &*ctx.on_touch).context(NOTHING_CHANGED)?;

    // 2. The FIDO2 PIN.
    p.say("");
    p.say(PIN_WARNING);
    let (pin, new_pin) = if device.has_pin() {
        ctx.check_fido2_pin_attempts(&device)
            .context(NOTHING_CHANGED)?;
        let pin = match ctx.require_fido2_pin()? {
            Some(pin) => pin,
            None => Zeroizing::new(p.ask_secret("FIDO2 PIN: ")?),
        };
        (pin, false)
    } else {
        p.say("This YubiKey has no FIDO2 PIN yet: choose one (at least 6 characters).");
        (ask_new_fido2_pin(p)?, true)
    };

    // 3. The management key.
    let key = ask_management_key(ctx, p)?;
    let algo = check_management_key(ctx, &key).context(NOTHING_CHANGED)?;

    // 4. Object count, plan, confirmation.
    let object_count = ask_object_count(p)?;
    p.say("");
    p.say(&format!(
        "Plan for YubiKey {}:\n  - a post-quantum store of {object_count} objects, protected by \
         the YubiKey's FIDO2 application\n  - {}create a FIDO2 credential (touch)\n  - wrap your \
         management key ({}) with it (touch); yb does not change the key\n  - erase the \
         yb objects and write the new store\n  - backups are mandatory: a FIDO2 or PIV reset \
         destroys the store",
        ctx.serial,
        if new_pin { "set the FIDO2 PIN, " } else { "" },
        algo.name()
    ));
    if ctx.protection == ProtectionMode::Standard {
        p.say(
            "  - note: a copy of the management key stays in PRINTED (ykman): anyone with the \
             PIV PIN can delete blobs, though not read or forge them",
        );
    }
    confirm(ctx.serial, store, p)?;

    // 5. Execution.
    if new_pin {
        device.set_pin(&pin).context(NOTHING_CHANGED)?;
        ctx.set_fido2_pin(&pin);
    }
    apply(ctx, &device, &pin, &key, algo, object_count)
}

fn ask_new_fido2_pin(p: &mut dyn Prompter) -> Result<Zeroizing<String>> {
    loop {
        let pin = Zeroizing::new(p.ask_secret("New FIDO2 PIN: ")?);
        if pin.chars().count() < MIN_NEW_PIN || pin.len() > 63 {
            p.say("The FIDO2 PIN must have 6 to 63 characters.");
            continue;
        }
        let again = Zeroizing::new(p.ask_secret("New FIDO2 PIN again: ")?);
        if *again != *pin {
            p.say("The two PINs differ.");
            continue;
        }
        return Ok(pin);
    }
}

/// The management key: YB_MANAGEMENT_KEY, else ykman's copy in PRINTED
/// (with the PIV PIN, if the user agrees), else typed.
fn ask_management_key(ctx: &Context, p: &mut dyn Prompter) -> Result<Zeroizing<String>> {
    if let Some(key) = ctx.management_key.clone() {
        return Ok(key);
    }
    if ctx.protection == ProtectionMode::Standard {
        let answer = p.ask(
            "The management key is kept on the YubiKey (ykman).  Read it with your PIV PIN?  [Y/n] ",
        )?;
        if !matches!(answer.trim().to_ascii_lowercase().as_str(), "n" | "no") {
            let piv_pin = Zeroizing::new(p.ask_secret("PIV PIN: ")?);
            ctx.piv.verify_pin(&ctx.reader, &piv_pin)?;
            if let Some(key) = read_printed_keys(&ctx.reader, ctx.piv.as_ref(), &piv_pin)?.current {
                return Ok(key);
            }
            p.say("No management key was found there.");
        }
    }
    Ok(Zeroizing::new(
        p.ask_secret("Management key (hex): ")?.trim().to_owned(),
    ))
}

fn ask_object_count(p: &mut dyn Prompter) -> Result<u8> {
    let default = yb_core::store::constants::DEFAULT_OBJECT_COUNT;
    loop {
        let answer = p.ask(&format!("Number of objects (1–32) [{default}]: "))?;
        let answer = answer.trim();
        if answer.is_empty() {
            return Ok(default);
        }
        match answer.parse::<u8>() {
            Ok(n) if (1..=32).contains(&n) => return Ok(n),
            _ => p.say("Please enter a number from 1 to 32."),
        }
    }
}

fn confirm(serial: u32, store: &StorePresence, p: &mut dyn Prompter) -> Result<()> {
    let destroys = match EraseStep::from_store(store) {
        EraseStep::Blobs(names) => Some(format!("{} blob(s)", names.len())),
        EraseStep::Unreadable => Some("an unreadable store".to_owned()),
        EraseStep::NoStore | EraseStep::Empty => None,
    };
    let cancelled = || -> anyhow::Error { crate::cli::guided::Cancelled.into() };
    match destroys {
        Some(what) => {
            p.say(&format!("This will destroy {what} on YubiKey {serial}."));
            let answer = p.ask("Type the serial number of this YubiKey to confirm: ")?;
            if answer.trim() != serial.to_string() {
                p.say("Cancelled: nothing was changed.");
                return Err(cancelled());
            }
        }
        None => {
            let answer = p.ask("Proceed?  [y/N] ")?;
            if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
                p.say("Cancelled: nothing was changed.");
                return Err(cancelled());
            }
        }
    }
    Ok(())
}
