// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Guided `yb format` (spec 0023 §4–§6): inspect the YubiKey, ask the few
//! questions that matter, show the plan, confirm, run it, and summarize.
//!
//! Nothing is written before the final confirmation.  Prompts go through
//! a [`Prompter`], so that tests can drive the flow without a terminal.

use anyhow::{Context as _, Result};
use std::fmt;
use std::io::{BufRead as _, Write as _};
use yb_core::{
    auxiliaries::{self, DEFAULT_PIN, DEFAULT_PUK},
    context::MANAGEMENT_KEY_NOT_FOUND,
    errors::{render, CardError, RenderEnv, YbError},
    list_blobs,
    report::{CardReport, SlotCertificate, StorePresence},
    store::constants::{DEFAULT_KEY_SLOT, DEFAULT_OBJECT_COUNT, DEFAULT_SUBJECT},
    Context, PinRef, SlotKeyCheck,
};

use crate::cli::format::{
    apply, EraseStep, FormatPlan, ManagementStep, Prepared, Settings, SlotStep,
};
use crate::cli::util::quote_name;

const NOTHING_CHANGED: &str = "nothing was changed on the YubiKey";

/// Terminal I/O for the guided flow.
pub trait Prompter {
    /// Show text to the user (on stderr for a terminal).
    fn say(&mut self, text: &str);
    /// Ask a question; the answer is echoed.  Fails when input is closed.
    fn ask(&mut self, prompt: &str) -> Result<String>;
    /// Ask for a secret; the answer is not echoed.
    fn ask_secret(&mut self, prompt: &str) -> Result<String>;
}

/// The real terminal: prompts on stderr, answers from stdin.
pub struct TtyPrompter;

impl Prompter for TtyPrompter {
    fn say(&mut self, text: &str) {
        eprintln!("{text}");
    }

    fn ask(&mut self, prompt: &str) -> Result<String> {
        eprint!("{prompt}");
        std::io::stderr().flush()?;
        let mut line = String::new();
        if std::io::stdin().lock().read_line(&mut line)? == 0 {
            anyhow::bail!("no answer (input closed)");
        }
        Ok(line.trim_end_matches(['\n', '\r']).to_owned())
    }

    fn ask_secret(&mut self, prompt: &str) -> Result<String> {
        Ok(rpassword::prompt_password(prompt)?)
    }
}

/// The user declined, or answered in a way that stops the flow.  The flow
/// has already said `Nothing was changed on the YubiKey.`; `main` exits 1
/// without another message.
#[derive(Debug)]
pub struct Cancelled;

impl fmt::Display for Cancelled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cancelled; nothing was changed on the YubiKey")
    }
}

impl std::error::Error for Cancelled {}

fn cancel(p: &mut dyn Prompter) -> anyhow::Error {
    p.say("Nothing was changed on the YubiKey.");
    Cancelled.into()
}

/// Run the guided format.
pub fn run(ctx: &mut Context, p: &mut dyn Prompter) -> Result<()> {
    let slot = DEFAULT_KEY_SLOT;
    let store = StorePresence::probe(&ctx.reader, ctx.piv.as_ref());
    let report = CardReport::build(ctx, slot);

    // 1. Report, and blocking errors.
    p.say(&report.render(None));
    p.say(&store_summary(&store));
    p.say("");
    stop_if_blocked(ctx, &report).context(NOTHING_CHANGED)?;

    // 2–3. PIN and PUK.
    let pin = ask_pin(ctx, &report, p)?;
    let new_puk = ask_puk(ctx, &report, p)?;

    // 4. Store slot key.
    let slot_key = ask_slot_key(ctx, &report, &store, p)?;

    // 5. Management key: always PIN-protected (spec 0023 §3a).
    let mut prepared = resolve_management_key(ctx, &pin.current, p)?;

    // 6. Object count.
    let object_count = ask_object_count(p)?;

    let settings = Settings {
        object_count,
        slot,
        generate: slot_key != SlotStep::Keep,
        subject: DEFAULT_SUBJECT.to_owned(),
        protect: true,
    };
    let plan = FormatPlan {
        serial: ctx.serial,
        change_pin: pin.new.is_some(),
        change_puk: new_puk.is_some(),
        management: ManagementStep::new(ctx, &settings, &prepared)?,
        erase: EraseStep::from_store(&store),
        slot_key,
        slot,
        object_count,
    };

    // Plan and confirmation (spec 0023 §5).
    p.say("");
    p.say(&plan.render());
    confirm(ctx.serial, &plan, p)?;

    // Execution (spec 0023 §6).
    let mut done = Vec::new();
    let mut current_pin = pin.current.clone();
    if let Some(new) = pin.new.clone() {
        let new =
            change_credential(ctx, PinRef::Pin, &current_pin, new, p).context(NOTHING_CHANGED)?;
        ctx.set_pin(&new);
        current_pin = new;
        done.push("changing the PIN".to_owned());
        say_progress(ctx, p, "PIN changed.");
    }
    if let Some(new) = new_puk {
        change_credential(ctx, PinRef::Puk, DEFAULT_PUK, new, p).with_context(|| {
            if done.is_empty() {
                NOTHING_CHANGED.to_owned()
            } else {
                "yb format stopped while changing the PUK; the PIN has already been \
                 changed"
                    .to_owned()
            }
        })?;
        done.push("changing the PUK".to_owned());
        say_progress(ctx, p, "PUK changed.");
    }
    ctx.refresh_defaults();
    prepared.pin = current_pin;
    let management = plan.management;
    apply(ctx, &settings, prepared, done)?;

    if !ctx.quiet {
        p.say(&summary(ctx, &settings, slot_key, &management, &pin));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

fn store_summary(store: &StorePresence) -> String {
    match store {
        StorePresence::None => "Store: none.".to_owned(),
        StorePresence::Unreadable(reason) => format!("Store: unreadable ({reason})."),
        StorePresence::Present(store) => {
            let names: Vec<String> = list_blobs(store)
                .into_iter()
                .map(|b| quote_name(&b.name))
                .collect();
            let blobs = match names.len() {
                0 => "empty".to_owned(),
                1 => format!("1 blob: {}", names[0]),
                n => format!("{n} blobs: {}", names.join(", ")),
            };
            format!(
                "Store: {} objects, slot 0x{:02x}, {blobs}.",
                store.object_count, store.store_key_slot
            )
        }
    }
}

/// Stop, before any question, on a card the flow cannot set up (spec 0023
/// §4 step 1).
fn stop_if_blocked(ctx: &Context, report: &CardReport) -> Result<()> {
    ctx.ensure_supported_protection()?;
    if report.pin_blocked() {
        let err = YbError::new("the PIN is blocked").why("too many wrong attempts");
        return Err(if report.puk_blocked() {
            err.fix(
                "the PUK is blocked too: only a PIV reset (`ykman piv reset`) helps, and \
                 it erases every key and object of the PIV application",
            )
        } else {
            err.fix("unblock it with `ykman piv access unblock-pin`, then run `yb format` again")
        }
        .into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Questions (spec 0023 §4)
// ---------------------------------------------------------------------------

struct PinAnswer {
    /// The PIN the card has now, verified.
    current: String,
    /// The PIN to set, if it must change.
    new: Option<String>,
    /// The factory PIN is kept (`--allow-defaults`).
    kept_factory: bool,
}

fn ask_pin(ctx: &Context, report: &CardReport, p: &mut dyn Prompter) -> Result<PinAnswer> {
    let reported_default = report.pin.is_some_and(|m| m.is_default);
    let current = if reported_default {
        DEFAULT_PIN.to_owned()
    } else {
        match ctx.known_pin() {
            Some(pin) => pin,
            None => p.ask_secret("Current PIN: ")?,
        }
    };
    // A wrong PIN stops at once, as ykman does.
    ctx.piv
        .verify_pin(&ctx.reader, &current)
        .context(NOTHING_CHANGED)?;
    ctx.set_pin(&current);

    // Firmware < 5.3 cannot report a factory PIN: recognize it.
    let factory = reported_default || (!report.has_metadata() && current == DEFAULT_PIN);
    if !factory {
        return Ok(PinAnswer {
            current,
            new: None,
            kept_factory: false,
        });
    }
    if ctx.allow_defaults {
        p.say("Keeping the factory PIN (--allow-defaults).");
        return Ok(PinAnswer {
            current,
            new: None,
            kept_factory: true,
        });
    }
    p.say("Your PIN is the factory default and must be changed.");
    let new = ask_new_value(p, PinRef::Pin)?;
    Ok(PinAnswer {
        current,
        new: Some(new),
        kept_factory: false,
    })
}

fn ask_puk(ctx: &Context, report: &CardReport, p: &mut dyn Prompter) -> Result<Option<String>> {
    // A blocked PUK cannot be changed, and cannot reset the PIN either.
    if !report
        .puk
        .is_some_and(|m| m.is_default && m.retries_left > 0)
    {
        return Ok(None);
    }
    if ctx.allow_defaults {
        p.say("Keeping the factory PUK (--allow-defaults).");
        return Ok(None);
    }
    p.say(
        "Your PUK is the factory default and must be changed (with it, anyone holding \
         the YubiKey can set a new PIN).",
    );
    ask_new_value(p, PinRef::Puk).map(Some)
}

/// Ask for a new PIN or PUK, twice, until it is 6–8 bytes, not the
/// factory value, and both entries agree.  The card may still reject it
/// (complexity policy, spec 0023 §6).
fn ask_new_value(p: &mut dyn Prompter, which: PinRef) -> Result<String> {
    let factory = match which {
        PinRef::Pin => DEFAULT_PIN,
        PinRef::Puk => DEFAULT_PUK,
    };
    loop {
        let value = p.ask_secret(&format!("New {which} (6–8 characters): "))?;
        if !(6..=8).contains(&value.len()) {
            p.say(&format!("The {which} must be 6 to 8 characters long."));
            continue;
        }
        if value == factory {
            p.say(&format!("That is the factory {which}; choose another one."));
            continue;
        }
        if p.ask_secret(&format!("Repeat the new {which}: "))? != value {
            p.say("The two entries differ.");
            continue;
        }
        return Ok(value);
    }
}

fn ask_slot_key(
    ctx: &Context,
    report: &CardReport,
    store: &StorePresence,
    p: &mut dyn Prompter,
) -> Result<SlotStep> {
    let slot = report.slot.slot;
    let problem = match &report.slot.certificate {
        SlotCertificate::NotP256 { subject } => Some(format!(
            "the certificate in slot 0x{slot:02x} ({subject}) does not hold an EC P-256 key"
        )),
        SlotCertificate::Unparseable => Some(format!(
            "the certificate in slot 0x{slot:02x} cannot be parsed"
        )),
        SlotCertificate::None | SlotCertificate::P256 { .. } => {
            match ctx.check_slot_key(slot).context(NOTHING_CHANGED)? {
                SlotKeyCheck::NoCertificate => {
                    p.say(&format!(
                        "A new key will be generated in slot 0x{slot:02x}."
                    ));
                    // A key without a certificate is still replaced.
                    return Ok(if report.slot.key.is_some() {
                        SlotStep::Replace
                    } else {
                        SlotStep::Generate
                    });
                }
                SlotKeyCheck::Mismatch => Some(format!(
                    "the key in slot 0x{slot:02x} does not match its certificate"
                )),
                SlotKeyCheck::Match => None,
            }
        }
    };

    if let Some(problem) = problem {
        p.say(&format!("Warning: {problem}."));
        let answer = p.ask(&format!(
            "Replace the key in slot 0x{slot:02x}?  It may be used by another \
             application.  [y/N] "
        ))?;
        return if is_yes(&answer) {
            Ok(SlotStep::Replace)
        } else {
            Err(cancel(p))
        };
    }

    loop {
        let answer =
            p.ask("Keep the existing key (recommended), or generate a new one?  [K/g] ")?;
        match answer.trim().to_ascii_lowercase().as_str() {
            "" | "k" | "keep" => return Ok(SlotStep::Keep),
            "g" | "generate" => {
                if matches!(EraseStep::from_store(store), EraseStep::Blobs(_)) {
                    p.say(
                        "Note: anything encrypted to the current key, including copies of \
                         the blobs, can no longer be decrypted.",
                    );
                }
                return Ok(SlotStep::Replace);
            }
            _ => p.say("Please answer k (keep) or g (generate)."),
        }
    }
}

/// Resolve the current management key with the spec 0022 resolver, and ask
/// for it only when the resolver cannot find it (spec 0023 §4 step 5).
fn resolve_management_key(ctx: &mut Context, pin: &str, p: &mut dyn Prompter) -> Result<Prepared> {
    match Prepared::resolve(ctx, true, pin.to_owned()) {
        Ok(prepared) => return Ok(prepared),
        Err(e) if !is_key_not_found(&e) => return Err(e.context(NOTHING_CHANGED)),
        Err(_) => {}
    }
    p.say("The management key is not stored on the YubiKey and is not the factory default.");
    let key = p.ask_secret("Current management key (hex): ")?;
    ctx.management_key = Some(key.trim().to_owned());
    Prepared::resolve(ctx, true, pin.to_owned()).context(NOTHING_CHANGED)
}

fn is_key_not_found(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        c.downcast_ref::<YbError>()
            .is_some_and(|y| y.what == MANAGEMENT_KEY_NOT_FOUND)
    })
}

fn ask_object_count(p: &mut dyn Prompter) -> Result<u8> {
    p.say(
        "The store holds at most this many objects of ~3 KB each.  Empty objects use \
         almost no space on the YubiKey, so the maximum is the usual choice.",
    );
    loop {
        let answer = p.ask(&format!(
            "Number of objects (1–32) [{DEFAULT_OBJECT_COUNT}]: "
        ))?;
        let answer = answer.trim();
        if answer.is_empty() {
            return Ok(DEFAULT_OBJECT_COUNT);
        }
        match answer.parse::<u8>() {
            Ok(n) if (1..=32).contains(&n) => return Ok(n),
            _ => p.say("Please enter a number from 1 to 32."),
        }
    }
}

fn is_yes(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

// ---------------------------------------------------------------------------
// Confirmation (spec 0023 §5)
// ---------------------------------------------------------------------------

fn confirm(serial: u32, plan: &FormatPlan, p: &mut dyn Prompter) -> Result<()> {
    match plan.destroys() {
        Some(what) => {
            p.say(&format!("This will destroy {what} on YubiKey {serial}."));
            let answer = p.ask("Type the serial number of this YubiKey to confirm: ")?;
            if answer.trim() != serial.to_string() {
                return Err(cancel(p));
            }
        }
        None => {
            if !is_yes(&p.ask("Proceed?  [y/N] ")?) {
                return Err(cancel(p));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Execution (spec 0023 §6)
// ---------------------------------------------------------------------------

/// Change the PIN or PUK from `old` to `new`.  When the card's complexity
/// policy rejects the new value (`SW 6985`, nothing changed), say why and
/// ask for another one.  Returns the value set.
fn change_credential(
    ctx: &Context,
    which: PinRef,
    old: &str,
    mut new: String,
    p: &mut dyn Prompter,
) -> Result<String> {
    loop {
        match ctx.piv.change_reference(&ctx.reader, which, old, &new) {
            Ok(()) => return Ok(new),
            Err(e) if is_complexity_rejection(&e) => {
                p.say(&render(&e, &RenderEnv::default()));
                new = ask_new_value(p, which)?;
            }
            Err(e) => return Err(e),
        }
    }
}

fn is_complexity_rejection(e: &anyhow::Error) -> bool {
    matches!(
        e.downcast_ref::<CardError>(),
        Some(CardError::Status { sw: 0x6985, .. })
    )
}

fn say_progress(ctx: &Context, p: &mut dyn Prompter, text: &str) {
    if !ctx.quiet {
        p.say(text);
    }
}

fn summary(
    ctx: &Context,
    settings: &Settings,
    slot_key: SlotStep,
    management: &ManagementStep,
    pin: &PinAnswer,
) -> String {
    let key = match slot_key {
        SlotStep::Keep => "kept",
        SlotStep::Generate | SlotStep::Replace => "new",
    };
    let mut lines = vec![
        format!("Done.  YubiKey {} is ready.", ctx.serial),
        format!(
            "  Store: {} objects, empty.  Key: slot 0x{:02x} ({key}).",
            settings.object_count, settings.slot
        ),
    ];
    match management {
        ManagementStep::Protect(algo) => {
            lines.push(format!("  Management key: PIN-protected ({algo}), new."));
            lines.push(format!(
                "  It is stored behind the PIN; to read it back if ever needed: \
                 yubico-piv-tool -a verify-pin -a read-object --id 0x{:06x}",
                auxiliaries::OBJ_PRINTED
            ));
        }
        ManagementStep::KeepProtected(algo) => {
            lines.push(format!("  Management key: PIN-protected ({algo})."))
        }
        ManagementStep::Keep => {}
    }
    let kept_factory_puk = ctx.defaults.puk;
    if pin.kept_factory || kept_factory_puk {
        lines.push(
            "  The factory PIN/PUK were kept: `yb store` refuses until they are changed, \
             unless it too gets --allow-defaults."
                .to_owned(),
        );
    }
    lines.push(String::new());
    lines.push("Next:  echo \"s3cr3t\" | yb store -n my-secret".to_owned());
    lines.push("       yb ls -l".to_owned());
    lines.push("       yb fsck          (health check)".to_owned());
    lines.join("\n")
}
