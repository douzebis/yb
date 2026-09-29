// SPDX-FileCopyrightText: 2025, 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! `yb format`, in two phases (spec 0022): checks that write nothing, then
//! the changes in an order where no failure leaves blobs behind a replaced
//! key or a management key that exists nowhere.
//!
//! Without format flags, from a terminal, `yb format` is guided (spec
//! 0023, see [`crate::cli::guided`]); both modes share the plan and Phase B
//! defined here.

use anyhow::{bail, Context as _, Result};
use clap::Args;
use std::io::Write;
use yb_core::{
    auxiliaries::{
        enable_pin_protected_management_key, generate_random_management_key, KeySwitch,
        ProtectionMode,
    },
    errors::YbError,
    list_blobs,
    report::{CardReport, StorePresence},
    store::{
        constants::{DEFAULT_KEY_SLOT, DEFAULT_OBJECT_COUNT, DEFAULT_SUBJECT},
        Store,
    },
    Context, MgmtAlgo, SecretOp, SlotKeyCheck,
};

use crate::cli::util::quote_name;

#[derive(Args, Debug, Default)]
pub struct FormatArgs {
    /// Number of PIV objects to allocate (1–32) [default: 32].
    #[arg(short = 'c', long = "object-count")]
    pub object_count: Option<u8>,

    /// PIV slot for the ECDH encryption key (decimal or 0x-prefixed hex)
    /// [default: 0x82].
    #[arg(short = 'k', long = "key-slot")]
    pub key_slot: Option<String>,

    /// Generate a new EC key pair in the chosen slot.
    #[arg(short = 'g', long = "generate")]
    pub generate: bool,

    /// X.509 subject for the self-signed certificate (only with --generate)
    /// [default: /CN=YBLOB ECCP256].
    #[arg(short = 'n', long = "subject")]
    pub subject: Option<String>,

    /// Keep the management key on the YubiKey, unlocked by the PIN.
    ///
    /// If it is not kept there, replace it with a random key stored in the
    /// PRINTED object, which only the PIN unlocks, so that future write
    /// operations only require the PIN.  If it already is, keep it.
    /// The current management key is taken from YB_MANAGEMENT_KEY, else from
    /// PRINTED if the YubiKey is already protected, else the factory default.
    #[arg(long = "protect")]
    pub protect: bool,

    /// Format without the guided flow, even from a terminal: keep the key
    /// in the slot, 32 objects, no protection (unless other flags say
    /// otherwise).
    #[arg(long = "yes")]
    pub yes: bool,

    /// Run the checks and show what the format would do, then stop.
    ///
    /// Talks to the YubiKey (and verifies the PIN) but writes nothing.
    #[arg(long = "plan")]
    pub plan: bool,
}

impl FormatArgs {
    /// No format flag was given: from a terminal, the format is guided
    /// (spec 0023 §3).
    pub fn has_no_format_flags(&self) -> bool {
        !(self.generate
            || self.protect
            || self.object_count.is_some()
            || self.key_slot.is_some()
            || self.subject.is_some()
            || self.yes
            || self.plan)
    }
}

/// Flag-driven `yb format` (and `--plan`).
pub fn run(ctx: &Context, args: &FormatArgs) -> Result<()> {
    run_with_output(ctx, args, &mut std::io::stdout().lock())
}

/// [`run`], writing the `--plan` output to `out`.
pub fn run_with_output(ctx: &Context, args: &FormatArgs, out: &mut dyn Write) -> Result<()> {
    let settings = Settings::from_args(args)?;
    let report = args.plan.then(|| CardReport::build(ctx, settings.slot));
    if let Some(ref report) = report {
        writeln!(out, "{}", report.render(None))?;
    }
    let prepared = preflight(ctx, &settings).context("nothing was changed on the YubiKey")?;
    let store = StorePresence::probe(&ctx.reader, ctx.piv.as_ref());

    if let Some(report) = report {
        let occupied = report.slot.is_occupied();
        let plan = FormatPlan {
            serial: ctx.serial,
            change_pin: false,
            change_puk: false,
            management: ManagementStep::new(ctx, &settings, &prepared)?,
            erase: EraseStep::from_store(&store),
            slot_key: match (settings.generate, occupied) {
                (false, _) => SlotStep::Keep,
                (true, false) => SlotStep::Generate,
                (true, true) => SlotStep::Replace,
            },
            slot: settings.slot,
            object_count: settings.object_count,
        };
        write!(out, "{}", plan.render())?;
        return Ok(());
    }

    // What will be destroyed, shown even with --quiet (spec 0022 §1 step 6).
    match EraseStep::from_store(&store) {
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
    apply(ctx, &settings, prepared, Vec::new())
}

/// What to format, from the flags or the guided flow's answers.
pub(crate) struct Settings {
    pub object_count: u8,
    pub slot: u8,
    pub generate: bool,
    pub subject: String,
    pub protect: bool,
}

impl Settings {
    fn from_args(args: &FormatArgs) -> Result<Self> {
        let object_count = args.object_count.unwrap_or(DEFAULT_OBJECT_COUNT);
        if !(1..=32).contains(&object_count) {
            bail!("object-count must be 1–32");
        }
        let slot = match args.key_slot {
            Some(ref s) => parse_slot(s)?,
            None => DEFAULT_KEY_SLOT,
        };
        let standard_slots: &[u8] = &[0x9A, 0x9C, 0x9D, 0x9E];
        if !standard_slots.contains(&slot) && !(0x80u8..=0x95u8).contains(&slot) {
            eprintln!("Warning: slot 0x{slot:02x} is not a standard PIV key slot");
        }
        Ok(Self {
            object_count,
            slot,
            generate: args.generate,
            subject: args
                .subject
                .clone()
                .unwrap_or_else(|| DEFAULT_SUBJECT.to_owned()),
            protect: args.protect,
        })
    }
}

/// What Phase A established for Phase B.
pub(crate) struct Prepared {
    /// The card's current management key, accepted by the card.
    pub management_key: String,
    pub management_key_in_printed: bool,
    /// The key is already PIN-protected: `--protect` keeps it (spec 0023
    /// §3a).
    pub already_protected: bool,
    pub pin: String,
}

impl Prepared {
    /// Resolve the management key (spec 0022 §1 step 4) and, for
    /// `--protect`, whether it is already protected.
    pub fn resolve(ctx: &Context, protect: bool, pin: String) -> Result<Self> {
        let management_key = ctx.management_key_for_write()?;
        let management_key_in_printed = ctx
            .management_key_source()
            .is_some_and(|source| source.is_printed());
        let already_protected = protect && ctx.management_key_protected()?;
        Ok(Self {
            management_key,
            management_key_in_printed,
            already_protected,
            pin,
        })
    }
}

// ---------------------------------------------------------------------------
// The plan (spec 0023 §5), shared by the guided flow and --plan
// ---------------------------------------------------------------------------

pub(crate) enum ManagementStep {
    /// Leave the management key as it is (no --protect).
    Keep,
    /// Replace it with a random PIN-protected key.
    Protect(MgmtAlgo),
    /// It is already PIN-protected: keep it.
    KeepProtected(MgmtAlgo),
}

impl ManagementStep {
    pub fn new(ctx: &Context, settings: &Settings, prepared: &Prepared) -> Result<Self> {
        if !settings.protect {
            return Ok(Self::Keep);
        }
        let algo = ctx.piv.management_key_algorithm(&ctx.reader)?;
        Ok(if prepared.already_protected {
            Self::KeepProtected(algo)
        } else {
            Self::Protect(algo)
        })
    }
}

pub(crate) enum EraseStep {
    NoStore,
    Empty,
    /// The names of the blobs destroyed.
    Blobs(Vec<String>),
    Unreadable,
}

impl EraseStep {
    pub fn from_store(store: &StorePresence) -> Self {
        match store {
            StorePresence::None => Self::NoStore,
            StorePresence::Unreadable(_) => Self::Unreadable,
            StorePresence::Present(store) => {
                let names: Vec<String> = list_blobs(store).into_iter().map(|b| b.name).collect();
                if names.is_empty() {
                    Self::Empty
                } else {
                    Self::Blobs(names)
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SlotStep {
    Keep,
    /// Generate a key in an empty slot.
    Generate,
    /// Replace the key already in the slot.
    Replace,
}

pub(crate) struct FormatPlan {
    pub serial: u32,
    pub change_pin: bool,
    pub change_puk: bool,
    pub management: ManagementStep,
    pub erase: EraseStep,
    pub slot_key: SlotStep,
    pub slot: u8,
    pub object_count: u8,
}

impl FormatPlan {
    /// The steps, in execution order: PIN/PUK, then spec 0022 B1–B3.
    pub fn steps(&self) -> Vec<String> {
        let slot = self.slot;
        let mut steps = Vec::new();
        if self.change_pin {
            steps.push("Change PIN".to_owned());
        }
        if self.change_puk {
            steps.push("Change PUK".to_owned());
        }
        steps.push(match self.management {
            ManagementStep::Keep => {
                "Keep the management key (not stored on the YubiKey)".to_owned()
            }
            ManagementStep::Protect(algo) => format!(
                "Replace the management key with a random one ({algo}), kept on the YubiKey \
                 and unlocked by the PIN"
            ),
            ManagementStep::KeepProtected(algo) => {
                format!("Keep the management key stored on the YubiKey ({algo})")
            }
        });
        match &self.erase {
            EraseStep::NoStore => {}
            EraseStep::Empty => {
                steps.push("Erase the existing store (it holds no blobs)".to_owned())
            }
            EraseStep::Blobs(names) => steps.push(format!(
                "ERASE store — destroys {}: {}",
                plural(names.len(), "blob"),
                quoted_list(names)
            )),
            EraseStep::Unreadable => {
                steps.push("ERASE the existing store (it cannot be read)".to_owned())
            }
        }
        steps.push(format!(
            "Create the store: {}, key slot 0x{slot:02x}",
            plural(self.object_count.into(), "object")
        ));
        steps.push(match self.slot_key {
            SlotStep::Keep => format!("Keep existing key in slot 0x{slot:02x}"),
            SlotStep::Generate => format!("Generate a new key in slot 0x{slot:02x}"),
            SlotStep::Replace => format!("REPLACE the key in slot 0x{slot:02x} with a new one"),
        });
        steps
    }

    pub fn render(&self) -> String {
        let mut out = format!("Plan for YubiKey {}:\n", self.serial);
        for (i, step) in self.steps().iter().enumerate() {
            out.push_str(&format!("  {}. {step}\n", i + 1));
        }
        out
    }

    /// What the plan destroys, e.g. "1 blob (bar)"; `None` when nothing.
    pub fn destroys(&self) -> Option<String> {
        let mut what = Vec::new();
        match &self.erase {
            EraseStep::Blobs(names) => what.push(format!(
                "{} ({})",
                plural(names.len(), "blob"),
                quoted_list(names)
            )),
            EraseStep::Unreadable => what.push("the unreadable store".to_owned()),
            EraseStep::NoStore | EraseStep::Empty => {}
        }
        if self.slot_key == SlotStep::Replace {
            what.push(format!("the key in slot 0x{:02x}", self.slot));
        }
        (!what.is_empty()).then(|| what.join(" and "))
    }
}

fn plural(n: usize, noun: &str) -> String {
    if n == 1 {
        format!("1 {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

fn quoted_list(names: &[String]) -> String {
    names
        .iter()
        .map(|n| quote_name(n))
        .collect::<Vec<_>>()
        .join(", ")
}

// ---------------------------------------------------------------------------
// Phase A — checks; writes nothing (spec 0022 §1)
// ---------------------------------------------------------------------------

fn preflight(ctx: &Context, settings: &Settings) -> Result<Prepared> {
    let slot = settings.slot;

    // 2. Card state: refuse PIN-derived or unparseable ADMIN DATA, and apply
    //    the default-credential policy (spec 0024).  The management key
    //    algorithm is detected by the authentication in 4.
    ctx.ensure_supported_protection()?;
    ctx.enforce_default_policy(SecretOp::Format {
        protect: settings.protect,
    })?;

    // 3. PIN.
    let pin = ctx.require_pin()?.ok_or_else(|| {
        YbError::new("a PIN is needed to format the store")
            .fix("set YB_PIN, use --pin-stdin, or run yb in a terminal")
    })?;
    ctx.piv.verify_pin(&ctx.reader, &pin)?;

    // 4. Management key: resolved and accepted by the card.
    let prepared = Prepared::resolve(ctx, settings.protect, pin)?;

    // 5. Store slot (kept as is unless --generate).
    if !settings.generate {
        match ctx.check_slot_key(slot)? {
            SlotKeyCheck::Match => {}
            SlotKeyCheck::NoCertificate => {
                return Err(YbError::new(format!("no certificate in slot 0x{slot:02x}"))
                    .fix("add --generate to create a key and its certificate")
                    .into());
            }
            SlotKeyCheck::Mismatch => {
                return Err(YbError::new(format!(
                    "the key in slot 0x{slot:02x} does not match its certificate"
                ))
                .fix("add --generate to replace both")
                .into());
            }
        }
    }

    Ok(prepared)
}

// ---------------------------------------------------------------------------
// Phase B — changes (spec 0022 §2)
// ---------------------------------------------------------------------------

/// Run Phase B.  `already_done` lists the steps completed before it (the
/// guided flow's PIN/PUK changes), for failure messages.
pub(crate) fn apply(
    ctx: &Context,
    settings: &Settings,
    prepared: Prepared,
    already_done: Vec<String>,
) -> Result<()> {
    let (reader, piv) = (ctx.reader.as_str(), ctx.piv.as_ref());
    let slot = settings.slot;
    let mut phase = PhaseB::new(ctx.quiet, already_done);
    let mut management_key = prepared.management_key;
    let switching = settings.protect && !prepared.already_protected;

    // B1 — --protect first: it touches neither the store nor its key.
    if switching {
        // Keep the card's current algorithm (spec 0021 §3).
        let algo = piv.management_key_algorithm(reader)?;
        let new_key = generate_random_management_key(algo);
        phase.run("storing a new management key on the YubiKey", "", || {
            enable_pin_protected_management_key(
                reader,
                piv,
                &KeySwitch {
                    old_key: &management_key,
                    old_key_in_printed: prepared.management_key_in_printed,
                    new_key: &new_key,
                    algo,
                    clearing_legacy_flag: ctx.protection == ProtectionMode::LegacyOrPukBlocked,
                },
            )
        })?;
        management_key = new_key;
        if !ctx.quiet {
            eprintln!("New management key ({algo}) kept on the YubiKey, unlocked by the PIN.");
        }
    } else if settings.protect && !ctx.quiet {
        let algo = piv.management_key_algorithm(reader)?;
        eprintln!("The management key ({algo}) is already kept on the YubiKey; keeping it.");
    }

    // B2 — erase the store before its key can be replaced.
    phase.run(
        "erasing the store",
        &format!(
            "The store may be partly erased; the key in slot 0x{slot:02x} is unchanged, so \
             intact blobs still decrypt.  Run `yb format` again."
        ),
        || Store::format(reader, piv, settings.object_count, slot, &management_key),
    )?;
    // B1 already wrote ADMIN DATA and PRINTED when it switched keys.
    if !switching {
        ctx.complete_pending_repairs();
    }

    // B3 — --generate last: its failures only affect an empty store.
    if settings.generate {
        phase.run(
            &format!("generating a key in slot 0x{slot:02x}"),
            &format!(
                "The store is empty and the key in slot 0x{slot:02x} may have been \
                 replaced, but its certificate could not be written or does not match.  \
                 Do not store data.  Run `yb format --generate` again."
            ),
            || {
                piv.generate_certificate(
                    reader,
                    slot,
                    &settings.subject,
                    &management_key,
                    Some(&prepared.pin),
                )?;
                match ctx.check_slot_key(slot)? {
                    SlotKeyCheck::Match => Ok(()),
                    _ => Err(YbError::new(
                        "the new certificate does not match the key in the slot",
                    )
                    .into()),
                }
            },
        )?;
    }

    if !ctx.quiet {
        eprintln!(
            "Store formatted: {} object(s), key slot 0x{slot:02x}",
            settings.object_count
        );
    }
    Ok(())
}

/// Runs the Phase B steps: announces each one, and turns a failure into an
/// error that says which steps completed, the resulting card state and what
/// to run next (spec 0022 §4).
struct PhaseB {
    quiet: bool,
    done: Vec<String>,
}

impl PhaseB {
    fn new(quiet: bool, done: Vec<String>) -> Self {
        Self { quiet, done }
    }

    /// Run the step described by `what` (e.g. "erasing the store").
    /// `on_failure` describes the card state and the next command; it may be
    /// empty when the step's own error already does.
    fn run<T>(
        &mut self,
        what: &str,
        on_failure: &str,
        step: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        if !self.quiet {
            eprintln!("{}…", capitalize(what));
        }
        let result = step().with_context(|| {
            let done = if self.done.is_empty() {
                "nothing".to_owned()
            } else {
                self.done.join(", ")
            };
            let mut msg = format!("yb format stopped while {what} (completed: {done})");
            if !on_failure.is_empty() {
                msg.push_str(".  ");
                msg.push_str(on_failure);
            }
            msg
        });
        if result.is_ok() {
            self.done.push(what.to_owned());
        }
        result
    }
}

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

fn parse_slot(s: &str) -> anyhow::Result<u8> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u8::from_str_radix(hex, 16).map_err(|_| anyhow::anyhow!("invalid key-slot: {s}"))
    } else {
        s.parse::<u8>()
            .map_err(|_| anyhow::anyhow!("invalid key-slot: {s}"))
    }
}
