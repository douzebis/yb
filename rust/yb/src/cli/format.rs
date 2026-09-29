// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! `yb format`, in two phases (spec 0022): checks that write nothing, then
//! the changes in an order where no failure leaves blobs behind a replaced
//! key or a management key that exists nowhere.

use anyhow::{bail, Context as _, Result};
use clap::Args;
use yb_core::{
    auxiliaries::{
        enable_pin_protected_management_key, generate_random_management_key, KeySwitch,
        ProtectionMode,
    },
    list_blobs,
    store::{
        constants::{DEFAULT_OBJECT_COUNT, DEFAULT_SUBJECT, OBJECT_ID_ZERO},
        Store,
    },
    Context, SecretOp, SlotKeyCheck,
};

use crate::cli::util::quote_name;

#[derive(Args, Debug)]
pub struct FormatArgs {
    /// Number of PIV objects to allocate (1–32).
    #[arg(short = 'c', long = "object-count", default_value_t = DEFAULT_OBJECT_COUNT)]
    pub object_count: u8,

    /// PIV slot for the ECDH encryption key (decimal or 0x-prefixed hex, e.g. 0x82).
    #[arg(short = 'k', long = "key-slot", default_value = "0x82")]
    pub key_slot: String,

    /// Generate a new EC key pair in the chosen slot.
    #[arg(short = 'g', long = "generate")]
    pub generate: bool,

    /// X.509 subject for the self-signed certificate (only with --generate).
    #[arg(short = 'n', long = "subject", default_value = DEFAULT_SUBJECT)]
    pub subject: String,

    /// Set up PIN-protected management key mode.
    ///
    /// Generates a random management key, stores it in the PIN-protected
    /// PRINTED object, and updates ADMIN DATA so that future write operations
    /// only require the PIN (no explicit --key needed).
    /// The current management key is taken from YB_MANAGEMENT_KEY, else from
    /// PRINTED if the YubiKey is already protected, else the factory default.
    #[arg(long = "protect")]
    pub protect: bool,
}

pub fn run(ctx: &Context, args: &FormatArgs) -> Result<()> {
    let plan = preflight(ctx, args).context("nothing was changed on the YubiKey")?;
    apply(ctx, args, plan)
}

/// What Phase A established for Phase B.
struct Plan {
    slot: u8,
    /// The card's current management key, accepted by the card.
    management_key: String,
    management_key_in_printed: bool,
    pin: String,
}

// ---------------------------------------------------------------------------
// Phase A — checks; writes nothing (spec 0022 §1)
// ---------------------------------------------------------------------------

fn preflight(ctx: &Context, args: &FormatArgs) -> Result<Plan> {
    // 1. Arguments.
    if !(1..=32).contains(&args.object_count) {
        bail!("object-count must be 1–32");
    }
    let slot = parse_slot(&args.key_slot)?;
    let standard_slots: &[u8] = &[0x9A, 0x9C, 0x9D, 0x9E];
    if !standard_slots.contains(&slot) && !(0x80u8..=0x95u8).contains(&slot) {
        eprintln!("Warning: slot 0x{slot:02x} is not a standard PIV key slot");
    }

    // 2. Card state: refuse PIN-derived or unparseable ADMIN DATA, and apply
    //    the default-credential policy (spec 0024).  The management key
    //    algorithm is detected by the authentication in 4.
    ctx.ensure_supported_protection()?;
    ctx.enforce_default_policy(SecretOp::Format {
        protect: args.protect,
    })?;

    // 3. PIN.
    let pin = ctx
        .require_pin()?
        .ok_or_else(|| anyhow::anyhow!("PIN required to format the store"))?;
    ctx.piv.verify_pin(&ctx.reader, &pin)?;

    // 4. Management key: resolved and accepted by the card.
    let management_key = ctx.management_key_for_write()?;
    let management_key_in_printed = ctx
        .management_key_source()
        .is_some_and(|source| source.is_printed());

    // 5. Store slot (kept as is unless --generate).
    if !args.generate {
        match ctx.check_slot_key(slot)? {
            SlotKeyCheck::Match => {}
            SlotKeyCheck::NoCertificate => {
                bail!("no certificate in slot 0x{slot:02x}; use --generate to create a key")
            }
            SlotKeyCheck::Mismatch => bail!(
                "the key in slot 0x{slot:02x} does not match its certificate; \
                 use --generate to replace both"
            ),
        }
    }

    // 6. Existing store: what will be destroyed (shown even with --quiet).
    announce_destroyed_blobs(ctx);

    Ok(Plan {
        slot,
        management_key,
        management_key_in_printed,
        pin,
    })
}

fn announce_destroyed_blobs(ctx: &Context) {
    match Store::from_device(&ctx.reader, ctx.piv.as_ref()) {
        Ok(store) => {
            for blob in list_blobs(&store) {
                eprintln!("will be destroyed: {}", quote_name(&blob.name));
            }
        }
        Err(_) => {
            let store_present = ctx
                .piv
                .object_size(&ctx.reader, OBJECT_ID_ZERO)
                .ok()
                .flatten()
                .is_some();
            if store_present {
                eprintln!("Warning: the existing store cannot be parsed; it will be erased");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Phase B — changes (spec 0022 §2)
// ---------------------------------------------------------------------------

fn apply(ctx: &Context, args: &FormatArgs, plan: Plan) -> Result<()> {
    let (reader, piv) = (ctx.reader.as_str(), ctx.piv.as_ref());
    let slot = plan.slot;
    let mut phase = PhaseB::new(ctx.quiet);
    let mut management_key = plan.management_key;

    // B1 — --protect first: it touches neither the store nor its key.
    if args.protect {
        // Keep the card's current algorithm (spec 0021 §3).
        let algo = piv.management_key_algorithm(reader)?;
        let new_key = generate_random_management_key(algo);
        phase.run("setting up the PIN-protected management key", "", || {
            enable_pin_protected_management_key(
                reader,
                piv,
                &KeySwitch {
                    old_key: &management_key,
                    old_key_in_printed: plan.management_key_in_printed,
                    new_key: &new_key,
                    algo,
                    clearing_legacy_flag: ctx.protection == ProtectionMode::LegacyOrPukBlocked,
                },
            )
        })?;
        management_key = new_key;
        if !ctx.quiet {
            eprintln!("PIN-protected management key configured ({algo}).");
        }
    }

    // B2 — erase the store before its key can be replaced.
    phase.run(
        "erasing the store",
        &format!(
            "The store may be partly erased; the key in slot 0x{slot:02x} is unchanged, so \
             intact blobs still decrypt.  Run `yb format` again."
        ),
        || Store::format(reader, piv, args.object_count, slot, &management_key),
    )?;
    // B1 already wrote ADMIN DATA and PRINTED when --protect ran.
    if !args.protect {
        ctx.complete_pending_repairs();
    }

    // B3 — --generate last: its failures only affect an empty store.
    if args.generate {
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
                    &args.subject,
                    &management_key,
                    Some(&plan.pin),
                )?;
                match ctx.check_slot_key(slot)? {
                    SlotKeyCheck::Match => Ok(()),
                    _ => bail!("the new certificate does not match the key in the slot"),
                }
            },
        )?;
    }

    if !ctx.quiet {
        eprintln!(
            "Store formatted: {} object(s), key slot 0x{slot:02x}",
            args.object_count
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
    fn new(quiet: bool) -> Self {
        Self {
            quiet,
            done: Vec::new(),
        }
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
