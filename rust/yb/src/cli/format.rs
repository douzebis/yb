// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

use anyhow::{bail, Result};
use clap::Args;
use yb_core::{
    auxiliaries::{
        enable_pin_protected_management_key, generate_random_management_key, DEFAULT_MANAGEMENT_KEY,
    },
    store::{
        constants::{DEFAULT_OBJECT_COUNT, DEFAULT_SUBJECT},
        Store,
    },
    Context,
};

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
    /// The current management key must be the factory default; supply it via
    /// YB_MANAGEMENT_KEY or --key if it has already been changed.
    #[arg(long = "protect")]
    pub protect: bool,
}

pub fn run(ctx: &Context, args: &FormatArgs) -> Result<()> {
    if !(1..=32).contains(&args.object_count) {
        bail!("object-count must be 1–32");
    }

    let slot = parse_slot(&args.key_slot)?;

    // Warn for non-standard PIV slots.
    let standard_slots: &[u8] = &[0x9A, 0x9C, 0x9D, 0x9E];
    let retired_range = 0x80u8..=0x95u8;
    if !standard_slots.contains(&slot) && !retired_range.contains(&slot) {
        eprintln!("Warning: slot 0x{slot:02x} is not a standard PIV key slot");
    }

    if args.generate {
        generate_certificate(ctx, slot, &args.subject)?;
    } else {
        verify_certificate(ctx, slot, &args.subject)?;
    }

    // --protect: generate a random management key and store it in
    // PIN-protected mode so that future write operations only require the PIN.
    //
    // After this completes the card's management key has changed, so we must
    // use pin-only auth for the Store::format call that follows — passing the
    // new key explicitly would also work but would require keeping it in memory
    // longer than necessary.  We set mgmt_key_override to signal which path
    // to take below.
    let pin_only_after_protect = if args.protect {
        let old_key = ctx
            .management_key
            .as_deref()
            .unwrap_or(DEFAULT_MANAGEMENT_KEY);
        let pin = ctx.require_pin()?.ok_or_else(|| {
            anyhow::anyhow!("PIN required to set up PIN-protected management key")
        })?;
        let new_key_hex = generate_random_management_key();
        enable_pin_protected_management_key(
            &ctx.reader,
            ctx.piv.as_ref(),
            old_key,
            &new_key_hex,
            &pin,
        )?;
        if !ctx.quiet {
            eprintln!("PIN-protected management key configured.");
        }
        true
    } else {
        false
    };

    // Resolve the management key for Store::format.
    // If --protect just ran, PIN-protected mode is now active on the card even
    // though ctx.pin_protected was set at startup (before the change).  Use
    // pin-only auth (mgmt_key = None) so write_object retrieves the new key
    // from the PRINTED object via PIN verification in the same session.
    let mgmt_key = if pin_only_after_protect {
        None
    } else {
        ctx.management_key_for_write()?
    };

    let pin = ctx.require_pin()?;
    Store::format(
        &ctx.reader,
        ctx.piv.as_ref(),
        args.object_count,
        slot,
        mgmt_key.as_deref(),
        pin.as_deref(),
    )?;

    if !ctx.quiet {
        eprintln!(
            "Store formatted: {} object(s), key slot 0x{slot:02x}",
            args.object_count
        );
    }
    Ok(())
}

fn parse_slot(s: &str) -> anyhow::Result<u8> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u8::from_str_radix(hex, 16).map_err(|_| anyhow::anyhow!("invalid key-slot: {s}"))
    } else {
        s.parse::<u8>()
            .map_err(|_| anyhow::anyhow!("invalid key-slot: {s}"))
    }
}

fn generate_certificate(ctx: &Context, slot: u8, subject: &str) -> Result<()> {
    let mgmt_key = ctx.management_key_for_write()?;
    let pin = ctx.require_pin()?;
    ctx.piv.generate_certificate(
        &ctx.reader,
        slot,
        subject,
        mgmt_key.as_deref(),
        pin.as_deref(),
    )?;
    Ok(())
}

fn verify_certificate(ctx: &Context, slot: u8, _expected_subject: &str) -> Result<()> {
    // Just check that a certificate exists in the slot.
    ctx.piv
        .read_certificate(&ctx.reader, slot)
        .map_err(|e| anyhow::anyhow!("no certificate in slot 0x{slot:02x}: {e}"))?;
    Ok(())
}
