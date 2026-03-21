// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

use anyhow::{bail, Result};
use clap::Args;
use yb_core::{
    store::{
        constants::{
            DEFAULT_OBJECT_COUNT, DEFAULT_OBJECT_SIZE, DEFAULT_SUBJECT, OBJECT_MAX_SIZE,
            OBJECT_MIN_SIZE,
        },
        Store,
    },
    Context,
};

#[derive(Args, Debug)]
pub struct FormatArgs {
    /// Number of PIV objects to allocate (1–20).
    #[arg(short = 'c', long = "object-count", default_value_t = DEFAULT_OBJECT_COUNT)]
    pub object_count: u8,

    /// Size of each PIV object in bytes (512–3052).
    #[arg(short = 's', long = "object-size", default_value_t = DEFAULT_OBJECT_SIZE)]
    pub object_size: usize,

    /// PIV slot for the ECDH encryption key (decimal or 0x-prefixed hex, e.g. 0x82).
    #[arg(short = 'k', long = "key-slot", default_value = "0x82")]
    pub key_slot: String,

    /// Generate a new EC key pair in the chosen slot.
    #[arg(short = 'g', long = "generate")]
    pub generate: bool,

    /// X.509 subject for the self-signed certificate (only with --generate).
    #[arg(short = 'n', long = "subject", default_value = DEFAULT_SUBJECT)]
    pub subject: String,
}

pub fn run(ctx: &Context, args: &FormatArgs) -> Result<()> {
    if !(1..=20).contains(&args.object_count) {
        bail!("object-count must be 1–20");
    }
    if !(OBJECT_MIN_SIZE..=OBJECT_MAX_SIZE).contains(&args.object_size) {
        bail!("object-size must be {OBJECT_MIN_SIZE}–{OBJECT_MAX_SIZE}");
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

    let mgmt_key = ctx.management_key_for_write()?;

    let pin = ctx.require_pin()?;
    Store::format(
        &ctx.reader,
        ctx.piv.as_ref(),
        args.object_count,
        args.object_size,
        slot,
        mgmt_key.as_deref(),
        pin.as_deref(),
    )?;

    if !ctx.quiet {
        eprintln!(
            "Store formatted: {} object(s) × {} bytes, key slot 0x{slot:02x}",
            args.object_count, args.object_size
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
