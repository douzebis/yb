// SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
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
    /// Number of PIV objects to allocate (1–16).
    #[arg(short = 'c', long = "object-count", default_value_t = DEFAULT_OBJECT_COUNT)]
    pub object_count: u8,

    /// Size of each PIV object in bytes (512–3052).
    #[arg(short = 's', long = "object-size", default_value_t = DEFAULT_OBJECT_SIZE)]
    pub object_size: usize,

    /// PIV slot to use for the ECDH encryption key (hex, e.g. 82).
    #[arg(short = 'k', long = "key-slot", default_value = "82")]
    pub key_slot: String,

    /// Generate a new EC key pair in the chosen slot.
    #[arg(short = 'g', long = "generate")]
    pub generate: bool,

    /// X.509 subject for the self-signed certificate (only with --generate).
    #[arg(short = 'n', long = "subject", default_value = DEFAULT_SUBJECT)]
    pub subject: String,
}

pub fn run(ctx: &Context, args: &FormatArgs) -> Result<()> {
    if !(1..=16).contains(&args.object_count) {
        bail!("object-count must be 1–16");
    }
    if !(OBJECT_MIN_SIZE..=OBJECT_MAX_SIZE).contains(&args.object_size) {
        bail!("object-size must be {OBJECT_MIN_SIZE}–{OBJECT_MAX_SIZE}");
    }

    let slot = u8::from_str_radix(args.key_slot.trim_start_matches("0x"), 16)
        .map_err(|_| anyhow::anyhow!("invalid key-slot: {}", args.key_slot))?;

    if args.generate {
        generate_certificate(ctx, slot, &args.subject)?;
    } else {
        verify_certificate(ctx, slot, &args.subject)?;
    }

    let mgmt_key = ctx.management_key_for_write()?;

    Store::format(
        &ctx.reader,
        ctx.piv.as_ref(),
        args.object_count,
        args.object_size,
        slot,
        mgmt_key.as_deref(),
        ctx.pin.as_deref(),
    )?;

    eprintln!(
        "Store formatted: {} object(s) × {} bytes, key slot 0x{slot:02x}",
        args.object_count, args.object_size
    );
    Ok(())
}

fn generate_certificate(ctx: &Context, slot: u8, subject: &str) -> Result<()> {
    let mgmt_key = ctx.management_key_for_write()?;
    ctx.piv.generate_certificate(
        &ctx.reader,
        slot,
        subject,
        mgmt_key.as_deref(),
        ctx.pin.as_deref(),
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
