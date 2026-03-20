// SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

use crate::{
    context::Context,
    store::{
        constants::{
            DEFAULT_OBJECT_COUNT, DEFAULT_OBJECT_SIZE, DEFAULT_SUBJECT, OBJECT_MAX_SIZE,
            OBJECT_MIN_SIZE,
        },
        Store,
    },
};
use anyhow::{bail, Result};
use clap::Args;

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
    use tempfile::NamedTempFile;

    let slot_hex = format!("{slot:02x}");
    let reader = &ctx.reader;

    let pubkey_file = NamedTempFile::new()?;
    let cert_file = NamedTempFile::new()?;

    // Step 1: generate key.
    let mut args = vec![
        "--reader",
        reader,
        "--action",
        "generate",
        "--slot",
        &slot_hex,
        "--algorithm",
        "ECCP256",
        "--touch-policy",
        "never",
        "--pin-policy",
        "once",
        "--output",
        pubkey_file.path().to_str().unwrap(),
    ];
    let key_arg;
    if let Some(ref k) = ctx.management_key {
        key_arg = format!("--key={k}");
        args.push(&key_arg);
    }
    run_yubico_piv_tool(&args)?;

    // Step 2: self-sign.
    let mut args = vec![
        "--reader",
        reader,
        "--action",
        "verify-pin",
        "--slot",
        &slot_hex,
        "--subject",
        subject,
        "--action",
        "selfsign",
        "--input",
        pubkey_file.path().to_str().unwrap(),
        "--output",
        cert_file.path().to_str().unwrap(),
    ];
    let pin_arg;
    if let Some(ref p) = ctx.pin {
        pin_arg = format!("--pin={p}");
        args.push(&pin_arg);
    }
    let key_arg;
    if let Some(ref k) = ctx.management_key {
        key_arg = format!("--key={k}");
        args.push(&key_arg);
    }
    run_yubico_piv_tool(&args)?;

    // Step 3: import certificate.
    let mut args = vec![
        "--reader",
        reader,
        "--action",
        "import-certificate",
        "--slot",
        &slot_hex,
        "--input",
        cert_file.path().to_str().unwrap(),
    ];
    let key_arg;
    if let Some(ref k) = ctx.management_key {
        key_arg = format!("--key={k}");
        args.push(&key_arg);
    }
    run_yubico_piv_tool(&args)?;

    Ok(())
}

fn verify_certificate(ctx: &Context, slot: u8, _expected_subject: &str) -> Result<()> {
    // Just check that a certificate exists in the slot.
    let slot_hex = format!("{slot:02x}");
    let args = [
        "--reader",
        &ctx.reader,
        "--slot",
        &slot_hex,
        "--action",
        "read-certificate",
    ];
    run_yubico_piv_tool(&args)?;
    Ok(())
}

fn run_yubico_piv_tool(args: &[&str]) -> Result<()> {
    use std::process::Command;
    let out = Command::new("yubico-piv-tool")
        .args(args)
        .output()
        .map_err(|e| anyhow::anyhow!("failed to run yubico-piv-tool: {e}"))?;
    if !out.status.success() {
        bail!(
            "yubico-piv-tool failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}
