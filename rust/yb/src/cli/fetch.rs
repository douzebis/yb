// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

use anyhow::{bail, Result};
use clap::Args;
use clap_complete::engine::{ArgValueCompleter, PathCompleter};
use std::io::Write as _;
use std::path::PathBuf;
use yb_core::orchestrator;
use yb_core::{store::Store, Context, SecretOp};

use crate::cli::util::{
    check_blob_signature, resolve_patterns, ExitStatus, SigVerdict, StatusError,
};
use crate::complete::complete_blob_names;

#[derive(Args, Debug)]
pub struct FetchArgs {
    /// Blob name(s) or glob patterns to retrieve.
    #[arg(required = true, add = ArgValueCompleter::new(complete_blob_names))]
    pub patterns: Vec<String>,

    /// Write blob content to stdout (only valid when exactly one blob matches).
    #[arg(short = 'p', long = "stdout")]
    pub stdout: bool,

    /// Write output to this file (only valid when exactly one blob matches).
    #[arg(short = 'o', long = "output", add = ArgValueCompleter::new(PathCompleter::file()))]
    pub output: Option<PathBuf>,

    /// Write fetched files into this directory (default: current directory).
    #[arg(short = 'O', long = "output-dir", add = ArgValueCompleter::new(PathCompleter::dir()))]
    pub output_dir: Option<PathBuf>,

    /// Deprecated: saving to files is now the default behavior.
    #[arg(short = 'x', long = "extract", hide = true)]
    pub extract: bool,
}

pub fn run(ctx: &Context, args: &FetchArgs) -> Result<()> {
    ctx.enforce_default_policy(SecretOp::Fetch)?;
    // Validate mutually exclusive output flags.
    if args.stdout && args.output.is_some() {
        bail!("--stdout and --output are mutually exclusive");
    }
    if args.stdout && args.output_dir.is_some() {
        bail!("--stdout and --output-dir are mutually exclusive");
    }
    if args.output.is_some() && args.output_dir.is_some() {
        bail!("--output and --output-dir are mutually exclusive");
    }

    if args.extract {
        eprintln!("Warning: --extract is deprecated; saving to files is now the default behavior");
    }

    let store = Store::from_device(&ctx.reader, ctx.piv.as_ref())?;
    let all_blobs = orchestrator::list_blobs(&store);

    // Resolve patterns to matched blob names.
    let all_blob_names: Vec<String> = all_blobs.iter().map(|b| b.name.clone()).collect();
    let matched = resolve_patterns(&args.patterns, &all_blob_names, false)?;

    // Validate per-match constraints.
    if (args.stdout || args.output.is_some()) && matched.len() != 1 {
        bail!(
            "--stdout / --output require exactly one matching blob, but {} matched",
            matched.len()
        );
    }

    // Signatures are checked against the slot's certificate (no PIN) before
    // any decryption (spec 0033).
    let verifying_key = ctx
        .piv
        .read_certificate(&ctx.reader, store.store_key_slot)
        .ok()
        .and_then(|cert_der| yb_core::parse_ec_public_key_from_cert_der(&cert_der).ok())
        .map(|pk| p256::ecdsa::VerifyingKey::from(&pk));

    for name in &matched {
        if let Some(head) = store.find_head(name) {
            match check_blob_signature(head, &store, verifying_key.as_ref()) {
                SigVerdict::Verified => {}
                SigVerdict::Corrupted => bail!(
                    "blob '{name}' is corrupted or was tampered with: its signature does \
                     not verify; nothing was fetched"
                ),
                SigVerdict::Unsigned => eprintln!(
                    "Warning: blob '{name}' has no signature (stored by an older yb); \
                     its integrity cannot be checked"
                ),
                SigVerdict::Unverifiable => eprintln!(
                    "Warning: blob '{name}' could not be checked: no certificate in slot \
                     0x{:02x}",
                    store.store_key_slot
                ),
            }
        }
        let pin = ctx.require_pin()?;
        let data = orchestrator::fetch_blob(
            &store,
            ctx.piv.as_ref(),
            &ctx.reader,
            name,
            pin.as_deref(),
            ctx.debug,
        )?
        .ok_or_else(|| {
            StatusError::new(ExitStatus::NotFound, format!("blob '{name}' not found"))
        })?;

        if args.stdout {
            std::io::stdout().write_all(&data)?;
        } else if let Some(ref path) = args.output {
            std::fs::write(path, &data)?;
            if !ctx.quiet {
                eprintln!(
                    "Fetched '{}' → {} ({} bytes)",
                    name,
                    path.display(),
                    data.len()
                );
            }
        } else {
            // Save to file: use output_dir / blob_name.
            let dest = if let Some(ref dir) = args.output_dir {
                dir.join(name)
            } else {
                PathBuf::from(name)
            };
            std::fs::write(&dest, &data)?;
            if !ctx.quiet {
                eprintln!(
                    "Fetched '{}' → {} ({} bytes)",
                    name,
                    dest.display(),
                    data.len()
                );
            }
        }
    }

    Ok(())
}
