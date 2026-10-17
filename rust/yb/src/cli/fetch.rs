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

    /// Read unencrypted blobs without any PIN or touch (spec 0044).  On a
    /// post-quantum store only their checksum is checked, not their seal
    /// nor the YubiKey's management key: corruption is detected, forgery
    /// is not.  For a locked YubiKey (blocked or reset FIDO2 PIN).
    /// Encrypted blobs are refused.
    #[arg(long = "no-check")]
    pub no_check: bool,

    /// Deprecated: saving to files is now the default behavior.
    #[arg(short = 'x', long = "extract", hide = true)]
    pub extract: bool,
}

pub fn run(ctx: &Context, args: &FetchArgs) -> Result<()> {
    let store = Store::from_device(&ctx.reader, ctx.piv.as_ref())?;
    // The PIV credentials protect legacy stores only (spec 0024, 0028).
    if !store.kind.is_post_quantum() {
        ctx.enforce_default_policy(SecretOp::Fetch)?;
    }
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

    if args.no_check {
        refuse_encrypted(&store, &matched)?;
        if store.kind.is_post_quantum() {
            return fetch_checksum_only(ctx, args, &store, &matched);
        }
    }

    if store.kind.is_post_quantum() {
        return fetch_post_quantum(ctx, args, &store, &matched);
    }

    // Signatures are checked against the slot's certificate (no PIN) before
    // any decryption (spec 0033).
    let verifying_key = ctx
        .piv
        .read_certificate(&ctx.reader, store.store_key_slot)
        .ok()
        .and_then(|cert_der| yb_core::parse_ec_public_key_from_cert_der(&cert_der).ok())
        .map(|pk| p256::ecdsa::VerifyingKey::from(&pk));

    // Every match is checked before anything is written, so that a
    // tampered blob among several stops the whole fetch.
    for name in &matched {
        if let Some(head) = store.find_head(name) {
            match check_blob_signature(head, &store, verifying_key.as_ref()) {
                // A checksum verdict comes from post-quantum stores only
                // (spec 0028, D5), whose fetch checks the seal.
                SigVerdict::Verified | SigVerdict::ChecksumOk => {}
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
                SigVerdict::NewerVersion => eprintln!(
                    "Warning: blob '{name}' was signed by a newer version of yb, so its \
                     integrity cannot be checked here; update yb to check it"
                ),
            }
        }
    }

    for name in &matched {
        if store
            .find_head(name)
            .is_some_and(orchestrator::uses_legacy_encryption)
        {
            eprintln!(
                "Warning: blob '{name}' uses the legacy encryption of older yb versions \
                 (AES-CBC, unauthenticated); store it again to protect it with AES-GCM"
            );
        }
        // The PIN only for an encrypted blob (spec 0034 G5).
        let encrypted = store.find_head(name).is_some_and(|h| h.is_encrypted());
        let pin = if encrypted { ctx.require_pin()? } else { None };
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
        write_output(ctx, args, name, &data)?;
    }

    Ok(())
}

/// Fetch from a post-quantum store (spec 0028): every matched blob's
/// checksum (no PIN), then its seal and the management key (FIDO2 PIN, one
/// touch per blob), all before anything is written (invariant 0006).
#[cfg(not(windows))]
fn fetch_post_quantum(
    ctx: &Context,
    args: &FetchArgs,
    store: &Store,
    matched: &[String],
) -> Result<()> {
    use yb_core::orchestrator::post_quantum::{quick_check, IntegrityError};
    for name in matched {
        let head = store.find_head(name).ok_or_else(|| {
            StatusError::new(ExitStatus::NotFound, format!("blob '{name}' not found"))
        })?;
        if quick_check(head, store) == SigVerdict::Corrupted {
            return Err(anyhow::Error::from(IntegrityError::Corrupted(name.clone()))
                .context("nothing was fetched"));
        }
    }
    let all_unencrypted = matched
        .iter()
        .all(|n| store.find_head(n).is_some_and(|h| !h.is_encrypted()));
    let session = ctx
        .post_quantum_session()
        .map_err(|e| suggest_no_check(e, all_unencrypted, None))?;
    let descriptor = store.descriptor().expect("a post-quantum store");
    let protection = session.protection(ctx, descriptor);
    let mut fetched = Vec::with_capacity(matched.len());
    for name in matched {
        let data = orchestrator::fetch_blob_with(store, &protection, name)
            .map_err(|e| {
                let retries = session.device.pin_retries().ok();
                suggest_no_check(e.context("nothing was fetched"), all_unencrypted, retries)
            })?
            .ok_or_else(|| {
                StatusError::new(ExitStatus::NotFound, format!("blob '{name}' not found"))
            })?;
        fetched.push((name, data));
    }
    for (name, data) in fetched {
        write_output(ctx, args, name, &data)?;
    }
    Ok(())
}

#[cfg(windows)]
fn fetch_post_quantum(_: &Context, _: &FetchArgs, _: &Store, _: &[String]) -> Result<()> {
    bail!("post-quantum stores are not supported on Windows")
}

/// `--no-check` refuses encrypted blobs, before anything is fetched.
fn refuse_encrypted(store: &Store, matched: &[String]) -> Result<()> {
    if let Some(name) = matched
        .iter()
        .find(|n| store.find_head(n).is_some_and(|h| h.is_encrypted()))
    {
        return Err(
            anyhow::Error::from(orchestrator::NoPinFetchError::Encrypted(name.clone()))
                .context("--no-check reads unencrypted blobs only; nothing was fetched"),
        );
    }
    Ok(())
}

/// `yb fetch --no-check` on a post-quantum store (spec 0044): every
/// blob's checksum, no FIDO2; all are read before anything is written.
fn fetch_checksum_only(
    ctx: &Context,
    args: &FetchArgs,
    store: &Store,
    matched: &[String],
) -> Result<()> {
    let mut fetched = Vec::with_capacity(matched.len());
    for name in matched {
        let (data, _) = orchestrator::fetch_unencrypted(store, ctx.piv.as_ref(), &ctx.reader, name)
            .map_err(|e| e.context("nothing was fetched"))?
            .ok_or_else(|| {
                StatusError::new(ExitStatus::NotFound, format!("blob '{name}' not found"))
            })?;
        fetched.push((name, data));
    }
    // Always, even with --quiet: the weakening must not go unnoticed.
    let names: Vec<String> = matched.iter().map(|n| format!("'{n}'")).collect();
    eprintln!(
        "warning: checksum only: {} checked against corruption, not against forgery (the \
         seal and the YubiKey's management key were not checked).  Anyone holding the \
         management key could have written {}.",
        names.join(", "),
        if names.len() == 1 { "it" } else { "them" }
    );
    for (name, data) in fetched {
        write_output(ctx, args, name, &data)?;
    }
    Ok(())
}

/// Add the `--no-check` hint to a post-quantum fetch failure when the
/// FIDO2 side is locked, reset or unreachable, and every blob asked for
/// is unencrypted (spec 0044 S2).  `retries`: the FIDO2 PIN attempts
/// left, for a wrong PIN.
#[cfg(not(windows))]
fn suggest_no_check(
    err: anyhow::Error,
    all_unencrypted: bool,
    retries: Option<u32>,
) -> anyhow::Error {
    use yb_core::fido2::Fido2Error;
    let locked = err.chain().any(|e| {
        matches!(
            e.downcast_ref::<Fido2Error>(),
            Some(
                Fido2Error::PinBlocked
                    | Fido2Error::PinAuthBlocked
                    | Fido2Error::FewAttempts(_)
                    | Fido2Error::NoCredential
                    | Fido2Error::PinNotSet
                    | Fido2Error::NoDevice
            )
        ) || (matches!(e.downcast_ref::<Fido2Error>(), Some(Fido2Error::PinInvalid))
            && retries.is_some_and(|n| n <= 3))
    });
    if !(locked && all_unencrypted) {
        return err;
    }
    yb_core::errors::YbError::new(format!("{err:#}"))
        .fix(
            "the blobs asked for are unencrypted: `yb fetch --no-check …` reads them without \
             the FIDO2 PIN, checking their checksum only (not their seal)",
        )
        .into()
}

/// Write one fetched blob where the arguments say.
fn write_output(ctx: &Context, args: &FetchArgs, name: &str, data: &[u8]) -> Result<()> {
    let dest = if args.stdout {
        std::io::stdout().write_all(data)?;
        return Ok(());
    } else if let Some(ref path) = args.output {
        path.clone()
    } else if let Some(ref dir) = args.output_dir {
        dir.join(name)
    } else {
        PathBuf::from(name)
    };
    std::fs::write(&dest, data)?;
    if !ctx.quiet {
        eprintln!(
            "Fetched '{}' → {} ({} bytes)",
            name,
            dest.display(),
            data.len()
        );
    }
    Ok(())
}
