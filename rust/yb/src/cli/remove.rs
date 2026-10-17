// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

use anyhow::Result;
use clap::Args;
use clap_complete::engine::ArgValueCompleter;
use yb_core::{list_blobs, remove_blobs, store::Store, Context, SecretOp};

use crate::cli::util::resolve_patterns;
use crate::complete::complete_blob_names;

#[derive(Args, Debug)]
pub struct RemoveArgs {
    /// Blob name(s) or glob patterns to remove.
    #[arg(required = true, add = ArgValueCompleter::new(complete_blob_names))]
    pub patterns: Vec<String>,

    /// Silently skip patterns that match nothing; exit 0 even if nothing was removed.
    #[arg(short = 'f', long = "ignore-missing")]
    pub ignore_missing: bool,
}

pub fn run(ctx: &Context, args: &RemoveArgs) -> Result<()> {
    let mut store = Store::from_device(&ctx.reader, ctx.piv.as_ref())?;
    store.sanitize();
    let post_quantum = store.kind.is_post_quantum();
    // The PIV credentials protect legacy stores only (spec 0024, 0028).
    if !post_quantum {
        ctx.enforce_default_policy(SecretOp::Remove)?;
    }

    let all_blob_names: Vec<String> = list_blobs(&store).into_iter().map(|b| b.name).collect();

    // Resolve all patterns to a deduplicated list of blob names to remove.
    let to_remove = resolve_patterns(&args.patterns, &all_blob_names, args.ignore_missing)?;

    if to_remove.is_empty() {
        return Ok(());
    }

    // One write pass, heads first (spec 0031).
    if post_quantum {
        let mgmt_key = post_quantum_management_key(ctx, &store)?;
        remove_blobs(&mut store, ctx.piv.as_ref(), &to_remove, &mgmt_key)?;
    } else {
        let mgmt_key = ctx.management_key_for_write()?;
        remove_blobs(&mut store, ctx.piv.as_ref(), &to_remove, &mgmt_key)?;
        ctx.complete_pending_repairs();
    }

    if !ctx.quiet {
        for name in &to_remove {
            eprintln!("Removed '{name}'");
        }
    }

    Ok(())
}

/// The management key of a post-quantum store (spec 0028, D7, D11): the
/// FIDO2 PIN and one touch, checked against the card.
#[cfg(not(windows))]
fn post_quantum_management_key(ctx: &Context, store: &Store) -> Result<yb_core::Zeroizing<String>> {
    let session = ctx.post_quantum_session()?;
    let descriptor = store.descriptor().expect("a post-quantum store");
    session.protection(ctx, descriptor).management_key()
}

#[cfg(windows)]
fn post_quantum_management_key(_: &Context, _: &Store) -> Result<yb_core::Zeroizing<String>> {
    anyhow::bail!("post-quantum stores are not supported on Windows")
}
