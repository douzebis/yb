// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

use anyhow::Result;
use clap::Args;
use clap_complete::engine::ArgValueCompleter;
use yb_core::{list_blobs, store::Store, Context};

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

    let all_blob_names: Vec<String> = list_blobs(&store).into_iter().map(|b| b.name).collect();

    // Resolve all patterns to a deduplicated list of blob names to remove.
    let to_remove = resolve_patterns(&args.patterns, &all_blob_names, args.ignore_missing)?;

    if to_remove.is_empty() {
        return Ok(());
    }

    // Mark all blobs for removal, then sync once (single write pass).
    let mgmt_key = ctx.management_key_for_write()?;
    for name in &to_remove {
        let chain = store
            .find_head(name)
            .map(|h| store.chunk_chain(h.index))
            .unwrap_or_default();
        for idx in chain {
            store.objects[idx as usize].reset();
        }
    }
    let pin = ctx.require_pin()?;
    store.sync(ctx.piv.as_ref(), mgmt_key.as_deref(), pin.as_deref())?;

    if !ctx.quiet {
        for name in &to_remove {
            eprintln!("Removed '{name}'");
        }
    }

    Ok(())
}
