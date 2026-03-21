// SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

use anyhow::{bail, Result};
use clap::Args;
use clap_complete::engine::ArgValueCompleter;
use globset::GlobBuilder;
use yb_core::{list_blobs, store::Store, Context};

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

    let all_blobs: Vec<String> = list_blobs(&store).into_iter().map(|b| b.name).collect();

    // Resolve all patterns to a deduplicated list of blob names to remove.
    let mut to_remove: Vec<String> = Vec::new();
    for pattern in &args.patterns {
        let is_glob = pattern.chars().any(|c| matches!(c, '*' | '?' | '['));
        if is_glob {
            let glob = GlobBuilder::new(pattern)
                .case_insensitive(false)
                .build()?
                .compile_matcher();
            let hits: Vec<&str> = all_blobs
                .iter()
                .filter(|n| glob.is_match(n.as_str()))
                .map(|n| n.as_str())
                .collect();
            if hits.is_empty() {
                if args.ignore_missing {
                    continue;
                }
                bail!("pattern '{}' matched no blobs", pattern);
            }
            for name in hits {
                if !to_remove.iter().any(|n| n == name) {
                    to_remove.push(name.to_owned());
                }
            }
        } else {
            // Plain name: exact match.
            if !all_blobs.iter().any(|n| n == pattern) {
                if args.ignore_missing {
                    continue;
                }
                bail!("blob '{}' not found", pattern);
            }
            if !to_remove.iter().any(|n| n == pattern) {
                to_remove.push(pattern.clone());
            }
        }
    }

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
