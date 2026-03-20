// SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

use anyhow::Result;
use chrono::{DateTime, Local, Utc};
use clap::Args;
use globset::GlobBuilder;
use yb_core::orchestrator;
use yb_core::{store::Store, Context};

#[derive(Args, Debug)]
pub struct ListArgs {
    /// Glob pattern to filter blob names (default: all).
    pub pattern: Option<String>,
}

pub fn run(ctx: &Context, args: &ListArgs) -> Result<()> {
    let matcher = match &args.pattern {
        Some(pat) => {
            let glob = GlobBuilder::new(pat)
                .case_insensitive(false)
                .build()?
                .compile_matcher();
            Some(glob)
        }
        None => None,
    };

    let store = Store::from_device(&ctx.reader, ctx.piv.as_ref())?;
    let blobs = orchestrator::list_blobs(&store);

    let blobs: Vec<_> = blobs
        .iter()
        .filter(|b| {
            matcher
                .as_ref()
                .map(|m| m.is_match(&b.name))
                .unwrap_or(true)
        })
        .collect();

    for b in blobs {
        let enc_flag = if b.is_encrypted { '-' } else { 'U' };
        let date = format_mtime(b.mtime);
        println!(
            "{enc_flag} {:02}  {:>8}  {}  {}",
            b.chunk_count, b.plain_size, date, b.name
        );
    }

    Ok(())
}

fn format_mtime(unix: u32) -> String {
    if unix == 0 {
        return "            ".to_owned();
    }
    let dt: DateTime<Local> =
        DateTime::from(DateTime::<Utc>::from_timestamp(unix as i64, 0).unwrap());
    dt.format("%b %e %H:%M").to_string()
}
