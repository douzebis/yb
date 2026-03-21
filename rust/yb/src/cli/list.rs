// SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

use anyhow::Result;
use chrono::{DateTime, Duration, Local, Utc};
use clap::Args;
use clap_complete::engine::ArgValueCompleter;
use globset::GlobBuilder;
use yb_core::orchestrator;
use yb_core::{store::Store, Context};

use crate::complete::complete_blob_names;

#[derive(Args, Debug)]
pub struct ListArgs {
    /// Glob pattern to filter blob names (default: all).
    #[arg(add = ArgValueCompleter::new(complete_blob_names))]
    pub pattern: Option<String>,

    /// Long format: flag, chunks, date, size, name.
    #[arg(short = 'l', long = "long")]
    pub long: bool,

    /// One name per line (default; explicit flag for scripting).
    #[arg(short = '1')]
    pub one_per_line: bool,

    /// Sort by modification time, newest first.
    #[arg(short = 't', long = "sort-time")]
    pub sort_time: bool,

    /// Reverse the sort order.
    #[arg(short = 'r', long = "reverse")]
    pub reverse: bool,
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
    let mut blobs = orchestrator::list_blobs(&store);

    // Filter.
    if let Some(ref m) = matcher {
        blobs.retain(|b| m.is_match(&b.name));
    }

    // Sort.
    if args.sort_time {
        blobs.sort_by(|a, b| b.mtime.cmp(&a.mtime)); // newest first
    }
    // Default sort (by name ascending) is already applied by list_blobs.

    if args.reverse {
        blobs.reverse();
    }

    for b in &blobs {
        if args.long {
            let enc_flag = if b.is_encrypted { '-' } else { 'P' };
            let date = format_mtime(b.mtime);
            println!(
                "{enc_flag} {:2}  {}  {:6}  {}",
                b.chunk_count, date, b.plain_size, b.name
            );
        } else {
            println!("{}", b.name);
        }
    }

    Ok(())
}

fn format_mtime(unix: u32) -> String {
    if unix == 0 {
        return "            ".to_owned();
    }
    let dt: DateTime<Local> =
        DateTime::from(DateTime::<Utc>::from_timestamp(unix as i64, 0).unwrap());
    let now = Local::now();
    if now.signed_duration_since(dt) < Duration::days(180) {
        dt.format("%b %e %H:%M").to_string()
    } else {
        dt.format("%b %e  %Y").to_string()
    }
}
