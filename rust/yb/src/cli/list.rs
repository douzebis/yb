// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
// SPDX-FileCopyrightText: 2025 - 2026 Thales Cloud Sécurisé
//
// SPDX-License-Identifier: MIT

use anyhow::Result;
use chrono::{DateTime, Duration, Local, Utc};
use clap::Args;
use clap_complete::engine::ArgValueCompleter;
use globset::GlobBuilder;
use yb_core::{orchestrator, parse_ec_public_key_from_cert_der, store::Store, Context};

use crate::cli::util::{check_blob_signature, quote_name, SigVerdict};
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

    // Fetch verifying key from the store's key slot certificate — no PIN needed.
    let verifying_key = ctx
        .piv
        .read_certificate(&ctx.reader, store.store_key_slot)
        .ok()
        .and_then(|cert_der| parse_ec_public_key_from_cert_der(&cert_der).ok())
        .map(|pk| {
            use p256::ecdsa::VerifyingKey;
            VerifyingKey::from(&pk)
        });

    // Build a verdict map keyed by blob name.
    let heads: Vec<_> = store.objects.iter().filter(|o| o.is_head()).collect();
    let mut verdict_map: std::collections::HashMap<&str, SigVerdict> =
        std::collections::HashMap::new();
    for head in &heads {
        let v = check_blob_signature(head, &store, verifying_key.as_ref());
        verdict_map.insert(head.blob_name.as_str(), v);
    }

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

    let mut any_corrupted = false;
    for b in &blobs {
        let corrupted = verdict_map
            .get(b.name.as_str())
            .map(|v| *v == SigVerdict::Corrupted)
            .unwrap_or(false);
        if corrupted {
            any_corrupted = true;
        }
        let displayed_name = quote_name(&b.name);
        let suffix = if corrupted { "  CORRUPTED" } else { "" };
        if args.long {
            let enc_flag = if b.is_encrypted { '-' } else { 'P' };
            let date = format_mtime(b.mtime);
            println!(
                "{enc_flag} {:2}  {}  {:6}  {displayed_name}{suffix}",
                b.chunk_count, date, b.plain_size,
            );
        } else {
            println!("{displayed_name}{suffix}");
        }
    }

    if any_corrupted {
        std::process::exit(1);
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
