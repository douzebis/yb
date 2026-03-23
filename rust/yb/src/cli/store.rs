// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
// SPDX-FileCopyrightText: 2025 - 2026 Thales Cloud Sécurisé
//
// SPDX-License-Identifier: MIT

use anyhow::{bail, Result};
use clap::Args;
use clap_complete::engine::{ArgValueCompleter, PathCompleter};
use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;
use yb_core::orchestrator::{self, Compression, Encryption, StoreOptions};
use yb_core::store::{constants::MAX_NAME_LEN, Store};
use yb_core::Context;

#[derive(Args, Debug)]
pub struct StoreArgs {
    /// Source files to store.  Blob name defaults to each file's basename.
    /// If no files are given, payload is read from stdin (requires --name).
    #[arg(add = ArgValueCompleter::new(PathCompleter::file()))]
    pub files: Vec<PathBuf>,

    /// Override blob name (required when reading from stdin; only valid with a single file).
    #[arg(short = 'n', long = "name")]
    pub name: Option<String>,

    /// Encrypt the blob (default).
    #[arg(
        short = 'e',
        long = "encrypted",
        default_value_t = true,
        overrides_with = "unencrypted"
    )]
    pub encrypted: bool,

    /// Store the blob unencrypted.
    #[arg(short = 'u', long = "unencrypted")]
    pub unencrypted: bool,

    /// Skip compression (useful for already-compressed data).
    #[arg(long = "no-compress")]
    pub no_compress: bool,
}

pub fn run(ctx: &Context, args: &StoreArgs) -> Result<()> {
    let encrypted = !args.unencrypted;
    let compression = match args.no_compress {
        true => Compression::None,
        false => Compression::Auto,
    };

    // Build list of (blob_name, payload) pairs.
    let entries: Vec<(String, Vec<u8>)> = if args.files.is_empty() {
        // Stdin mode: --name required.
        let name = args
            .name
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--name is required when reading from stdin"))?
            .to_owned();
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        vec![(name, buf)]
    } else {
        if args.name.is_some() && args.files.len() > 1 {
            bail!("--name can only be used with a single file");
        }
        let mut entries = Vec::with_capacity(args.files.len());
        for path in &args.files {
            let name = if let Some(ref n) = args.name {
                n.clone()
            } else {
                path.file_name()
                    .and_then(|n| n.to_str())
                    .map(|s| s.to_owned())
                    .ok_or_else(|| anyhow::anyhow!("cannot derive blob name from {:?}", path))?
            };
            let payload = std::fs::read(path)?;
            entries.push((name, payload));
        }

        // Detect basename collisions before writing anything.
        let mut seen: HashMap<&str, &PathBuf> = HashMap::new();
        for (i, (name, _)) in entries.iter().enumerate() {
            if let Some(prev) = seen.get(name.as_str()) {
                bail!(
                    "duplicate blob name '{}' from '{}' and '{}'",
                    name,
                    prev.display(),
                    args.files[i].display()
                );
            }
            seen.insert(name.as_str(), &args.files[i]);
        }

        entries
    };

    let mut store = Store::from_device(&ctx.reader, ctx.piv.as_ref())?;
    store.sanitize();

    let peer_pk = if encrypted {
        Some(ctx.get_public_key(store.store_key_slot)?)
    } else {
        None
    };

    let mgmt_key = ctx.management_key_for_write()?;

    // All-or-nothing capacity check (S2).
    let total_chunks: usize = entries
        .iter()
        .map(|(name, payload)| {
            let enc_len = if encrypted {
                // Approximate: actual encrypted size = payload + GCM overhead.
                payload.len() + yb_core::crypto::GCM_OVERHEAD
            } else {
                payload.len()
            };
            let name_len = name.len().min(MAX_NAME_LEN);
            yb_core::orchestrator::chunks_needed(enc_len, name_len, store.object_size)
        })
        .sum();

    // Blobs that already exist with the same name will have their chunks freed
    // before new ones are allocated, so don't count them against free capacity.
    let freed_chunks: usize = entries
        .iter()
        .filter_map(|(name, _)| store.find_head(name))
        .map(|head| store.chunk_chain(head.index()).len())
        .sum();

    if store.free_count() + freed_chunks < total_chunks {
        if entries.len() == 1 {
            bail!(
                "store is full — remove some blobs first (need {} slot(s), {} free)",
                total_chunks,
                store.free_count()
            );
        } else {
            bail!(
                "store is full — need {} slots for {} files, only {} free",
                total_chunks,
                entries.len(),
                store.free_count()
            );
        }
    }

    let pin = ctx.require_pin()?;
    for (name, payload) in &entries {
        let ok = orchestrator::store_blob(
            &mut store,
            ctx.piv.as_ref(),
            name,
            payload,
            StoreOptions {
                encryption: match peer_pk.as_ref() {
                    Some(pk) => Encryption::Encrypted(pk),
                    None => Encryption::None,
                },
                compression,
            },
            mgmt_key.as_deref(),
            pin.as_deref(),
        )?;
        if !ok {
            bail!(
                "store is full while writing '{}' — this should not happen",
                name
            );
        }
        if !ctx.quiet {
            eprintln!(
                "Stored '{}' ({} bytes{})",
                name,
                payload.len(),
                if encrypted { ", encrypted" } else { "" }
            );
        }
    }

    Ok(())
}
