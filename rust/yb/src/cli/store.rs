// SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

use anyhow::{bail, Result};
use clap::Args;
use std::io::Read;
use std::path::PathBuf;
use yb_core::orchestrator;
use yb_core::{store::Store, Context};

#[derive(Args, Debug)]
pub struct StoreArgs {
    /// Blob name (defaults to the basename of --input).
    pub name: Option<String>,

    /// Input file (reads from stdin if omitted).
    #[arg(short = 'i', long = "input")]
    pub input: Option<PathBuf>,

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
}

pub fn run(ctx: &Context, args: &StoreArgs) -> Result<()> {
    let encrypted = !args.unencrypted;

    // Read payload.
    let payload = match &args.input {
        Some(path) => std::fs::read(path)?,
        None => {
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf)?;
            buf
        }
    };

    // Determine blob name.
    let name = match &args.name {
        Some(n) => n.clone(),
        None => match &args.input {
            Some(p) => p
                .file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.to_owned())
                .ok_or_else(|| anyhow::anyhow!("cannot derive blob name from input path"))?,
            None => bail!("blob name required when reading from stdin"),
        },
    };

    let mut store = Store::from_device(&ctx.reader, ctx.piv.as_ref())?;
    store.sanitize();

    let peer_pk = if encrypted {
        Some(ctx.get_public_key(store.store_key_slot)?)
    } else {
        None
    };

    let mgmt_key = ctx.management_key_for_write()?;

    let ok = orchestrator::store_blob(
        &mut store,
        ctx.piv.as_ref(),
        &name,
        &payload,
        encrypted,
        peer_pk.as_ref(),
        mgmt_key.as_deref(),
        ctx.pin.as_deref(),
    )?;

    if !ok {
        bail!("store is full — remove some blobs first");
    }

    eprintln!(
        "Stored '{name}' ({} bytes{})",
        payload.len(),
        if encrypted { ", encrypted" } else { "" }
    );
    Ok(())
}
