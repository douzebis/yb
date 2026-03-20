// SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

use anyhow::{bail, Result};
use clap::Args;
use std::io::Write as _;
use std::path::PathBuf;
use yb_core::orchestrator;
use yb_core::{store::Store, Context};

#[derive(Args, Debug)]
pub struct FetchArgs {
    /// Blob name(s) to retrieve.
    #[arg(required = true)]
    pub names: Vec<String>,

    /// Write output to this file (only valid with a single blob name).
    #[arg(short = 'o', long = "output")]
    pub output: Option<PathBuf>,

    /// Extract each blob to a file named after the blob.
    #[arg(short = 'x', long = "extract")]
    pub extract: bool,
}

pub fn run(ctx: &Context, args: &FetchArgs) -> Result<()> {
    if args.output.is_some() && args.names.len() > 1 {
        bail!("--output can only be used with a single blob name");
    }
    if args.output.is_some() && args.extract {
        bail!("--output and --extract are mutually exclusive");
    }

    let store = Store::from_device(&ctx.reader, ctx.piv.as_ref())?;
    // store.sanitize() is read-only here; do it on a clone if needed.

    for name in &args.names {
        let pin = ctx.pin.as_deref();
        let data =
            orchestrator::fetch_blob(&store, ctx.piv.as_ref(), name, ctx.serial, pin, ctx.debug)?
                .ok_or_else(|| anyhow::anyhow!("blob '{name}' not found"))?;

        if args.extract {
            std::fs::write(name, &data)?;
            eprintln!("Extracted '{name}' ({} bytes)", data.len());
        } else if let Some(ref path) = args.output {
            std::fs::write(path, &data)?;
        } else {
            std::io::stdout().write_all(&data)?;
        }
    }
    Ok(())
}
