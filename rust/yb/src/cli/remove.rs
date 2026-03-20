// SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

use anyhow::{bail, Result};
use clap::Args;
use yb_core::orchestrator;
use yb_core::{store::Store, Context};

#[derive(Args, Debug)]
pub struct RemoveArgs {
    /// Name of the blob to remove.
    pub name: String,
}

pub fn run(ctx: &Context, args: &RemoveArgs) -> Result<()> {
    let mut store = Store::from_device(&ctx.reader, ctx.piv.as_ref())?;
    store.sanitize();

    let mgmt_key = ctx.management_key_for_write()?;

    let removed = orchestrator::remove_blob(
        &mut store,
        ctx.piv.as_ref(),
        &args.name,
        mgmt_key.as_deref(),
        ctx.pin.as_deref(),
    )?;

    if !removed {
        bail!("blob '{}' not found", args.name);
    }

    eprintln!("Removed '{}'", args.name);
    Ok(())
}
