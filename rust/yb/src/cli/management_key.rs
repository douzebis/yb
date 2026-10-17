// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! `yb management-key set` (spec 0028, D7): after the user changed the
//! YubiKey's management key (with ykman or another tool), store the new
//! one, wrapped by FIDO2, in the post-quantum store's descriptor.

use anyhow::{bail, Context as _, Result};
use clap::{Args, Subcommand};
use yb_core::auxiliaries::DEFAULT_MANAGEMENT_KEY;
use yb_core::errors::YbError;
use yb_core::store::Store;
use yb_core::{Context, Zeroizing};

#[derive(Args, Debug)]
pub struct ManagementKeyArgs {
    #[command(subcommand)]
    pub command: ManagementKeyCommand,
}

#[derive(Subcommand, Debug)]
pub enum ManagementKeyCommand {
    /// Tell yb the YubiKey's new management key (post-quantum stores),
    /// from YB_MANAGEMENT_KEY or a prompt.
    Set,
}

pub fn run(ctx: &Context, args: &ManagementKeyArgs) -> Result<()> {
    match args.command {
        ManagementKeyCommand::Set => set(ctx),
    }
}

#[cfg(windows)]
fn set(_: &Context) -> Result<()> {
    bail!("post-quantum stores are not supported on Windows")
}

#[cfg(not(windows))]
fn set(ctx: &Context) -> Result<()> {
    use yb_core::orchestrator::post_quantum::rewrap_management_key;

    let store = Store::from_device(&ctx.reader, ctx.piv.as_ref())?;
    let Some(descriptor) = store.descriptor() else {
        bail!(
            "`yb management-key set` is for post-quantum stores; legacy stores keep their key \
             in PRINTED (`yb rotate-management-key`)"
        );
    };
    let key = match ctx.management_key.clone() {
        Some(key) => key,
        None if atty::is(atty::Stream::Stderr) => Zeroizing::new(
            rpassword::prompt_password("New management key (hex): ")?
                .trim()
                .to_owned(),
        ),
        None => {
            return Err(YbError::new("the new management key is needed")
                .fix("set YB_MANAGEMENT_KEY, or run yb in a terminal")
                .into())
        }
    };
    if key.eq_ignore_ascii_case(DEFAULT_MANAGEMENT_KEY) {
        return Err(YbError::new("the management key is the factory default")
            .why("a post-quantum store uses the YubiKey's own management key")
            .fix("change it first, e.g. `ykman piv access change-management-key`")
            .into());
    }
    if ctx
        .piv
        .authenticate_management_key(&ctx.reader, &key)
        .is_err()
    {
        bail!("the YubiKey rejects this management key; nothing was changed");
    }
    if !ctx.quiet {
        eprintln!(
            "Note: if you did not change the management key yourself, the PIV application may \
             have been reset, and the store tampered with: check before going on."
        );
    }
    let algo = ctx.piv.management_key_algorithm(&ctx.reader)?;
    let session = ctx.post_quantum_session()?;
    rewrap_management_key(
        ctx.piv.as_ref(),
        &ctx.reader,
        descriptor,
        &session.device,
        session.pin(),
        &key,
        algo,
        &*ctx.on_touch,
    )
    .context("nothing was changed")?;
    if !ctx.quiet {
        eprintln!(
            "The store now uses the new management key ({}).",
            algo.name()
        );
    }
    Ok(())
}
