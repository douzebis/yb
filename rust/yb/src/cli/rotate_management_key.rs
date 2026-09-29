// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! `yb rotate-management-key` (spec 0027): replace the management key with
//! a random one, kept on the YubiKey and unlocked by the PIN, without
//! touching the store.

use anyhow::{Context as _, Result};
use clap::Args;
use yb_core::{
    auxiliaries::{
        enable_pin_protected_management_key, generate_random_management_key, KeySwitch,
        ProtectionMode,
    },
    errors::YbError,
    Context, SecretOp,
};

use crate::cli::util::read_back_hint;

#[derive(Args, Debug, Default)]
pub struct RotateManagementKeyArgs {}

pub fn run(ctx: &Context, _args: &RotateManagementKeyArgs) -> Result<()> {
    let (old_key, old_key_in_printed, was_stored) =
        preflight(ctx).context("nothing was changed on the YubiKey")?;

    // The switch: spec 0022 B1, keeping the card's algorithm (spec 0021 §3).
    let (reader, piv) = (ctx.reader.as_str(), ctx.piv.as_ref());
    let algo = piv.management_key_algorithm(reader)?;
    let new_key = generate_random_management_key(algo);
    enable_pin_protected_management_key(
        reader,
        piv,
        &KeySwitch {
            old_key: &old_key,
            old_key_in_printed,
            new_key: &new_key,
            algo,
            clearing_legacy_flag: ctx.protection == ProtectionMode::LegacyOrPukBlocked,
        },
    )?;

    if !ctx.quiet {
        if was_stored {
            eprintln!("Management key rotated ({algo}).");
        } else {
            eprintln!(
                "Management key replaced, and now kept on the YubiKey, unlocked by your \
                 PIN ({algo})."
            );
        }
        eprintln!("{}", read_back_hint());
    }
    Ok(())
}

/// Spec 0027 §2: checks that write nothing.  Returns the current key,
/// whether PRINTED holds it (§3a), and whether it is already stored there
/// (spec 0023 §3a).
fn preflight(ctx: &Context) -> Result<(String, bool, bool)> {
    ctx.ensure_supported_protection()?;
    ctx.enforce_default_policy(SecretOp::RotateManagementKey)?;
    let pin = ctx.require_pin()?.ok_or_else(|| {
        YbError::new("a PIN is needed to change the management key")
            .fix("set YB_PIN, use --pin-stdin, or run yb in a terminal")
    })?;
    ctx.piv.verify_pin(&ctx.reader, &pin)?;
    let old_key = ctx.management_key_for_write()?;
    let old_key_in_printed = ctx.management_key_in_printed()?;
    let was_stored = ctx.management_key_protected()?;
    Ok((old_key, old_key_in_printed, was_stored))
}
