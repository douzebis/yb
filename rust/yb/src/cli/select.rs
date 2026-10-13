// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! `yb select` — interactively pick a YubiKey and print its serial number.
//!
//! Intended for scripting: `yb --serial "$(yb select)" store myfile`

use anyhow::{bail, Result};
use clap::Args;
use yb_core::open_backend;

#[derive(Args, Debug)]
pub struct SelectArgs {
    /// Print the reader name instead of the serial number.
    #[arg(long = "reader")]
    pub reader: bool,
}

pub fn run(args: &SelectArgs) -> Result<()> {
    let piv = open_backend()?;

    let devices = piv.list_devices()?;

    let selected = match devices.len() {
        0 => bail!("no YubiKey found"),
        1 => devices.into_iter().next().unwrap(),
        _ => {
            if !atty::is(atty::Stream::Stderr) {
                bail!("multiple YubiKeys found and no TTY — use --serial to select one");
            }
            match super::picker::run_picker(&piv, &devices)? {
                Some((d, _flash)) => d,
                None => bail!("device selection cancelled"),
            }
        }
    };

    if args.reader {
        println!("{}", selected.reader);
    } else {
        println!("{}", selected.serial);
    }
    Ok(())
}
