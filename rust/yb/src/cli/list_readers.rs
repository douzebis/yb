// SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

use anyhow::Result;
use clap::Args;
use yb_core::{HardwarePiv, PivBackend as _};

#[derive(Args, Debug)]
pub struct ListReadersArgs {}

/// Run list-readers without constructing a Context (works when no YubiKey is connected).
pub fn run(_args: &ListReadersArgs) -> Result<()> {
    let piv = HardwarePiv::new();
    let readers = piv.list_readers()?;
    if readers.is_empty() {
        eprintln!("No PC/SC readers found.");
    } else {
        for r in &readers {
            println!("{r}");
        }
    }
    Ok(())
}
