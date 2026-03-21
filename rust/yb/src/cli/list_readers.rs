// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

use anyhow::Result;
use clap::Args;
use yb_core::{HardwarePiv, PivBackend as _, VirtualPiv};

#[derive(Args, Debug)]
pub struct ListReadersArgs {}

/// Run list-readers without constructing a Context (works when no YubiKey is connected).
pub fn run(_args: &ListReadersArgs) -> Result<()> {
    let readers = if let Ok(path) = std::env::var("YB_FIXTURE") {
        VirtualPiv::from_fixture(std::path::Path::new(&path))?.list_readers()?
    } else {
        HardwarePiv::new().list_readers()?
    };
    if readers.is_empty() {
        eprintln!("No PC/SC readers found.");
    } else {
        for r in &readers {
            println!("{r}");
        }
    }
    Ok(())
}
