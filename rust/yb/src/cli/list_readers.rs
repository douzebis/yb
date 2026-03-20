// SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

use crate::context::Context;
use anyhow::Result;
use clap::Args;

#[derive(Args, Debug)]
pub struct ListReadersArgs {}

pub fn run(ctx: &Context, _args: &ListReadersArgs) -> Result<()> {
    let readers = ctx.piv.list_readers()?;
    if readers.is_empty() {
        eprintln!("No PC/SC readers found.");
    } else {
        for r in &readers {
            println!("{r}");
        }
    }
    Ok(())
}
