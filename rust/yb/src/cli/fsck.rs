// SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

use anyhow::Result;
use clap::Args;
use yb_core::{store::Store, Context};

#[derive(Args, Debug)]
pub struct FsckArgs {}

pub fn run(ctx: &Context, _args: &FsckArgs) -> Result<()> {
    let store = Store::from_device(&ctx.reader, ctx.piv.as_ref())?;

    println!("Store:");
    println!("  object_count:   {}", store.object_count);
    println!("  object_size:    {}", store.object_size);
    println!("  store_key_slot: 0x{:02x}", store.store_key_slot);
    println!("  store_age:      {}", store.store_age);
    println!();

    for obj in &store.objects {
        println!("Object {}:", obj.index);
        println!("  age:       {}", obj.age);
        if obj.age == 0 {
            println!("  (empty)");
        } else {
            println!("  chunk_pos:  {}", obj.chunk_pos);
            println!("  next_chunk: {}", obj.next_chunk);
            if obj.chunk_pos == 0 {
                println!("  blob_name:      {}", obj.blob_name);
                println!("  blob_size:      {}", obj.blob_size);
                println!("  blob_plain_sz:  {}", obj.blob_plain_size);
                println!("  blob_key_slot:  0x{:02x}", obj.blob_key_slot);
                println!("  blob_mtime:     {}", obj.blob_mtime);
                println!(
                    "  encrypted:      {}",
                    if obj.is_encrypted() { "yes" } else { "no" }
                );
            }
            println!("  payload_len: {}", obj.payload.len());
        }
        println!();
    }

    Ok(())
}
