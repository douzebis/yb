// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

use anyhow::Result;
use clap::Args;
use yb_core::{
    store::{
        constants::{OBJECT_MAX_SIZE, YUBIKEY_NVM_BYTES},
        Store,
    },
    Context,
};

#[derive(Args, Debug)]
pub struct FsckArgs {
    /// Print full per-object dump in addition to the summary.
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,
}

pub fn run(ctx: &Context, args: &FsckArgs) -> Result<()> {
    let store = Store::from_device(&ctx.reader, ctx.piv.as_ref())?;

    if args.verbose {
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
    }

    // Detect anomalies.
    let warnings = detect_anomalies(&store);

    // Summary line.
    let stored = store.objects.iter().filter(|o| o.is_head()).count();
    let free = store.free_count();

    // Conservative free-byte estimate (spec 0010 §3.5):
    //   free_bytes = min(free_slots × MAX_OBJECT_SIZE, nvm_remaining)
    // where nvm_remaining = YUBIKEY_NVM_BYTES − sum of GET DATA response
    // lengths for all objects yb manages.
    let nvm_used: usize = store.objects.iter().map(|o| o.object_size).sum();
    let nvm_remaining = YUBIKEY_NVM_BYTES.saturating_sub(nvm_used);
    let free_bytes = (free * OBJECT_MAX_SIZE).min(nvm_remaining);

    println!(
        "Store: {} objects, slot 0x{:02x}, age {}",
        store.object_count, store.store_key_slot, store.store_age
    );
    println!(
        "Blobs: {} stored, {} objects free (~{} bytes available)",
        stored, free, free_bytes
    );

    if warnings.is_empty() {
        println!("Status: OK");
    } else {
        println!("Status: {} warning(s)", warnings.len());
        for w in &warnings {
            println!("  WARNING: {w}");
        }
        std::process::exit(1);
    }

    Ok(())
}

pub fn detect_anomalies(store: &Store) -> Vec<String> {
    use std::collections::{HashMap, HashSet};

    let mut warnings = Vec::new();

    // Find duplicate blob names (two head chunks with the same name).
    let mut name_map: HashMap<&str, Vec<u8>> = HashMap::new();
    for obj in store.objects.iter().filter(|o| o.is_head()) {
        name_map
            .entry(obj.blob_name.as_str())
            .or_default()
            .push(obj.index);
    }
    for (name, indices) in &name_map {
        if indices.len() > 1 {
            warnings.push(format!(
                "duplicate blob name '{}' in objects {:?}",
                name, indices
            ));
        }
    }

    // Collect reachable indices by following all head chains.
    let mut reachable: HashSet<u8> = HashSet::new();
    for obj in store.objects.iter().filter(|o| o.is_head()) {
        let chain = store.chunk_chain(obj.index);
        for idx in chain {
            reachable.insert(idx);
        }
    }

    // Any occupied non-head object not in a reachable chain is an orphan.
    for obj in store.objects.iter().filter(|o| !o.is_empty()) {
        if !reachable.contains(&obj.index) {
            warnings.push(format!(
                "object {} is an orphaned continuation chunk (no reachable head)",
                obj.index
            ));
        }
    }

    warnings
}
