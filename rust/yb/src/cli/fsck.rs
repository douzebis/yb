// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
// SPDX-FileCopyrightText: 2025 - 2026 Thales Cloud Sécurisé
//
// SPDX-License-Identifier: MIT

use anyhow::Result;
use clap::Args;
use yb_core::{
    parse_ec_public_key_from_cert_der, scan_nvm,
    store::{constants::OBJECT_ID_ZERO, Object, Store},
    Context,
};

use crate::cli::util::{check_blob_signature, quote_name, SigVerdict};

#[derive(Args, Debug)]
pub struct FsckArgs {
    /// Print full per-object dump in addition to the summary.
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,

    /// Scan all PIV objects to report NVM usage (store / other / free).
    /// Issues ~290 read-only APDUs; may take a few seconds on real hardware.
    #[arg(long = "nvm")]
    pub nvm: bool,
}

// ---------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------

pub fn run(ctx: &Context, args: &FsckArgs) -> Result<()> {
    let store = Store::from_device(&ctx.reader, ctx.piv.as_ref())?;

    // Fetch public key from the store's key slot certificate — no PIN needed.
    let verifying_key = ctx
        .piv
        .read_certificate(&ctx.reader, store.store_key_slot)
        .ok()
        .and_then(|cert_der| parse_ec_public_key_from_cert_der(&cert_der).ok())
        .map(|pk| {
            use p256::ecdsa::VerifyingKey;
            VerifyingKey::from(&pk)
        });

    let heads: Vec<&Object> = store.objects.iter().filter(|o| o.is_head()).collect();
    let stored = heads.len();

    // Per-blob signature verdicts.
    let mut sig_verified = 0usize;
    let mut sig_unverified = 0usize;
    let mut sig_corrupted = 0usize;

    let mut blob_verdicts: Vec<(&Object, SigVerdict)> = Vec::new();
    for head in &heads {
        let verdict = check_blob_signature(head, &store, verifying_key.as_ref());
        match verdict {
            SigVerdict::Verified => sig_verified += 1,
            SigVerdict::Unverified => sig_unverified += 1,
            SigVerdict::Corrupted => sig_corrupted += 1,
        }
        blob_verdicts.push((head, verdict));
    }

    // Store header — count only reachable (non-orphaned) objects as used.
    let reachable: std::collections::HashSet<u8> = heads
        .iter()
        .flat_map(|h| store.chunk_chain(h.index()))
        .collect();
    let free_count = store
        .objects
        .iter()
        .filter(|o| o.is_empty() || !reachable.contains(&o.index()))
        .count();
    let store_bytes_used: usize = store
        .objects
        .iter()
        .filter(|o| reachable.contains(&o.index()))
        .map(|o| o.object_size())
        .sum();

    println!(
        "Store: {} objects, slot 0x{:02x}, age {}",
        store.object_count, store.store_key_slot, store.store_age
    );
    println!(
        "Blobs: {} stored, {} objects free (~{} bytes used by store)",
        stored, free_count, store_bytes_used
    );

    // Per-blob table.
    if stored > 0 {
        println!();
        for (head, verdict) in &blob_verdicts {
            println!("  {:<30} {}", quote_name(&head.blob_name), verdict);
        }
        println!();
        println!(
            "Integrity: {} verified, {} unverified, {} corrupted",
            sig_verified, sig_unverified, sig_corrupted
        );
    }

    // NVM breakdown — only when --nvm is requested.
    if args.nvm {
        // Only count reachable slots as store NVM — orphans are treated as free.
        let store_ids: std::collections::HashSet<u32> = reachable
            .iter()
            .map(|&i| OBJECT_ID_ZERO + i as u32)
            .collect();
        match scan_nvm(&ctx.reader, ctx.piv.as_ref(), &store_ids) {
            Ok(usage) => println!(
                "NVM: ~{} bytes store  |  ~{} bytes other  |  ~{} bytes free (estimated)",
                usage.store_bytes, usage.other_bytes, usage.free_bytes
            ),
            Err(e) => eprintln!("yb: warning: NVM scan failed: {e}"),
        }
    }

    // Structural anomalies — verbose only.
    let has_anomalies = args.verbose && {
        let warnings = detect_anomalies(&store);
        for w in &warnings {
            println!("WARNING: {w}");
        }

        println!();
        for obj in &store.objects {
            println!("Object {}:", obj.index());
            println!("  age:        {}", obj.age());
            if obj.age() == 0 {
                println!("  (empty)");
            } else {
                println!("  chunk_pos:  {}", obj.chunk_pos());
                println!("  next_chunk: {}", obj.next_chunk());
                if obj.chunk_pos() == 0 {
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
                println!("  payload_len: {}", obj.payload_len());
            }
            println!();
        }
        !warnings.is_empty()
    };

    if sig_corrupted > 0 || has_anomalies {
        std::process::exit(1);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Structural anomaly detection
// ---------------------------------------------------------------------------

pub fn detect_anomalies(store: &Store) -> Vec<String> {
    use std::collections::{HashMap, HashSet};

    let mut warnings = Vec::new();

    // Find duplicate blob names (two head chunks with the same name).
    let mut name_map: HashMap<&str, Vec<u8>> = HashMap::new();
    for obj in store.objects.iter().filter(|o| o.is_head()) {
        name_map
            .entry(obj.blob_name.as_str())
            .or_default()
            .push(obj.index());
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
        let chain = store.chunk_chain(obj.index());
        for idx in chain {
            reachable.insert(idx);
        }
    }

    // Any occupied non-head object not in a reachable chain is an orphan.
    for obj in store.objects.iter().filter(|o| !o.is_empty()) {
        if !reachable.contains(&obj.index()) {
            warnings.push(format!(
                "object {} is an orphaned continuation chunk (no reachable head)",
                obj.index()
            ));
        }
    }

    warnings
}
