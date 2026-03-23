// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
// SPDX-FileCopyrightText: 2025 - 2026 Thales Cloud Sécurisé
//
// SPDX-License-Identifier: MIT

use anyhow::Result;
use clap::Args;
use yb_core::{
    collect_blob_chain, parse_ec_public_key_from_cert_der, scan_nvm,
    store::{constants::OBJECT_ID_ZERO, Object, Store},
    Context,
};

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
// Signature verdict
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigVerdict {
    Verified,
    Unverified,
    Corrupted,
}

impl std::fmt::Display for SigVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SigVerdict::Verified => write!(f, "VERIFIED"),
            SigVerdict::Unverified => write!(f, "UNVERIFIED"),
            SigVerdict::Corrupted => write!(f, "CORRUPTED"),
        }
    }
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

    // Store header.
    let free = store.free_count();
    let store_bytes_used: usize = store.objects.iter().map(|o| o.object_size).sum();

    println!(
        "Store: {} objects, slot 0x{:02x}, age {}",
        store.object_count, store.store_key_slot, store.store_age
    );
    println!(
        "Blobs: {} stored, {} objects free (~{} bytes used by store)",
        stored, free, store_bytes_used
    );

    // Per-blob table.
    if stored > 0 {
        println!();
        for (head, verdict) in &blob_verdicts {
            println!("  {:<30} {}", head.blob_name, verdict);
        }
        println!();
        println!(
            "Integrity: {} verified, {} unverified, {} corrupted",
            sig_verified, sig_unverified, sig_corrupted
        );
    }

    // NVM breakdown — only when --nvm is requested.
    if args.nvm {
        let store_ids: std::collections::HashSet<u32> = (0..store.object_count)
            .map(|i| OBJECT_ID_ZERO + i as u32)
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
    let has_anomalies = if args.verbose {
        let warnings = detect_anomalies(&store);
        for w in &warnings {
            println!("WARNING: {w}");
        }

        println!();
        for obj in &store.objects {
            println!("Object {}:", obj.index);
            println!("  age:        {}", obj.age);
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
        !warnings.is_empty()
    } else {
        false
    };

    if sig_corrupted > 0 || has_anomalies {
        std::process::exit(1);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Signature check (spec 0017 §4)
// ---------------------------------------------------------------------------

/// Evaluate the spec 0017 verdict for a single blob.
pub fn check_blob_signature(
    head: &Object,
    store: &Store,
    verifying_key: Option<&p256::ecdsa::VerifyingKey>,
) -> SigVerdict {
    use yb_core::piv::session::raw_ecdsa_to_der;

    let blob_size = head.blob_size as usize;
    let (payload, trailing, has_supernumerary) = collect_blob_chain(head, store);
    let combined = payload.len() + trailing.len();

    // Apply the verdict table (spec 0017 §4, if/elif order).
    if combined < blob_size {
        return SigVerdict::Corrupted;
    }

    if trailing.is_empty() {
        return SigVerdict::Unverified;
    }

    if trailing.len() > 65 {
        if has_supernumerary || !trailing.iter().all(|&b| b == 0) {
            return SigVerdict::Corrupted;
        }
        return SigVerdict::Unverified;
    }

    if trailing.len() == 65 {
        match trailing[0] {
            0x00 => {
                if has_supernumerary || !trailing.iter().all(|&b| b == 0) {
                    return SigVerdict::Corrupted;
                }
                SigVerdict::Unverified
            }
            0x01 => {
                let vk = match verifying_key {
                    Some(k) => k,
                    None => return SigVerdict::Unverified,
                };
                let mut raw = [0u8; 64];
                raw.copy_from_slice(&trailing[1..65]);
                let der = raw_ecdsa_to_der(&raw);

                use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature};
                use sha2::{Digest, Sha256};

                let digest = Sha256::digest(&payload);
                let sig = match Signature::from_der(&der) {
                    Ok(s) => s,
                    Err(_) => return SigVerdict::Corrupted,
                };
                match vk.verify_prehash(&digest, &sig) {
                    Ok(()) => SigVerdict::Verified,
                    Err(_) => SigVerdict::Corrupted,
                }
            }
            _ => SigVerdict::Corrupted,
        }
    } else {
        // trailing.len() in (0, 65) — partial trailer region.
        if has_supernumerary || !trailing.iter().all(|&b| b == 0) {
            return SigVerdict::Corrupted;
        }
        SigVerdict::Unverified
    }
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
