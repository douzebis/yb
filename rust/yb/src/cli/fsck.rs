// SPDX-FileCopyrightText: 2025, 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

use anyhow::Result;
use clap::Args;
use std::collections::HashSet;
use std::io::Write;
use yb_core::{
    errors::YbError,
    parse_ec_public_key_from_cert_der,
    report::{CardReport, Severity, StorePresence},
    scan_nvm,
    store::{
        constants::{DEFAULT_KEY_SLOT, OBJECT_ID_ZERO},
        Object, Store,
    },
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

    /// Ask for the PIN and check that the key in the store slot matches
    /// its certificate.
    #[arg(long = "check-key")]
    pub check_key: bool,
}

// ---------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------

pub fn run(ctx: &Context, args: &FsckArgs) -> Result<()> {
    let healthy = check(ctx, args, &mut std::io::stdout().lock())?;
    if !healthy {
        std::process::exit(1);
    }
    Ok(())
}

/// Write the fsck report to `out`: the YubiKey section (spec 0023 §2),
/// then the store.  Returns `false` when the report has an error (exit
/// status 1).  Writes nothing to the card.
pub fn check(ctx: &Context, args: &FsckArgs, out: &mut dyn Write) -> Result<bool> {
    let presence = StorePresence::probe(&ctx.reader, ctx.piv.as_ref());
    let slot = match presence {
        StorePresence::Present(ref store) => store.store_key_slot,
        _ => DEFAULT_KEY_SLOT,
    };

    let mut report = CardReport::build(ctx, slot);
    // A certificate without a P-256 key is already reported as an error.
    if args.check_key && !report.slot.certificate_unusable() {
        if ctx.require_pin()?.is_none() {
            return Err(YbError::new("a PIN is needed for --check-key")
                .fix("set YB_PIN, use --pin-stdin, or run yb in a terminal")
                .into());
        }
        report.key_check = Some(ctx.check_slot_key(slot)?);
    }
    writeln!(out, "{}", report.render(Some("use --check-key")))?;
    let card_ok = report.severity() < Severity::Error;

    let store_ok = match presence {
        StorePresence::None => {
            writeln!(out, "Store: none — run `yb format` to create one")?;
            if args.nvm {
                write_nvm(ctx, &HashSet::new(), out)?;
            }
            true
        }
        StorePresence::Unreadable(reason) => {
            writeln!(out, "Store: unreadable ({reason})")?;
            false
        }
        StorePresence::Present(store) => check_store(ctx, args, &store, out)?,
    };
    Ok(card_ok && store_ok)
}

/// The store part of the report, unchanged since before spec 0023.
fn check_store(ctx: &Context, args: &FsckArgs, store: &Store, out: &mut dyn Write) -> Result<bool> {
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
        let verdict = check_blob_signature(head, store, verifying_key.as_ref());
        match verdict {
            SigVerdict::Verified => sig_verified += 1,
            SigVerdict::Unverified => sig_unverified += 1,
            SigVerdict::Corrupted => sig_corrupted += 1,
        }
        blob_verdicts.push((head, verdict));
    }

    // Store header — count only reachable (non-orphaned) objects as used.
    let reachable: HashSet<u8> = heads
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

    writeln!(
        out,
        "Store: {} objects, slot 0x{:02x}, age {}",
        store.object_count, store.store_key_slot, store.store_age
    )?;
    writeln!(
        out,
        "Blobs: {} stored, {} objects free (~{} bytes used by store)",
        stored, free_count, store_bytes_used
    )?;

    // Per-blob table.
    if stored > 0 {
        writeln!(out)?;
        for (head, verdict) in &blob_verdicts {
            writeln!(out, "  {:<30} {}", quote_name(&head.blob_name), verdict)?;
        }
        writeln!(out)?;
        writeln!(
            out,
            "Integrity: {} verified, {} unverified, {} corrupted",
            sig_verified, sig_unverified, sig_corrupted
        )?;
    }

    // NVM breakdown — only when --nvm is requested.
    if args.nvm {
        // Only count reachable slots as store NVM — orphans are treated as free.
        let store_ids: HashSet<u32> = reachable
            .iter()
            .map(|&i| OBJECT_ID_ZERO + i as u32)
            .collect();
        write_nvm(ctx, &store_ids, out)?;
    }

    // Structural anomalies — verbose only.
    let has_anomalies = args.verbose && {
        let warnings = detect_anomalies(store);
        for w in &warnings {
            writeln!(out, "WARNING: {w}")?;
        }

        writeln!(out)?;
        for obj in &store.objects {
            writeln!(out, "Object {}:", obj.index())?;
            writeln!(out, "  age:        {}", obj.age())?;
            if obj.age() == 0 {
                writeln!(out, "  (empty)")?;
            } else {
                writeln!(out, "  chunk_pos:  {}", obj.chunk_pos())?;
                writeln!(out, "  next_chunk: {}", obj.next_chunk())?;
                if obj.chunk_pos() == 0 {
                    writeln!(out, "  blob_name:      {}", obj.blob_name)?;
                    writeln!(out, "  blob_size:      {}", obj.blob_size)?;
                    writeln!(out, "  blob_plain_sz:  {}", obj.blob_plain_size)?;
                    writeln!(out, "  blob_key_slot:  0x{:02x}", obj.blob_key_slot)?;
                    writeln!(out, "  blob_mtime:     {}", obj.blob_mtime)?;
                    writeln!(
                        out,
                        "  encrypted:      {}",
                        if obj.is_encrypted() { "yes" } else { "no" }
                    )?;
                }
                writeln!(out, "  payload_len: {}", obj.payload_len())?;
            }
            writeln!(out)?;
        }
        !warnings.is_empty()
    };

    Ok(sig_corrupted == 0 && !has_anomalies)
}

/// The `--nvm` line.  `store_ids` are the objects counted as store.
fn write_nvm(ctx: &Context, store_ids: &HashSet<u32>, out: &mut dyn Write) -> Result<()> {
    match scan_nvm(&ctx.reader, ctx.piv.as_ref(), store_ids) {
        Ok(usage) => writeln!(
            out,
            "NVM: ~{} bytes store  |  ~{} bytes other  |  ~{} bytes free (estimated)",
            usage.store_bytes, usage.other_bytes, usage.free_bytes
        )?,
        Err(e) => eprintln!("yb: warning: NVM scan failed: {e}"),
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
