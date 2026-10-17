// SPDX-FileCopyrightText: 2025, 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

use anyhow::Result;
use clap::Args;
use std::collections::HashSet;
use std::io::Write;
use yb_core::{
    errors::YbError,
    orchestrator::uses_legacy_encryption,
    parse_ec_public_key_from_cert_der,
    report::{CardReport, Fido2Report, ReportStore, Severity, StorePresence},
    scan_nvm,
    store::{
        constants::{DEFAULT_KEY_SLOT, OBJECT_ID_ZERO},
        Object, Store, MAX_AGE,
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

    /// Post-quantum stores: also check, with the FIDO2 PIN, the store's
    /// credential and the management key (one touch), then every blob's
    /// seal (one touch per blob).  Without it, fsck asks for nothing.
    #[arg(long = "seals")]
    pub seals: bool,
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
    let post_quantum =
        matches!(&presence, StorePresence::Present(store) if store.kind.is_post_quantum());

    let mut report = CardReport::build(ctx, slot);
    // Each application's role (spec 0045); a post-quantum store has no
    // store slot (spec 0028).
    report.store = match &presence {
        StorePresence::Present(_) if post_quantum => ReportStore::PostQuantum,
        StorePresence::Present(_) => ReportStore::Legacy,
        _ => ReportStore::None,
    };
    if let StorePresence::Present(store) = &presence {
        if let Some(descriptor) = store.descriptor() {
            report.fido2 = Some(Fido2Report {
                state: yb_core::report::fido2_state(ctx),
                credential_id_len: descriptor.credential_id.len(),
                checked_below: args.seals,
                unencrypted_blobs: store
                    .objects
                    .iter()
                    .any(|o| o.is_head() && !o.is_encrypted()),
            });
        }
    }
    // A certificate without a P-256 key is already reported as an error.
    if args.check_key && !post_quantum && !report.slot.certificate_unusable() {
        if ctx.require_pin()?.is_none() {
            return Err(YbError::new("a PIN is needed for --check-key")
                .fix("set YB_PIN, use --pin-stdin, or run yb in a terminal")
                .into());
        }
        report.key_check = Some(ctx.check_slot_key(slot)?);
    }
    let hint = (!post_quantum).then_some("use --check-key");
    writeln!(out, "{}", report.render(hint, true))?;
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
        StorePresence::Present(store) if post_quantum => {
            check_post_quantum_store(ctx, args, &store, out)?
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
    let mut sig_unsigned = 0usize;
    let mut sig_unverifiable = 0usize;
    let mut sig_newer = 0usize;
    let mut sig_corrupted = 0usize;
    let mut legacy = 0usize;

    let mut blob_verdicts: Vec<(&Object, SigVerdict)> = Vec::new();
    for head in &heads {
        let verdict = check_blob_signature(head, store, verifying_key.as_ref());
        match verdict {
            // Post-quantum stores (spec 0028) get their own report in
            // `yb fsck`; the legacy check never gives a checksum verdict.
            SigVerdict::Verified | SigVerdict::ChecksumOk => sig_verified += 1,
            SigVerdict::Unsigned => sig_unsigned += 1,
            SigVerdict::Unverifiable => sig_unverifiable += 1,
            SigVerdict::NewerVersion => sig_newer += 1,
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
        "Store: legacy, {} objects, age {}",
        store.object_count, store.store_age
    )?;
    writeln!(
        out,
        "  {:<16} {} stored, {} objects free (~{} bytes used by the store)",
        "Blobs", stored, free_count, store_bytes_used
    )?;

    // Ages are 24-bit; a store must be reformatted before they run out
    // (spec 0034 G6).
    if store.store_age > MAX_AGE / 10 * 9 {
        writeln!(
            out,
            "warning: the store is at age {} of {MAX_AGE}; stores fail when ages run \
             out: fetch the blobs, reformat, store them again",
            store.store_age
        )?;
    }

    // Objects a write that ran out of card memory deleted (spec 0038).
    for &idx in &store.missing {
        writeln!(
            out,
            "warning: object 0x{:06X} is absent from the card (a write ran out of card \
             memory); the next write recreates it",
            OBJECT_ID_ZERO + u32::from(idx)
        )?;
    }

    // Objects recording another object count than object 0 do not belong
    // to this store; yb ignores them (spec 0034 G7).
    let foreign: Vec<&Object> = store
        .objects
        .iter()
        .filter(|o| o.object_count() != store.object_count)
        .collect();
    for obj in &foreign {
        writeln!(
            out,
            "error: object {} records a store of {} objects, not {}: not part of this \
             store, ignored",
            obj.index(),
            obj.object_count(),
            store.object_count
        )?;
    }

    // Per-blob table.
    if stored > 0 {
        writeln!(out)?;
        for (head, verdict) in &blob_verdicts {
            // LEGACY: the encryption before spec 0006 (spec 0034 G4).
            let marker = if *verdict != SigVerdict::Corrupted && uses_legacy_encryption(head) {
                legacy += 1;
                "  LEGACY"
            } else {
                ""
            };
            writeln!(
                out,
                "  {:<30} {verdict}{marker}",
                quote_name(&head.blob_name)
            )?;
        }
        writeln!(out)?;
        writeln!(
            out,
            "Integrity: {} verified, {} unsigned, {} corrupted (signatures need no PIN)",
            sig_verified, sig_unsigned, sig_corrupted
        )?;
        if sig_unverifiable > 0 {
            writeln!(
                out,
                "  {sig_unverifiable} signed blob(s) not checked: no certificate in the store's key slot"
            )?;
        }
        if sig_newer > 0 {
            writeln!(
                out,
                "  {sig_newer} blob(s) not checked: signed by a newer version of yb (update yb \
                 to check them)"
            )?;
        }
        if legacy > 0 {
            writeln!(
                out,
                "  {legacy} blob(s) LEGACY: encrypted as by older yb versions (AES-CBC, \
                 unauthenticated); store them again to protect them with AES-GCM"
            )?;
        }
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

    Ok(sig_corrupted == 0 && foreign.is_empty() && !has_anomalies)
}

/// The `--nvm` line.  `store_ids` are the objects counted as store.
/// The store part of the report for a post-quantum store (spec 0028): the
/// descriptor, each blob's checksum (no PIN), then the credential and the
/// management key (FIDO2 PIN, one touch), and with `--seals` each blob's
/// seal (one touch per blob).  Writes nothing to the card.
#[cfg(not(windows))]
fn check_post_quantum_store(
    ctx: &Context,
    args: &FsckArgs,
    store: &Store,
    out: &mut dyn Write,
) -> Result<bool> {
    use yb_core::orchestrator::post_quantum::quick_check;
    use yb_core::orchestrator::SigVerdict;

    let descriptor = store.descriptor().expect("a post-quantum store");
    let heads: Vec<&Object> = store.objects.iter().filter(|o| o.is_head()).collect();
    let reachable: HashSet<u8> = heads
        .iter()
        .flat_map(|h| store.chunk_chain(h.index()))
        .collect();
    let free_count = store
        .objects
        .iter()
        .filter(|o| o.is_empty() || !reachable.contains(&o.index()))
        .count();
    writeln!(
        out,
        "Store: post-quantum, {} objects, age {}",
        store.object_count, store.store_age
    )?;
    let not_checked = if args.seals {
        ""
    } else {
        "; not checked against the card"
    };
    writeln!(
        out,
        "  {:<16} a copy, wrapped by FIDO2 ({}){not_checked}",
        "Management key",
        descriptor.mgmt_algo.name()
    )?;
    writeln!(
        out,
        "  {:<16} {} stored, {} objects free",
        "Blobs",
        heads.len(),
        free_count
    )?;
    for &idx in &store.missing {
        writeln!(
            out,
            "warning: object 0x{:06X} is absent from the card (a write ran out of card \
             memory); the next write recreates it",
            store.object_id(idx)
        )?;
    }

    let mut healthy = true;
    if !heads.is_empty() {
        writeln!(out)?;
        let mut corrupted = 0;
        for head in &heads {
            let verdict = quick_check(head, store);
            if verdict == SigVerdict::Corrupted {
                corrupted += 1;
            }
            writeln!(out, "  {:<30} {verdict}", quote_name(&head.blob_name))?;
        }
        writeln!(out)?;
        writeln!(
            out,
            "Integrity: {} checksum OK, {corrupted} corrupted (checksums need no PIN)",
            heads.len() - corrupted
        )?;
        healthy &= corrupted == 0;
    }

    if !args.seals {
        writeln!(
            out,
            "Not checked: the credential, the management key, the seals —\n  `yb fsck \
             --seals` checks them (FIDO2 PIN, one touch, then one per blob)"
        )?;
    } else {
        // Prompts go to standard error while the checks run; the section
        // is printed whole once they are done (spec 0045 S3).
        let mut lines = Vec::new();
        healthy &= check_with_fido2(ctx, store, descriptor, &heads, &mut lines);
        writeln!(out, "Checked with the FIDO2 PIN:")?;
        for (label, text) in lines {
            writeln!(out, "  {label:<16} {text}")?;
        }
    }

    if args.nvm {
        let mut store_ids: HashSet<u32> = reachable.iter().map(|&i| store.object_id(i)).collect();
        store_ids.insert(OBJECT_ID_ZERO);
        write_nvm(ctx, &store_ids, out)?;
    }
    Ok(healthy)
}

/// The checks that need the FIDO2 PIN (`fsck --seals`, spec 0045 S3): the
/// credential and the management key (one touch), then each blob's seal
/// (one touch each).  Fills `lines` with (label, result); returns whether
/// all passed.
#[cfg(not(windows))]
fn check_with_fido2(
    ctx: &Context,
    store: &Store,
    descriptor: &yb_core::store::Descriptor,
    heads: &[&Object],
    lines: &mut Vec<(String, String)>,
) -> bool {
    use yb_core::fido2::Fido2Error;
    use yb_core::orchestrator::fetch_blob_with;
    use yb_core::orchestrator::post_quantum::IntegrityError;
    let error = |e: &anyhow::Error| format!("ERROR: {e:#}");
    let session = match ctx.post_quantum_session() {
        Ok(session) => session,
        Err(e) => {
            lines.push(("FIDO2".to_owned(), error(&e)));
            return false;
        }
    };
    let protection = session.protection(ctx, descriptor);
    match protection.management_key() {
        Ok(_) => {
            lines.push(("Credential".to_owned(), "answers".to_owned()));
            lines.push(("Management key".to_owned(), "matches the card".to_owned()));
        }
        Err(e) => {
            let mismatch = e
                .downcast_ref::<IntegrityError>()
                .is_some_and(|i| *i == IntegrityError::ManagementKeyMismatch);
            let no_credential = e
                .downcast_ref::<Fido2Error>()
                .is_some_and(|f| *f == Fido2Error::NoCredential);
            if mismatch {
                lines.push(("Credential".to_owned(), "answers".to_owned()));
                lines.push(("Management key".to_owned(), error(&e)));
            } else if no_credential {
                lines.push(("Credential".to_owned(), error(&e)));
            } else {
                lines.push(("FIDO2".to_owned(), error(&e)));
            }
            return false;
        }
    }
    let mut healthy = true;
    for head in heads {
        let name = quote_name(&head.blob_name);
        match fetch_blob_with(store, &protection, &head.blob_name) {
            Ok(_) => lines.push((name, "seal OK".to_owned())),
            Err(e) => {
                lines.push((name, error(&e)));
                healthy = false;
            }
        }
    }
    healthy
}

#[cfg(windows)]
fn check_post_quantum_store(
    _: &Context,
    _: &FsckArgs,
    _: &Store,
    out: &mut dyn Write,
) -> Result<bool> {
    writeln!(out, "Store: post-quantum (not supported on Windows)")?;
    Ok(false)
}

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
