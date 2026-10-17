// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

use anyhow::{bail, Result};
use clap::Args;
use clap_complete::engine::{ArgValueCompleter, PathCompleter};
use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;
use yb_core::orchestrator::{self, Compression, Encryption, StoreOptions};
use yb_core::store::{constants::MAX_NAME_LEN, Store};
use yb_core::{errors::YbError, Context, SecretOp, SlotKeyCheck};

use crate::cli::util::{ExitStatus, StatusError};

#[derive(Args, Debug)]
pub struct StoreArgs {
    /// Source files to store.  Blob name defaults to each file's basename.
    /// If no files are given, payload is read from stdin (requires --name).
    #[arg(add = ArgValueCompleter::new(PathCompleter::file()))]
    pub files: Vec<PathBuf>,

    /// Override blob name (required when reading from stdin; only valid with a single file).
    #[arg(short = 'n', long = "name")]
    pub name: Option<String>,

    /// Encrypt the blob (default).
    #[arg(
        short = 'e',
        long = "encrypted",
        default_value_t = true,
        overrides_with = "unencrypted"
    )]
    pub encrypted: bool,

    /// Store the blob unencrypted.
    #[arg(short = 'u', long = "unencrypted")]
    pub unencrypted: bool,

    /// Skip compression (useful for already-compressed data).
    #[arg(long = "no-compress")]
    pub no_compress: bool,
}

pub fn run(ctx: &Context, args: &StoreArgs) -> Result<()> {
    let mut store = Store::from_device(&ctx.reader, ctx.piv.as_ref())?;
    store.sanitize();
    let post_quantum = store.kind.is_post_quantum();
    // The PIV credentials protect legacy stores only (spec 0024, 0028).
    if !post_quantum {
        ctx.enforce_default_policy(SecretOp::Store)?;
    }
    let encrypted = !args.unencrypted;
    let compression = match args.no_compress {
        true => Compression::None,
        false => Compression::Auto,
    };

    // Build list of (blob_name, payload) pairs.
    let entries: Vec<(String, Vec<u8>)> = if args.files.is_empty() {
        // Stdin mode: --name required.
        let name = args
            .name
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--name is required when reading from stdin"))?
            .to_owned();
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        vec![(name, buf)]
    } else {
        if args.name.is_some() && args.files.len() > 1 {
            bail!("--name can only be used with a single file");
        }
        let mut entries = Vec::with_capacity(args.files.len());
        for path in &args.files {
            let name = if let Some(ref n) = args.name {
                n.clone()
            } else {
                path.file_name()
                    .and_then(|n| n.to_str())
                    .map(|s| s.to_owned())
                    .ok_or_else(|| anyhow::anyhow!("cannot derive blob name from {:?}", path))?
            };
            let payload = std::fs::read(path)?;
            entries.push((name, payload));
        }

        // Detect basename collisions before writing anything.
        let mut seen: HashMap<&str, &PathBuf> = HashMap::new();
        for (i, (name, _)) in entries.iter().enumerate() {
            if let Some(prev) = seen.get(name.as_str()) {
                bail!(
                    "duplicate blob name '{}' from '{}' and '{}'",
                    name,
                    prev.display(),
                    args.files[i].display()
                );
            }
            seen.insert(name.as_str(), &args.files[i]);
        }

        entries
    };

    if post_quantum {
        check_capacity(&store, &entries, encrypted)?;
        return store_post_quantum(ctx, &mut store, &entries, encrypted, compression);
    }

    let peer_pk = if encrypted {
        Some(ctx.get_public_key(store.store_key_slot)?)
    } else {
        None
    };

    let mgmt_key = ctx.management_key_for_write()?;

    check_capacity(&store, &entries, encrypted)?;

    // Refuse to write blobs that the slot key could not decrypt or whose
    // signatures would not verify (spec 0022 §6).
    let slot = store.store_key_slot;
    if ctx.check_slot_key(slot)? == SlotKeyCheck::Mismatch {
        return Err(YbError::new(format!(
            "the key in slot 0x{slot:02x} does not match its certificate"
        ))
        .why("new blobs would be undecryptable; nothing was stored")
        .fix("`yb format --generate` (this erases the store)")
        .into());
    }

    let pin = ctx.require_pin()?;
    for (name, payload) in &entries {
        let ok = orchestrator::store_blob(
            &mut store,
            ctx.piv.as_ref(),
            name,
            payload,
            StoreOptions {
                encryption: match peer_pk.as_ref() {
                    Some(pk) => Encryption::Encrypted(pk),
                    None => Encryption::None,
                },
                compression,
            },
            &mgmt_key,
            pin.as_deref(),
        )?;
        if !ok {
            bail!(
                "store is full while writing '{}' — this should not happen",
                name
            );
        }
        report_stored(ctx, name, payload.len(), encrypted);
    }

    ctx.complete_pending_repairs();
    Ok(())
}

/// Store into a post-quantum store (spec 0028): the FIDO2 PIN, one touch
/// per blob; each blob is protected before anything is written.
#[cfg(not(windows))]
fn store_post_quantum(
    ctx: &Context,
    store: &mut Store,
    entries: &[(String, Vec<u8>)],
    encrypted: bool,
    compression: Compression,
) -> Result<()> {
    let session = ctx.post_quantum_session()?;
    let descriptor = store.descriptor().cloned().expect("a post-quantum store");
    let protection = session.protection(ctx, &descriptor);
    for (name, payload) in entries {
        let ok = orchestrator::store_blob_with(
            store,
            ctx.piv.as_ref(),
            &protection,
            name,
            payload,
            encrypted,
            compression,
            None,
        )?;
        if !ok {
            bail!("store is full while writing '{name}' — this should not happen");
        }
        report_stored(ctx, name, payload.len(), encrypted);
    }
    Ok(())
}

#[cfg(windows)]
fn store_post_quantum(
    _: &Context,
    _: &mut Store,
    _: &[(String, Vec<u8>)],
    _: bool,
    _: Compression,
) -> Result<()> {
    bail!("post-quantum stores are not supported on Windows")
}

fn report_stored(ctx: &Context, name: &str, len: usize, encrypted: bool) {
    if !ctx.quiet {
        eprintln!(
            "Stored '{}' ({} bytes{})",
            name,
            len,
            if encrypted { ", encrypted" } else { "" }
        );
    }
}

/// All-or-nothing capacity check (S2), replaying the stores in order: a
/// blob's new copy, trailer included, must fit in the objects free at that
/// point; an existing copy is freed only after its replacement is written
/// (spec 0031), so it counts as occupied until then.  Compression only
/// makes blobs smaller, so this never refuses a store that would fit.
fn check_capacity(store: &Store, entries: &[(String, Vec<u8>)], encrypted: bool) -> Result<()> {
    let mut free = store.free_count();
    for (name, payload) in entries {
        let needed = objects_for(store, name, payload.len(), encrypted);
        let old_copy = store
            .find_head(name)
            .map_or(0, |head| store.chunk_chain(head.index()).len());
        if needed > free {
            let replacing = if old_copy > 0 {
                "; replacing a blob needs room for the new copy before the old one is \
                 removed"
            } else {
                ""
            };
            let message = if entries.len() == 1 {
                format!(
                    "store is full — remove some blobs first (need {needed} object(s), \
                     {free} free{replacing})"
                )
            } else {
                format!(
                    "store is full — not enough room for '{name}' (need {needed} \
                     object(s), {free} free{replacing}); nothing was stored"
                )
            };
            return Err(StatusError::new(ExitStatus::StoreFull, message).into());
        }
        free = free - needed + old_copy;
    }
    Ok(())
}

/// Objects a blob needs, as the capacity check counts them: the payload
/// before compression, encryption overhead and trailer included (an upper
/// bound).  `yb self-test` uses it to check a "store full".
pub fn objects_for(store: &Store, name: &str, payload_len: usize, encrypted: bool) -> usize {
    let name_len = name.len().min(MAX_NAME_LEN);
    #[cfg(not(windows))]
    if store.kind.is_post_quantum() {
        use yb_core::orchestrator::post_quantum::{
            PQ_ENCRYPTION_OVERHEAD, PQ_TRAILER_LEN_ENCRYPTED, PQ_TRAILER_LEN_PLAIN,
        };
        let len = if encrypted {
            payload_len + PQ_ENCRYPTION_OVERHEAD + PQ_TRAILER_LEN_ENCRYPTED
        } else {
            payload_len + PQ_TRAILER_LEN_PLAIN
        };
        return yb_core::orchestrator::chunks_needed(len, name_len, store.object_size);
    }
    let enc_len = if encrypted {
        // Approximate: actual encrypted size = payload + GCM overhead.
        payload_len + yb_core::crypto::GCM_OVERHEAD
    } else {
        payload_len
    };
    yb_core::orchestrator::objects_needed(enc_len, name_len, store.object_size)
}
