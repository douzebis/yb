// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Shared CLI helpers.

use anyhow::{bail, Result};
use globset::GlobBuilder;
use std::collections::HashSet;
use yb_core::{
    collect_blob_chain,
    store::{Object, Store},
};

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
        if has_supernumerary || !trailing.iter().all(|&b| b == 0) {
            return SigVerdict::Corrupted;
        }
        SigVerdict::Unverified
    }
}

// ---------------------------------------------------------------------------
// Name quoting (spec 0018)
// ---------------------------------------------------------------------------

/// Return true if `name` contains any character outside the safe set:
/// `a–z A–Z 0–9 . - _ + , / :`
fn needs_quoting(name: &str) -> bool {
    name.bytes().any(|b| !matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'-' | b'_' | b'+' | b',' | b'/' | b':'))
}

/// Return the name as it should appear in `yb ls` output.
///
/// Names in the safe set are returned unchanged.  All other names are
/// wrapped in POSIX single quotes, with embedded `'` escaped as `'\''`.
pub fn quote_name(name: &str) -> String {
    if !needs_quoting(name) {
        return name.to_owned();
    }
    let escaped = name.replace('\'', r"'\''");
    format!("'{escaped}'")
}

/// Resolve a list of glob/literal patterns against a list of blob names.
///
/// - Glob patterns (`*`, `?`, `[`) expand to all matching names.
/// - Literal names must exist unless `ignore_missing` is true.
/// - Result is deduplicated and preserves first-seen order.
pub fn resolve_patterns(
    patterns: &[String],
    blob_names: &[String],
    ignore_missing: bool,
) -> Result<Vec<String>> {
    let mut result: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for pattern in patterns {
        let is_glob = pattern.chars().any(|c| matches!(c, '*' | '?' | '['));
        if is_glob {
            let glob = GlobBuilder::new(pattern)
                .case_insensitive(false)
                .build()?
                .compile_matcher();
            let hits: Vec<&str> = blob_names
                .iter()
                .filter(|n| glob.is_match(n.as_str()))
                .map(|n| n.as_str())
                .collect();
            if hits.is_empty() {
                if ignore_missing {
                    continue;
                }
                bail!("pattern '{}' matched no blobs", pattern);
            }
            for name in hits {
                if seen.insert(name.to_owned()) {
                    result.push(name.to_owned());
                }
            }
        } else {
            if !blob_names.iter().any(|n| n == pattern) {
                if ignore_missing {
                    continue;
                }
                bail!("blob '{}' not found", pattern);
            }
            if seen.insert(pattern.clone()) {
                result.push(pattern.clone());
            }
        }
    }

    Ok(result)
}
