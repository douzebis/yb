// SPDX-FileCopyrightText: 2025, 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Shared CLI helpers.

use anyhow::{bail, Result};
use globset::GlobBuilder;
use std::collections::HashSet;

// ---------------------------------------------------------------------------
// Signature verdict
// ---------------------------------------------------------------------------

// The verdicts and the check live in yb-core (specs 0017, 0033).
pub use yb_core::orchestrator::{check_blob_signature, SigVerdict};

// ---------------------------------------------------------------------------
// Name quoting (spec 0018)
// ---------------------------------------------------------------------------

/// Return true if `name` contains any byte outside the safe ASCII set:
/// `a–z A–Z 0–9 . - _ + , / :`
///
/// All safe characters are ASCII, so iterating bytes is both correct and
/// sufficient — any non-ASCII byte will fail the match and trigger quoting.
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

/// How to read back the management key yb keeps on the YubiKey, for the
/// rare case it is needed.  Never the key itself.
pub fn read_back_hint() -> String {
    format!(
        "To read it back if ever needed: \
         yubico-piv-tool -a verify-pin -a read-object --id 0x{:06x}",
        yb_core::auxiliaries::OBJ_PRINTED
    )
}
