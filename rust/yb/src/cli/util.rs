// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Shared CLI helpers.

use anyhow::{bail, Result};
use globset::GlobBuilder;
use std::collections::HashSet;

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
