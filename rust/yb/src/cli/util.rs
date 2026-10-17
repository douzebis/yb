// SPDX-FileCopyrightText: 2025, 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Shared CLI helpers.

use anyhow::Result;
use globset::GlobBuilder;
use std::collections::HashSet;

// ---------------------------------------------------------------------------
// Exit statuses (spec 0032)
// ---------------------------------------------------------------------------

/// yb's exit statuses besides 0 (success) and 1 (any other error), so that
/// callers need not parse messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatus {
    /// A blob name or pattern matched nothing (`fetch`, `rm` without `-f`).
    NotFound = 2,
    /// The store has no room; checked before writing (`store`).
    StoreFull = 3,
    /// An integrity check failed on a post-quantum store (spec 0028):
    /// checksum, seal or management key; nothing was returned or written.
    Integrity = 4,
}

/// An error that ends yb with a specific [`ExitStatus`].
#[derive(Debug)]
pub struct StatusError {
    pub status: ExitStatus,
    message: String,
}

impl std::fmt::Display for StatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for StatusError {}

impl StatusError {
    pub fn new(status: ExitStatus, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

/// The exit status for `err`: its [`StatusError`]'s, 4 for a failed
/// integrity check of a post-quantum store, or 1.
pub fn exit_status(err: &anyhow::Error) -> i32 {
    if let Some(e) = err.chain().find_map(|e| e.downcast_ref::<StatusError>()) {
        return e.status as i32;
    }
    #[cfg(not(windows))]
    if err.chain().any(|e| {
        e.downcast_ref::<yb_core::orchestrator::post_quantum::IntegrityError>()
            .is_some()
    }) {
        return ExitStatus::Integrity as i32;
    }
    1
}

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
                return Err(StatusError::new(
                    ExitStatus::NotFound,
                    format!("pattern '{pattern}' matched no blobs"),
                )
                .into());
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
                return Err(StatusError::new(
                    ExitStatus::NotFound,
                    format!("blob '{pattern}' not found"),
                )
                .into());
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
