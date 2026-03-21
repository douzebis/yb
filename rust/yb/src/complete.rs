// SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Shell-completion helpers for the `yb` CLI.

use clap_complete::engine::CompletionCandidate;
use std::ffi::OsStr;
use yb_core::{orchestrator, piv::hardware::HardwarePiv, store::Store, PivBackend};

/// Complete YubiKey serial numbers from connected devices.
pub fn complete_serials(incomplete: &OsStr) -> Vec<CompletionCandidate> {
    let piv = HardwarePiv::new();
    let Ok(devices) = piv.list_devices() else {
        return vec![];
    };
    let prefix = incomplete.to_string_lossy();
    devices
        .into_iter()
        .map(|d| d.serial.to_string())
        .filter(|s| s.starts_with(prefix.as_ref()))
        .map(CompletionCandidate::new)
        .collect()
}

/// Complete blob names from the YubiKey store.
///
/// Uses the first connected device.  All errors are silently swallowed —
/// a failed completion is better than an error message interrupting the shell.
pub fn complete_blob_names(incomplete: &OsStr) -> Vec<CompletionCandidate> {
    let piv = HardwarePiv::new();
    let Ok(devices) = piv.list_devices() else {
        return vec![];
    };
    let Some(device) = devices.into_iter().next() else {
        return vec![];
    };
    let Ok(store) = Store::from_device(&device.reader, &piv) else {
        return vec![];
    };
    let prefix = incomplete.to_string_lossy();
    orchestrator::list_blobs(&store)
        .into_iter()
        .filter(|b| b.name.starts_with(prefix.as_ref()))
        .map(|b| CompletionCandidate::new(b.name))
        .collect()
}
