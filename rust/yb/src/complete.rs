// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Shell-completion helpers for the `yb` CLI.

use clap_complete::engine::CompletionCandidate;
use std::ffi::OsStr;
use std::sync::Arc;
use yb_core::{
    orchestrator,
    piv::{hardware::HardwarePiv, VirtualPiv},
    store::Store,
    DeviceInfo, PivBackend,
};

/// Build a PIV backend: VirtualPiv when YB_FIXTURE is set, HardwarePiv otherwise.
fn make_piv() -> Arc<dyn PivBackend> {
    if let Ok(path) = std::env::var("YB_FIXTURE") {
        if let Ok(vpiv) = VirtualPiv::from_fixture(std::path::Path::new(&path)) {
            return Arc::new(vpiv);
        }
    }
    Arc::new(HardwarePiv::new())
}

/// Complete YubiKey serial numbers from connected devices.
pub fn complete_serials(incomplete: &OsStr) -> Vec<CompletionCandidate> {
    let piv = make_piv();
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

/// Device selection options found on the command line being completed.
#[derive(Debug, Default, PartialEq, Eq)]
struct Selector {
    serial: Option<u32>,
    reader: Option<String>,
}

/// Extract `--serial`/`-s` and `--reader`/`-r` from the words of the command
/// line being completed.
///
/// During dynamic completion the shell runs `yb` with the whole command line
/// as arguments, so the global options typed before the subcommand are
/// available here even though the completer only receives the current word.
fn parse_selector<I: IntoIterator<Item = String>>(words: I) -> Selector {
    let mut sel = Selector::default();
    let mut words = words.into_iter();
    while let Some(word) = words.next() {
        if let Some(v) = word.strip_prefix("--serial=") {
            sel.serial = v.parse().ok();
        } else if let Some(v) = word.strip_prefix("--reader=") {
            sel.reader = Some(v.to_owned());
        } else if word == "--serial" || word == "-s" {
            sel.serial = words.next().and_then(|v| v.parse().ok());
        } else if word == "--reader" || word == "-r" {
            sel.reader = words.next();
        }
    }
    sel
}

/// Pick the device whose store should be used for completion: the one named
/// by `--serial`/`--reader`, or the only connected device.  With several
/// devices and no selector, return `None` rather than guess.
fn select_device<'a>(sel: &Selector, devices: &'a [DeviceInfo]) -> Option<&'a DeviceInfo> {
    if let Some(serial) = sel.serial {
        return devices.iter().find(|d| d.serial == serial);
    }
    if let Some(ref reader) = sel.reader {
        return devices.iter().find(|d| &d.reader == reader);
    }
    match devices {
        [only] => Some(only),
        _ => None,
    }
}

/// Complete blob names from the YubiKey store.
///
/// Uses the device selected by `--serial`/`--reader` on the command line, or
/// the only connected device.  All errors are silently swallowed — a failed
/// completion is better than an error message interrupting the shell.
pub fn complete_blob_names(incomplete: &OsStr) -> Vec<CompletionCandidate> {
    let piv = make_piv();
    let Ok(devices) = piv.list_devices() else {
        return vec![];
    };
    let sel = parse_selector(std::env::args().skip(1));
    let Some(device) = select_device(&sel, &devices) else {
        return vec![];
    };
    let Ok(store) = Store::from_device(&device.reader, piv.as_ref()) else {
        return vec![];
    };
    let prefix = incomplete.to_string_lossy();
    orchestrator::list_blobs(&store)
        .into_iter()
        .filter(|b| b.name.starts_with(prefix.as_ref()))
        .map(|b| CompletionCandidate::new(b.name))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_owned).collect()
    }

    fn device(serial: u32, reader: &str) -> DeviceInfo {
        DeviceInfo {
            serial,
            version: "5.7.1".to_owned(),
            reader: reader.to_owned(),
        }
    }

    #[test]
    fn parse_serial_forms() {
        for line in [
            "-- yb --allow-defaults --serial 32283437 fetch --stdout ssh",
            "-- yb --serial=32283437 fetch ssh",
            "-- yb -s 32283437 fetch ssh",
        ] {
            assert_eq!(parse_selector(words(line)).serial, Some(32283437), "{line}");
        }
    }

    #[test]
    fn parse_reader_forms() {
        let sel = parse_selector(words("-- yb --reader=R1 fetch x"));
        assert_eq!(sel.reader.as_deref(), Some("R1"));
        let sel = parse_selector(words("-- yb -r R2 fetch x"));
        assert_eq!(sel.reader.as_deref(), Some("R2"));
    }

    #[test]
    fn parse_no_selector() {
        assert_eq!(
            parse_selector(words("-- yb fetch ssh")),
            Selector::default()
        );
    }

    #[test]
    fn selects_by_serial_among_several() {
        let devices = [device(23028855, "R0"), device(32283437, "R1")];
        let sel = Selector {
            serial: Some(32283437),
            reader: None,
        };
        assert_eq!(select_device(&sel, &devices).unwrap().reader, "R1");
    }

    #[test]
    fn selects_by_reader() {
        let devices = [device(1, "R0"), device(2, "R1")];
        let sel = Selector {
            serial: None,
            reader: Some("R0".to_owned()),
        };
        assert_eq!(select_device(&sel, &devices).unwrap().serial, 1);
    }

    #[test]
    fn single_device_needs_no_selector() {
        let devices = [device(1, "R0")];
        assert_eq!(
            select_device(&Selector::default(), &devices)
                .unwrap()
                .serial,
            1
        );
    }

    #[test]
    fn several_devices_without_selector_give_nothing() {
        let devices = [device(1, "R0"), device(2, "R1")];
        assert!(select_device(&Selector::default(), &devices).is_none());
    }

    #[test]
    fn unknown_serial_gives_nothing() {
        let devices = [device(1, "R0")];
        let sel = Selector {
            serial: Some(9),
            reader: None,
        };
        assert!(select_device(&sel, &devices).is_none());
    }
}
