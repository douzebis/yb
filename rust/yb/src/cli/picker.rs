// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
// SPDX-FileCopyrightText: 2025 - 2026 Thales Cloud Sécurisé
//
// SPDX-License-Identifier: MIT

//! Single-line carousel picker for selecting a YubiKey when multiple are
//! connected.  The currently displayed device flashes its LED at 3 Hz via
//! `PivBackend::start_flash`.

use anyhow::Result;
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    execute, queue,
    style::{self, Color},
    terminal,
};
use std::io::{stderr, Write as _};
use std::sync::Arc;
use yb_core::{DeviceInfo, PivBackend};

/// 3 Hz — calm, clearly intentional blink for device identification.
const FLASH_INTERVAL_MS: u64 = 333;

/// Run the interactive single-line carousel device picker.
///
/// Cycles through `devices` with left/right arrow keys (or j/k).
/// The current device flashes its LED.  Returns the selected [`DeviceInfo`],
/// or `None` if the user presses Esc.
pub fn run_picker(piv: &Arc<dyn PivBackend>, devices: &[DeviceInfo]) -> Result<Option<DeviceInfo>> {
    assert!(
        !devices.is_empty(),
        "run_picker called with empty device list"
    );

    let mut idx = 0usize;
    let mut flash = piv.start_flash(&devices[idx].reader, FLASH_INTERVAL_MS);

    terminal::enable_raw_mode()?;
    let mut out = stderr();
    execute!(out, cursor::Hide)?;

    render(&mut out, devices, idx, true)?;

    let result = loop {
        if let Ok(Event::Key(KeyEvent {
            code, modifiers, ..
        })) = event::read()
        {
            match (code, modifiers) {
                // Navigate left / previous.
                (KeyCode::Left, _)
                | (KeyCode::Char('h'), KeyModifiers::NONE)
                | (KeyCode::Char('k'), KeyModifiers::NONE) => {
                    drop(flash);
                    idx = if idx == 0 { devices.len() - 1 } else { idx - 1 };
                    flash = piv.start_flash(&devices[idx].reader, FLASH_INTERVAL_MS);
                    render(&mut out, devices, idx, false)?;
                }
                // Navigate right / next.
                (KeyCode::Right, _)
                | (KeyCode::Char('l'), KeyModifiers::NONE)
                | (KeyCode::Char('j'), KeyModifiers::NONE) => {
                    drop(flash);
                    idx = (idx + 1) % devices.len();
                    flash = piv.start_flash(&devices[idx].reader, FLASH_INTERVAL_MS);
                    render(&mut out, devices, idx, false)?;
                }
                // Confirm.
                (KeyCode::Enter, _) => {
                    drop(flash);
                    break Some(devices[idx].clone());
                }
                // Cancel.
                (KeyCode::Esc, _)
                | (KeyCode::Char('q'), KeyModifiers::NONE)
                | (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                    drop(flash);
                    break None;
                }
                _ => {}
            }
        }
    };

    // Erase the picker line and restore cursor.
    queue!(
        out,
        cursor::MoveToColumn(0),
        terminal::Clear(terminal::ClearType::CurrentLine),
        cursor::Show,
    )?;
    out.flush()?;
    terminal::disable_raw_mode()?;

    Ok(result)
}

/// Render (or re-render) the single-line carousel on stderr.
///
/// Format:  ← YubiKey 12345678 (v5.4.3)  [2/3] →    ←/→ · Enter · Esc
fn render(
    out: &mut impl std::io::Write,
    devices: &[DeviceInfo],
    idx: usize,
    first: bool,
) -> Result<()> {
    let dev = &devices[idx];
    let n = devices.len();

    // On subsequent renders, move back to column 0 and overwrite.
    if !first {
        queue!(out, cursor::MoveToColumn(0))?;
    }

    queue!(
        out,
        terminal::Clear(terminal::ClearType::CurrentLine),
        style::SetForegroundColor(Color::DarkYellow),
        style::Print("\u{2190} "), // ←
        style::ResetColor,
        style::SetBackgroundColor(Color::DarkGreen),
        style::SetForegroundColor(Color::White),
        style::Print(format!(" YubiKey {}  (v{}) ", dev.serial, dev.version)),
        style::ResetColor,
        style::SetForegroundColor(Color::DarkYellow),
        style::Print(format!(" \u{2192}  [{}/{}]", idx + 1, n)), // →
        style::ResetColor,
        style::Print("    \u{2190}/\u{2192} navigate \u{00B7} Enter confirm \u{00B7} Esc cancel"),
    )?;
    out.flush()?;
    Ok(())
}
