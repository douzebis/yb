// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
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

/// On/off durations for device-selection flash: 100 ms on, 100 ms off (5 Hz).
const FLASH_ON_MS: u64 = 100;
const FLASH_OFF_MS: u64 = 100;

/// Run the interactive single-line carousel device picker.
///
/// Cycles through `devices` with left/right arrow keys (or j/k).
/// The current device flashes its LED.  Returns the selected [`DeviceInfo`]
/// together with the live flash handle (so the caller can keep the LED
/// flashing uninterrupted into the next prompt), or `None` if the user
/// cancels.
pub fn run_picker(
    piv: &Arc<dyn PivBackend>,
    devices: &[DeviceInfo],
) -> Result<Option<(DeviceInfo, Option<Box<dyn yb_core::piv::FlashHandle>>)>> {
    assert!(
        !devices.is_empty(),
        "run_picker called with empty device list"
    );

    let mut idx = 0usize;
    let mut flash = piv.start_flash(&devices[idx].reader, FLASH_ON_MS, FLASH_OFF_MS);

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
                    flash = piv.start_flash(&devices[idx].reader, FLASH_ON_MS, FLASH_OFF_MS);
                    render(&mut out, devices, idx, false)?;
                }
                // Navigate right / next.
                (KeyCode::Right, _)
                | (KeyCode::Char('l'), KeyModifiers::NONE)
                | (KeyCode::Char('j'), KeyModifiers::NONE) => {
                    drop(flash);
                    idx = (idx + 1) % devices.len();
                    flash = piv.start_flash(&devices[idx].reader, FLASH_ON_MS, FLASH_OFF_MS);
                    render(&mut out, devices, idx, false)?;
                }
                // Confirm — keep the flash handle alive for the caller.
                (KeyCode::Enter, _) => {
                    break Some((devices[idx].clone(), Some(flash)));
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
