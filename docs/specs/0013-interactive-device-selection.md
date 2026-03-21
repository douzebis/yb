<!--
SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
SPDX-FileCopyrightText: 2025 - 2026 Thales Cloud Sécurisé

SPDX-License-Identifier: MIT
-->

# 0013 — Interactive Device Selection with LED Feedback

**Status:** draft
**App:** yb (Rust)
**Implemented in:** <!-- YYYY-MM-DD, fill after implementation -->

## Problem

When multiple YubiKeys are connected, `yb` currently prints a list and errors out
with "use --serial or --reader".  The user must note the desired serial from the
list, re-run the command with `--serial`, and hope they remember which physical
token is which.  This is error-prone when several identical-looking tokens are
plugged in.

The Python version solved this with an interactive terminal menu: the currently
highlighted YubiKey flashes its LED, letting the user confirm the right token
visually and select it by pressing Enter.  The Rust port has no equivalent.

## Goals

- When multiple YubiKeys are present **and** no `--serial` / `--reader` is
  provided **and** the process is attached to a TTY, launch an interactive
  terminal menu for device selection.
- The selected YubiKey flashes its LED continuously while highlighted.
  Navigating to a different row stops flashing on the old device and starts
  flashing the new one.
- Pressing Enter confirms the selection; pressing Ctrl-C or Escape cancels
  and exits with a non-zero status.
- In non-interactive contexts (pipe, redirect, CI) the behavior is unchanged:
  print the device list and error out as today.
- Add a `yb select` subcommand that explicitly launches the picker and then
  prints the selected serial to stdout, for scripting.

## Non-goals

- Flashing when a device is already unambiguously selected (single device, or
  `--serial` supplied).
- Flashing in non-interactive contexts.
- Supporting non-YubiKey PC/SC tokens.
- A graphical or web UI.

---

## Specification

### 1. Flash mechanism

#### 1.1 What triggers the LED

The YubiKey has no dedicated "LED blink" APDU.  The LED flashes momentarily
whenever the card processes a smartcard command.  The Python implementation
exploits this by repeatedly issuing a `SELECT PIV` APDU on the target reader:

```
00 A4 04 00 05 A0 00 00 03 08
CLA INS P1 P2 Lc  ──── AID ────
```

Each `SELECT` causes one brief flash.  The Python code issues one `SELECT`
every 200 ms, producing a 5 Hz blink that is visible and distinctive without
being distracting.

The `SELECT PIV` APDU already exists in the Rust codebase as `SELECT_PIV`
(`hardware.rs:554`).

#### 1.2 PC/SC connection model for flashing

A `PcscSession` holds an open `pcsc::Card` handle.  Opening a fresh
`PcscSession` for every flash would incur round-trip overhead for context
establishment and `SCardConnect`.  Instead, a **dedicated flash connection**
is kept open for the lifetime of each flash loop:

```
while flashing:
    SCardConnect (Shared mode) → card handle
    loop every 200 ms:
        transmit SELECT_PIV on card handle   ← flash
    SCardDisconnect
```

The connection uses `pcsc::ShareMode::Shared` so it coexists with the main
connection that the rest of `yb` will open later.

#### 1.3 Threading model

One background Rust thread per actively flashing device.  The thread owns a
`std::sync::atomic::AtomicBool` stop flag (shared via `Arc`).  The main thread
sets the flag to stop the thread.  The thread checks the flag after each
`transmit` call (no sleeping — `transmit` already blocks for ~1 ms; a 200 ms
interval is implemented by calling `transmit` and then `std::thread::sleep`
in a loop that re-checks the flag every 10 ms for responsiveness).

Stop sequence:
1. Main thread sets `stop_flag`.
2. Flash thread notices flag, breaks out of its loop, drops the card handle.
3. Main thread joins with a 500 ms timeout and proceeds regardless.

The thread is spawned with `std::thread::Builder::new().name("yb-flash-N")`.

#### 1.4 Error handling in the flash thread

The flash thread must **never panic** the process.  Any `transmit` error
(device removed, USB glitch) silently breaks the loop.  The main thread does
not observe flash errors; worst case the LED simply stops blinking.

#### 1.5 `PivBackend::flash` method

A new optional method is added to the `PivBackend` trait:

```rust
/// Flash the device on the given reader asynchronously.
///
/// Returns a handle that stops flashing when dropped.
/// The default implementation is a no-op (returns a handle that does
/// nothing), so existing implementations are unaffected.
fn start_flash(&self, reader: &str) -> Box<dyn FlashHandle>;
```

```rust
/// Opaque handle returned by `PivBackend::start_flash`.
/// Dropping the handle stops the flash loop.
pub trait FlashHandle: Send {}
```

`HardwarePiv` provides a real implementation that spawns the background thread
described in §1.3.  `VirtualPiv` (and the default trait impl) returns a no-op
handle — no LED, no thread.

This keeps flash logic inside `yb-core` and testable without hardware, while
the `PivBackend` abstraction boundary remains intact.

### 2. Interactive picker

#### 2.1 Terminal rendering

The picker is a simple full-screen-in-place (non-full-screen) terminal widget
rendered entirely with ANSI escape sequences and raw-mode stdin, using the
`crossterm` crate.  No `prompt_toolkit` equivalent (Python-specific) is needed.

Rendered layout (example, two devices):

```
Select a YubiKey:

  → YubiKey 12345678  (v5.4.3)   ← highlighted row (green background)
    YubiKey 87654321  (v5.2.6)

↑/↓ navigate · Enter confirm · Ctrl-C/Esc cancel
```

The `→` marker and green background move with the selection.

#### 2.2 Key handling (raw mode)

`crossterm` enables raw mode on stdin for the duration of the picker.  Raw mode
is restored via `Drop` (`crossterm::terminal::disable_raw_mode`) so Ctrl-C
cannot leave the terminal in a broken state.

Key bindings:

| Key | Action |
|-----|--------|
| `↑` / `k` | Move selection up |
| `↓` / `j` | Move selection down |
| `Enter` | Confirm |
| `Esc` / `q` / `Ctrl-C` | Cancel |

#### 2.3 Flash lifecycle during navigation

- On entry: start flashing device at index 0.
- On `↑`/`↓`: stop current flash handle (drop it), start flashing new device.
- On `Enter`: stop flash handle (drop it), return selected `DeviceInfo`.
- On cancel: stop flash handle (drop it), return `None`.

#### 2.4 Crate dependency

Add `crossterm` to `yb/Cargo.toml` (the CLI binary crate, not `yb-core`).  The
picker is CLI-layer code and does not belong in the library.

```toml
crossterm = "0.27"
```

### 3. Integration into `Context::new`

`Context::new` in `context.rs` currently calls `select_device(...)` which errors
when multiple devices are found and no serial/reader was given.

The new flow when `devices.len() > 1` and no `--serial`/`--reader`:

```
if stdout is a TTY:
    selected ← run_picker(&devices, piv)     // §2
    if selected is None:
        bail!("device selection cancelled")
    proceed with selected device
else:
    (existing behavior) print list + error
```

`run_picker` lives in `yb/src/cli/picker.rs` (CLI crate).  Because `Context::new`
is in `yb-core` and cannot call into the CLI crate, the picker is injected as a
closure:

```rust
pub fn new(
    serial: Option<u32>,
    reader: Option<String>,
    management_key: Option<String>,
    pin: Option<String>,
    pin_fn: Box<dyn Fn() -> Result<Option<String>>>,
    device_picker: Box<dyn Fn(&[DeviceInfo]) -> Result<Option<DeviceInfo>>>,
    output: OutputOptions,
    allow_defaults: bool,
) -> Result<Self>
```

`main.rs` supplies a real picker closure when stderr is a TTY, and a
non-interactive fallback (print + error) otherwise.

The `with_backend` constructor is unchanged (tests never have multiple devices).

### 4. `yb select` subcommand

A new subcommand `yb select` (no subcommand-specific flags) runs the picker
unconditionally:

- If a single YubiKey is connected: print its serial and exit 0 (no picker
  needed).
- If multiple YubiKeys are connected and TTY: run the picker, print chosen
  serial to stdout.
- If multiple YubiKeys and no TTY: error out.
- If no YubiKey: error out.

Intended use: `yb --serial "$(yb select)" store myfile`.

### 5. `PivBackend` trait change — backward compatibility

The `start_flash` method has a default implementation:

```rust
fn start_flash(&self, _reader: &str) -> Box<dyn FlashHandle> {
    Box::new(NoopFlash)
}

struct NoopFlash;
impl FlashHandle for NoopFlash {}
impl Drop for NoopFlash { fn drop(&mut self) {} }
```

All existing `PivBackend` implementors (`VirtualPiv`, `EmulatedPiv`,
`TwoDevicePiv` in tests) automatically inherit the no-op.  Only `HardwarePiv`
overrides it.

### 6. `device_picker` closure in tests

Tests that call `Context::new` must supply a `device_picker` argument.  All
existing test call sites pass a closure that immediately returns the first
device (or errors if the list is empty), simulating non-interactive
single-device behavior:

```rust
Box::new(|devices: &[DeviceInfo]| {
    devices.first().cloned().map(Some)
        .ok_or_else(|| anyhow::anyhow!("no device"))
})
```

This is a mechanical change with no behavioral impact on existing tests.

---

## Design notes

### Why SELECT PIV and not a dedicated blink APDU?

YubiKey firmware does not expose a "blink" instruction in the PIV applet.
`ykman` uses the OTP application (`slot_write` with a special challenge) to
blink on some models, but the OTP application is not always enabled, requires
a different AID, and introduces an ykman dependency.

The `SELECT PIV` approach works on all YubiKey 4+ models regardless of other
applet configuration, uses only the PC/SC interface already open in `yb`, and
requires no additional dependencies.

The trade-off is that `SELECT PIV` also re-initializes the PIV session state,
which means the flash connection and the main working connection must be
**separate** PC/SC handles.  Using `ShareMode::Shared` on both is the correct
approach; pcsclite and the WinSCard API both support multiple shared handles on
the same reader.

### Why crossterm and not ratatui / tui-rs?

`ratatui` is a full TUI framework with layout primitives, widget trees, and a
diffing renderer.  The picker renders four to ten lines of text.  `crossterm`
alone is sufficient and adds ~100 KB to the binary versus ~400 KB for
`ratatui`.

### Why inject `device_picker` into `Context::new` rather than call it from `main.rs` before constructing the context?

`Context::new` already selects the device.  Moving selection into `main.rs`
before `Context::new` would require `main.rs` to partially duplicate the
device-selection logic (serial/reader resolution, error handling) that lives in
`context.rs`, coupling the CLI more tightly to the library internals.  Injection
keeps `context.rs` as the single source of truth for device selection.

### Why not `indicatif` for the picker?

`indicatif` (already a dependency) provides progress bars and spinners but has
no arrow-key navigation.  The picker needs raw-mode key input, which
`indicatif` does not provide.

---

## Open Questions

- `crossterm` vs `termion`: `crossterm` is cross-platform (Windows, macOS,
  Linux); `termion` is Unix-only.  Since `yb` targets Linux/macOS where
  YubiKeys are typically used, either would work.  `crossterm` is preferred
  for future portability.
- Should the picker also show the reader name, or just serial + version?
  Serial + version is usually sufficient for identification; reader name is
  verbose (e.g. `Yubico YubiKey OTP+FIDO+CCID 00 00`).

---

## References

- Python implementation: `src/yb/yubikey_selector.py` (flash loop and
  interactive picker)
- `hardware.rs`: `SELECT_PIV` constant, `PcscSession`, `ShareMode::Shared`
- `context.rs`: `select_device`, `Context::new`
- `crossterm` crate: cross-platform raw-mode terminal I/O
- PC/SC spec: `SCardConnect` `SCARD_SHARE_SHARED`, `SCardTransmit`
