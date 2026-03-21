// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Minimal LED flash test — one YubiKey, raw pcsc.
//!
//! Usage: flash_test [reader-name] [mode]
//!   mode = "flash" (default): 3 Hz blink for 10 seconds
//!   mode = "idle":            do nothing for 30 seconds (watch for noise flashes)
//!
//! With no args, lists available readers.

const SELECT_PIV: &[u8] = &[0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08];
// Select a non-existent AID — card returns an error but LED goes dark.
const SELECT_NONE: &[u8] = &[0x00, 0xA4, 0x04, 0x00, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

fn main() {
    let reader_name = std::env::args().nth(1).unwrap_or_else(|| {
        let ctx = pcsc::Context::establish(pcsc::Scope::User).expect("PC/SC context");
        let mut buf = vec![0u8; 65536];
        println!("Available readers:");
        for r in ctx.list_readers(&mut buf).expect("list readers") {
            println!("  {:?}", r);
        }
        std::process::exit(1);
    });

    let mode = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "flash".to_owned());

    if mode == "idle" {
        println!("Idle mode — doing nothing for 30 seconds.");
        println!("Watch the YubiKey LED for any spontaneous flashes.");
        println!("(Each spontaneous flash is noise from another process or pcscd)");
        std::thread::sleep(std::time::Duration::from_secs(30));
        println!("Done.");
        return;
    }

    if mode == "hold" {
        // Hold connection open without transmitting — does pcscd's internal
        // USB polling thread cause LED flashes on its own?
        let ctx = pcsc::Context::establish(pcsc::Scope::User).expect("PC/SC context");
        let reader_cstr = std::ffi::CString::new(reader_name.as_str()).expect("CString");
        let card = ctx
            .connect(&reader_cstr, pcsc::ShareMode::Shared, pcsc::Protocols::ANY)
            .expect("connect");
        println!("Connection open, holding for 30 seconds — watch for LED flashes.");
        std::thread::sleep(std::time::Duration::from_secs(30));
        drop(card);
        println!("Done.");
        return;
    }

    if mode == "persistent" {
        // Keep connection open, send SELECT_PIV every 400ms — no power cycling.
        // Watch for off/on dips during the on-period.
        let ctx = pcsc::Context::establish(pcsc::Scope::User).expect("PC/SC context");
        let reader_cstr = std::ffi::CString::new(reader_name.as_str()).expect("CString");
        let mut buf = vec![0u8; pcsc::MAX_BUFFER_SIZE_EXTENDED];
        let card = ctx
            .connect(&reader_cstr, pcsc::ShareMode::Shared, pcsc::Protocols::ANY)
            .expect("connect");
        println!("Persistent connection, SELECT_PIV every 400ms for 20 seconds.");
        println!("LED should stay ON the whole time — watch for any dips.");
        for i in 1..=50 {
            match card.transmit(SELECT_PIV, &mut buf) {
                Ok(resp) => println!(
                    "  #{i}: SW {:02X} {:02X}",
                    resp[resp.len() - 2],
                    resp[resp.len() - 1]
                ),
                Err(e) => println!("  #{i}: error: {e}"),
            }
            std::thread::sleep(std::time::Duration::from_millis(400));
        }
        drop(card);
        println!("Done.");
        return;
    }

    let ctx = pcsc::Context::establish(pcsc::Scope::User).expect("PC/SC context");
    let reader_cstr = std::ffi::CString::new(reader_name.as_str()).expect("CString");
    let mut buf = vec![0u8; pcsc::MAX_BUFFER_SIZE_EXTENDED];

    println!("Flashing \"{}\" at 3 Hz for 10 seconds...", reader_name);
    println!("WATCH THE YUBIKEY LED");

    // Cycle: connect (power-up) → SELECT_PIV (LED on) → sleep on_ms →
    //        unpower (LED off) → sleep off_ms → connect (power-up, absorbed) → ...
    //
    // The power-up flash on connect is absorbed into the on-period because we
    // sleep the full off-period before reconnecting.
    let on_ms = 400u64;
    let off_ms = 400u64;
    // Delay after connect() before SELECT_PIV, to let the ATR power-up flash
    // settle before the intentional on-period starts.
    let settle_ms = 50u64;

    let mut card_opt = ctx
        .connect(&reader_cstr, pcsc::ShareMode::Shared, pcsc::Protocols::ANY)
        .ok();

    for i in 1..=20 {
        match card_opt.take() {
            Some(card) => {
                // Wait for ATR power-up flash to settle.
                std::thread::sleep(std::time::Duration::from_millis(settle_ms));
                // LED on.
                match card.transmit(SELECT_PIV, &mut buf) {
                    Ok(resp) => println!(
                        "  flash #{i}: SW {:02X} {:02X}",
                        resp[resp.len() - 2],
                        resp[resp.len() - 1]
                    ),
                    Err(e) => println!("  flash #{i}: transmit error: {e}"),
                }
                std::thread::sleep(std::time::Duration::from_millis(on_ms));
                // LED off.
                if let Err((_, e)) = card.disconnect(pcsc::Disposition::UnpowerCard) {
                    println!("  flash #{i}: disconnect error: {e}");
                }
                // Off-period, then reconnect.
                std::thread::sleep(std::time::Duration::from_millis(off_ms));
                card_opt = ctx
                    .connect(&reader_cstr, pcsc::ShareMode::Shared, pcsc::Protocols::ANY)
                    .ok();
            }
            None => {
                println!("  flash #{i}: connect error");
                std::thread::sleep(std::time::Duration::from_millis(settle_ms + on_ms + off_ms));
                card_opt = ctx
                    .connect(&reader_cstr, pcsc::ShareMode::Shared, pcsc::Protocols::ANY)
                    .ok();
            }
        }
    }

    println!("Done.");
}
