// SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Test harness for tier-2 integration tests.
//!
//! Spins up a `piv-authenticator` virtual card connected to `pcscd` via
//! `vpcd`, runs a test closure against it, then tears down the card.
//!
//! Requires the `integration-tests` feature and a running `pcscd` with the
//! `vpcd` driver loaded (`vsmartcard-vpcd` package).

#[cfg(feature = "integration-tests")]
mod inner {
    use piv_authenticator::{virt::with_ram_client, vpicc::VpiccCard, Authenticator, Options};
    use std::{
        sync::{mpsc, Mutex},
        thread::sleep,
        time::Duration,
    };
    use stoppable_thread::spawn;

    /// Serialise concurrent `with_vsc` calls — vpcd supports one virtual card
    /// at a time per process.
    static VSC_MUTEX: Mutex<()> = Mutex::new(());

    /// Run `f` with a fresh virtual PIV card connected to `pcscd` via `vpcd`.
    ///
    /// `f` receives the PC/SC reader name of the virtual card.
    /// Returns `None` if `vpcd` is not available (so callers can skip gracefully).
    pub fn with_vsc<F, R>(options: Options, f: F) -> Option<R>
    where
        F: FnOnce(&str) -> R,
    {
        // Skip gracefully if vpcd socket is absent.
        if !std::path::Path::new("/var/run/vpcd").exists() {
            eprintln!("with_vsc: /var/run/vpcd not found — skipping (install vsmartcard-vpcd and restart pcscd)");
            return None;
        }

        let Ok(_lock) = VSC_MUTEX.lock() else {
            panic!("VSC_MUTEX poisoned — a previous test panicked");
        };

        let mut vpicc = vpicc::connect().expect("failed to connect to vpcd");

        let (tx, rx) = mpsc::channel();
        let handle = spawn(move |stopped| {
            with_ram_client("piv-authenticator", |client| {
                let card = Authenticator::new(client, options);
                let mut vpicc_card = VpiccCard::new(card);
                let mut result = Ok(());
                while !stopped.get() && result.is_ok() {
                    result = vpicc.poll(&mut vpicc_card);
                    if result.is_ok() {
                        let _ = tx.send(());
                    }
                }
                result
            })
        });

        rx.recv()
            .expect("failed to receive ready signal from vpicc thread");

        // Give pcscd time to detect the new reader.
        sleep(Duration::from_millis(200));

        // Find the virtual reader name via PC/SC.
        let reader_name = find_virtual_reader();

        let result = f(&reader_name);

        handle
            .stop()
            .join()
            .expect("failed to join vpicc thread")
            .expect("vpicc thread error");

        Some(result)
    }

    fn find_virtual_reader() -> String {
        let ctx =
            pcsc::Context::establish(pcsc::Scope::User).expect("failed to establish PC/SC context");
        let mut buf = vec![0u8; 65536];
        let readers: Vec<String> = ctx
            .list_readers(&mut buf)
            .expect("failed to list PC/SC readers")
            .map(|r| r.to_string_lossy().into_owned())
            .collect();
        readers
            .into_iter()
            .find(|r| r.contains("Virtual") || r.contains("virtual") || r.contains("vpcd"))
            .expect("no virtual reader found — is vpcd running?")
    }
}

#[cfg(feature = "integration-tests")]
pub use inner::with_vsc;
#[cfg(feature = "integration-tests")]
pub use piv_authenticator::Options;
