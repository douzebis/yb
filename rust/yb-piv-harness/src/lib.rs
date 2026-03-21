// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
// SPDX-FileCopyrightText: 2025 - 2026 Thales Cloud Sécurisé
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
    /// Returns `None` if no virtual reader is available (so callers skip gracefully).
    ///
    /// Two modes:
    /// - **External card** (NixOS VM / CI): if a virtual reader is already
    ///   registered with pcscd (e.g. piv-authenticator-vpicc is running as an
    ///   external process), use it directly without spinning up an in-process card.
    /// - **In-process card** (developer nix-shell): connect to vpcd ourselves,
    ///   spin up piv-authenticator in a background thread, then run `f`.
    pub fn with_vsc<F, R>(options: Options, f: F) -> Option<R>
    where
        F: FnOnce(&str) -> R,
    {
        let Ok(_lock) = VSC_MUTEX.lock() else {
            panic!("VSC_MUTEX poisoned — a previous test panicked");
        };

        // Check whether a virtual reader is already present (external mode).
        if let Some(reader_name) = try_find_virtual_reader() {
            return Some(f(&reader_name));
        }

        // No external card — try to start one in-process via vpcd TCP port.
        // Skip gracefully if vpcd is not listening.
        let mut vpicc_conn = match vpicc::connect() {
            Ok(c) => c,
            Err(_) => {
                eprintln!(
                    "with_vsc: vpcd not available and no virtual reader found \
                     — skipping (run pcscd with vsmartcard-vpcd plugin)"
                );
                return None;
            }
        };

        let (tx, rx) = mpsc::channel();
        let handle = spawn(move |stopped| {
            with_ram_client("piv-authenticator", |client| {
                let card = Authenticator::new(client, options);
                let mut vpicc_card = VpiccCard::new(card);
                let mut result = Ok(());
                while !stopped.get() && result.is_ok() {
                    result = vpicc_conn.poll(&mut vpicc_card);
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

        let reader_name =
            try_find_virtual_reader().expect("no virtual reader found after connecting to vpcd");

        let result = f(&reader_name);

        handle
            .stop()
            .join()
            .expect("failed to join vpicc thread")
            .expect("vpicc thread error");

        Some(result)
    }

    /// Return the name of a virtual/vpcd reader already registered with pcscd,
    /// or `None` if none is present.
    fn try_find_virtual_reader() -> Option<String> {
        let ctx = pcsc::Context::establish(pcsc::Scope::User).ok()?;
        let mut buf = vec![0u8; 65536];
        let readers: Vec<String> = ctx
            .list_readers(&mut buf)
            .ok()?
            .map(|r| r.to_string_lossy().into_owned())
            .collect();
        readers
            .into_iter()
            .find(|r| r.contains("Virtual") || r.contains("virtual") || r.contains("vpcd"))
    }
}

#[cfg(feature = "integration-tests")]
pub use inner::with_vsc;
#[cfg(feature = "integration-tests")]
pub use piv_authenticator::Options;
