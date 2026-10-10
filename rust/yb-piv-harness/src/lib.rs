// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Test harness for tier-2 integration tests.
//!
//! Spins up a `piv-authenticator` virtual card connected to `pcscd` via
//! `vpcd`, runs a test closure against it, then tears down the card.
//!
//! Requires the `integration-tests` feature and a running `pcscd` with the
//! `vpcd` driver loaded (`vsmartcard-vpcd` package; on NixOS,
//! `services.vsmartcard-vpcd.enable`).
//!
//! Without vpcd, tests skip, unless `YB_REQUIRE_VSC` is set (as in the NixOS
//! VM test): then they fail, so a broken setup cannot pass silently.

#[cfg(feature = "integration-tests")]
mod inner {
    use piv_authenticator::{virt::with_ram_client, vpicc::VpiccCard, Authenticator, Options};
    use std::{
        ffi::CString,
        fmt::Debug,
        sync::{mpsc, Mutex, PoisonError},
        thread::{self, sleep},
        time::{Duration, Instant},
    };
    use stoppable_thread::{spawn, StoppableHandle};
    use vpicc::VSmartCard;

    /// How long pcscd may take to report a card inserted or removed.
    const PCSCD_DELAY: Duration = Duration::from_secs(5);

    /// Serialise concurrent `with_vsc` calls — vpcd supports one virtual card
    /// at a time per process.
    static VSC_MUTEX: Mutex<()> = Mutex::new(());

    /// Run `f` with a fresh virtual PIV card connected to `pcscd` via `vpcd`.
    ///
    /// Connects to vpcd, runs piv-authenticator in a background thread as the
    /// card, and passes `f` the PC/SC name of the reader holding it.  The card
    /// is removed afterwards, even if `f` panics, so every call starts from an
    /// empty reader.
    ///
    /// Returns `None` if vpcd is unavailable (so callers skip gracefully),
    /// unless `YB_REQUIRE_VSC` is set, in which case it panics.
    pub fn with_vsc<F, R>(options: Options, f: F) -> Option<R>
    where
        F: FnOnce(&str) -> R,
    {
        // The mutex only serialises the tests; the card guard below cleans
        // up after a test that panicked, so a poisoned mutex is fine.
        let _lock = VSC_MUTEX.lock().unwrap_or_else(PoisonError::into_inner);

        // pcscd may be socket-activated: listing its readers starts it, and
        // with it vpcd.  If vpcd's readers are listed, its port may take a
        // moment to accept connections; if not, vpcd is not installed.
        let vpcd_loaded = !virtual_readers().is_empty();
        let mut last_err = None;
        let conn = {
            let mut try_connect = || vpicc::connect().map_err(|e| last_err = Some(e)).ok();
            if vpcd_loaded {
                wait_for(&mut try_connect)
            } else {
                try_connect()
            }
        };
        let Some(mut vpicc_conn) = conn else {
            let reason = last_err.map(|e| e.to_string()).unwrap_or_default();
            let msg = format!(
                "with_vsc: vpcd not available ({reason}) \
                 (run pcscd with the vsmartcard-vpcd driver)"
            );
            if std::env::var_os("YB_REQUIRE_VSC").is_some() {
                panic!("{msg}");
            }
            eprintln!("{msg} — skipping");
            return None;
        };

        let (tx, rx) = mpsc::channel();
        let _card = CardThread(Some(spawn(move |stopped| {
            with_ram_client("piv-authenticator", |client| {
                let card = Authenticator::new(client, options);
                let mut vpicc_card = YubiKeyCompat(VpiccCard::new(card));
                let mut result = Ok(());
                while !stopped.get() && result.is_ok() {
                    result = vpicc_conn.poll(&mut vpicc_card);
                    if result.is_ok() {
                        let _ = tx.send(());
                    }
                }
                result
            })
        })));

        rx.recv()
            .expect("failed to receive ready signal from vpicc thread");

        let reader_name = wait_for(find_virtual_reader_with_card)
            .expect("virtual card not reported by pcscd after connecting to vpcd");

        Some(f(&reader_name))
    }

    /// SELECT of the PIV application by its 5-byte RID, as YubiKeys accept it
    /// and as yb, `ykman` and `yubico-piv-tool` send it.
    const SELECT_PIV_RID: &[u8] = &[0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08];
    /// The same SELECT with the AID truncated to 9 bytes, the shortest form
    /// piv-authenticator accepts.
    const SELECT_PIV_TRUNCATED: &[u8] = &[
        0x00, 0xA4, 0x04, 0x00, 0x09, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00,
    ];

    /// INS of the Yubico GET METADATA extension.
    const INS_GET_METADATA: u8 = 0xF7;
    /// "Instruction not supported".
    const SW_INS_NOT_SUPPORTED: [u8; 2] = [0x6D, 0x00];

    /// The emulated card, adjusted where piv-authenticator differs from a
    /// YubiKey in ways yb depends on.  Every other command passes through
    /// unchanged.
    ///
    /// - SELECT of the PIV application by its RID: piv-authenticator answers
    ///   6A82; it is rewritten to the 9-byte form.
    /// - GET METADATA: piv-authenticator answers success with no data (the
    ///   command is a stub there).  It is answered 6D00 instead, as by a
    ///   YubiKey without the extension (firmware < 5.3), for which yb assumes
    ///   a 3DES management key: piv-authenticator's default.
    struct YubiKeyCompat(VpiccCard);

    impl VSmartCard for YubiKeyCompat {
        fn atr(&self) -> &[u8] {
            self.0.atr()
        }

        fn power_on(&mut self) {
            self.0.power_on()
        }

        fn power_off(&mut self) {
            self.0.power_off()
        }

        fn reset(&mut self) {
            self.0.reset()
        }

        fn execute(&mut self, msg: &[u8]) -> Vec<u8> {
            if msg.get(1) == Some(&INS_GET_METADATA) {
                return SW_INS_NOT_SUPPORTED.to_vec();
            }
            // With or without a trailing Le byte.
            if msg.starts_with(SELECT_PIV_RID) && msg.len() <= SELECT_PIV_RID.len() + 1 {
                let mut select = SELECT_PIV_TRUNCATED.to_vec();
                select.extend_from_slice(&msg[SELECT_PIV_RID.len()..]);
                return self.0.execute(&select);
            }
            self.0.execute(msg)
        }
    }

    /// The thread running the virtual card.  Dropping it (after the test, or
    /// while a failed test unwinds) stops the card and waits until pcscd
    /// reports the reader empty, so that the next test cannot see this card.
    struct CardThread<E: Debug>(Option<StoppableHandle<Result<(), E>>>);

    impl<E: Debug> Drop for CardThread<E> {
        fn drop(&mut self) {
            let Some(handle) = self.0.take() else {
                return;
            };
            let joined = handle.stop().join();
            let removed = wait_for(|| find_virtual_reader_with_card().is_none().then_some(()));
            // Panicking again while a failed test unwinds would abort the
            // process: report teardown errors only after a passing test.
            if !thread::panicking() {
                joined
                    .expect("failed to join vpicc thread")
                    .expect("vpicc thread error");
                removed.expect("virtual card still reported by pcscd after removal");
            }
        }
    }

    /// Poll `f` until it returns `Some`, for at most [`PCSCD_DELAY`].
    fn wait_for<T>(mut f: impl FnMut() -> Option<T>) -> Option<T> {
        let deadline = Instant::now() + PCSCD_DELAY;
        loop {
            if let Some(v) = f() {
                return Some(v);
            }
            if Instant::now() >= deadline {
                return None;
            }
            sleep(Duration::from_millis(50));
        }
    }

    /// Return the name of a virtual (vpcd) reader that holds a card, or
    /// `None` if there is none.
    fn find_virtual_reader_with_card() -> Option<String> {
        virtual_readers()
            .into_iter()
            .find(|(_, has_card)| *has_card)
            .map(|(name, _)| name)
    }

    /// The virtual (vpcd) readers known to pcscd, each with whether it holds
    /// a card.  vpcd readers exist even when empty.  Empty if pcscd or vpcd
    /// is unavailable.
    fn virtual_readers() -> Vec<(String, bool)> {
        let Ok(ctx) = pcsc::Context::establish(pcsc::Scope::User) else {
            return Vec::new();
        };
        let mut buf = vec![0u8; 65536];
        let Ok(names) = ctx.list_readers(&mut buf) else {
            return Vec::new();
        };
        let mut states: Vec<pcsc::ReaderState> = names
            .filter(|r| {
                let r = r.to_string_lossy();
                r.contains("Virtual") || r.contains("virtual") || r.contains("vpcd")
            })
            .map(|r| pcsc::ReaderState::new(CString::from(r), pcsc::State::UNAWARE))
            .collect();
        if states.is_empty() || ctx.get_status_change(Duration::ZERO, &mut states).is_err() {
            return Vec::new();
        }
        states
            .iter()
            .map(|s| {
                let name = s.name().to_string_lossy().into_owned();
                (name, s.event_state().contains(pcsc::State::PRESENT))
            })
            .collect()
    }
}

#[cfg(feature = "integration-tests")]
pub use inner::with_vsc;
#[cfg(feature = "integration-tests")]
pub use piv_authenticator::Options;
