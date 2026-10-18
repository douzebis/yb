// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! The card lock (spec 0048): one program at a time talks to the YubiKey.
//!
//! On hardware, the lock is PC/SC's transaction (`SCardBeginTransaction`):
//! every connection yb opens holds it while open, and a sequence that must
//! not be interleaved (a whole-store read, a write) keeps one connection
//! open through a [`CardLock`] from [`PivBackend::exclusive`].  The
//! simulated backends implement the same rule with a [`CardScheduler`],
//! which tests can replace to choose the interleaving of several clients.
//!
//! [`PivBackend::exclusive`]: super::PivBackend::exclusive

use anyhow::Result;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread::ThreadId;
use std::time::Duration;

/// Holds the card lock until dropped (spec 0048).  Re-entrant: a thread
/// holding the lock may take it again.
pub struct CardLock<'a> {
    release: Option<Box<dyn FnOnce() + 'a>>,
}

impl<'a> CardLock<'a> {
    /// A lock that `release` gives back.
    pub fn new(release: impl FnOnce() + 'a) -> Self {
        Self {
            release: Some(Box::new(release)),
        }
    }

    /// A lock that holds nothing: for backends without one.
    pub fn none() -> Self {
        Self { release: None }
    }
}

impl Drop for CardLock<'_> {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            release();
        }
    }
}

/// How a simulated YubiKey orders its clients: the lock, and the points
/// where another client may run.
pub trait CardScheduler: Send + Sync {
    /// Take the lock for the calling thread, waiting while another thread
    /// holds it.  Re-entrant.
    fn lock(&self);
    /// Give back one [`lock`](Self::lock).
    fn unlock(&self);
    /// Called after [`lock`](Self::lock) when the lock is taken for a
    /// sequence of commands ([`PivBackend::exclusive`]), not for a single
    /// one: tests order operations by these.
    ///
    /// [`PivBackend::exclusive`]: super::PivBackend::exclusive
    fn sequence(&self) {}
    /// Called before each card command, the lock held: a point where
    /// another client may run.  An error interrupts the caller there, as
    /// a crash or a YubiKey pulled out would.
    fn command(&self) -> Result<()>;
}

/// The default [`CardScheduler`]: a re-entrant lock per thread, the
/// clients running freely.
#[derive(Default)]
pub struct ThreadLock {
    owner: Mutex<(Option<ThreadId>, usize)>,
    free: Condvar,
}

impl CardScheduler for ThreadLock {
    fn lock(&self) {
        let me = std::thread::current().id();
        let mut owner = self.owner.lock().unwrap();
        while owner.0.is_some_and(|t| t != me) {
            owner = self.free.wait(owner).unwrap();
        }
        owner.0 = Some(me);
        owner.1 += 1;
    }

    fn unlock(&self) {
        let mut owner = self.owner.lock().unwrap();
        owner.1 -= 1;
        if owner.1 == 0 {
            owner.0 = None;
            self.free.notify_all();
        }
    }

    fn command(&self) -> Result<()> {
        Ok(())
    }
}

/// The lock of a simulated YubiKey, for its backend's commands and
/// [`PivBackend::exclusive`](super::PivBackend::exclusive).
pub(crate) struct SimulatedLock {
    scheduler: Mutex<Arc<dyn CardScheduler>>,
}

impl Default for SimulatedLock {
    fn default() -> Self {
        Self {
            scheduler: Mutex::new(Arc::new(ThreadLock::default())),
        }
    }
}

impl SimulatedLock {
    pub(crate) fn set_scheduler(&self, scheduler: Arc<dyn CardScheduler>) {
        *self.scheduler.lock().unwrap() = scheduler;
    }

    fn scheduler(&self) -> Arc<dyn CardScheduler> {
        self.scheduler.lock().unwrap().clone()
    }

    /// The lock for a sequence of commands, held until the returned guard
    /// is dropped.
    pub(crate) fn exclusive(&self) -> CardLock<'static> {
        let scheduler = self.scheduler();
        scheduler.lock();
        scheduler.sequence();
        CardLock::new(move || scheduler.unlock())
    }

    /// One command: the lock for its duration, and the scheduler's turn.
    pub(crate) fn command(&self) -> Result<CardLock<'static>> {
        let scheduler = self.scheduler();
        scheduler.lock();
        let lock = CardLock::new({
            let scheduler = scheduler.clone();
            move || scheduler.unlock()
        });
        scheduler.command()?;
        Ok(lock)
    }
}

// ---------------------------------------------------------------------------
// Waiting for another program (spec 0048, Q1)
// ---------------------------------------------------------------------------

static WAIT_NOTICE: OnceLock<Box<dyn Fn() + Send + Sync>> = OnceLock::new();

/// Tell the user when yb waits for another program using the YubiKey:
/// `notice` is called once a wait for the lock passes a second (the yb
/// command prints a line; a library stays quiet).  Set once per process.
pub fn set_wait_notice(notice: impl Fn() + Send + Sync + 'static) {
    let _ = WAIT_NOTICE.set(Box::new(notice));
}

/// Run `wait`, which takes the lock; if it lasts over a second, the wait
/// notice (if any) is given while it goes on.
pub(crate) fn waiting<T>(wait: impl FnOnce() -> T) -> T {
    let Some(notice) = WAIT_NOTICE.get() else {
        return wait();
    };
    let (done, finished) = std::sync::mpsc::channel::<()>();
    let watcher = std::thread::spawn(move || {
        if finished.recv_timeout(Duration::from_secs(1))
            == Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        {
            notice();
        }
    });
    let result = wait();
    drop(done);
    let _ = watcher.join();
    result
}
