// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Specs 0048 and 0049 — concurrent access.
//!
//! Several clients use one simulated YubiKey at once.  A seeded scheduler
//! (`Scheduler`) chooses which client runs at each card command and each
//! request for the card lock, so a seed replays the same interleaving; it
//! can also interrupt a client at a command, as a crash would.  Each
//! operation's position is the lock it took last (the order of the card
//! lock).  An oracle replays the operations in that order on a model (name
//! → content) and checks every answer and the final store: yb's operations
//! are serializable (invariant 0020), and snapshot sessions answer as of
//! their snapshot and detect conflicts exactly (invariant 0021).

use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use yb_core::piv::{CardScheduler, VirtualPiv};
use yb_core::store::Store;
use yb_core::{
    fetch_blob, list_blobs, remove_blobs, store_blob, store_blob_checked, unchanged_since,
    BlobChanged, Compression, Encryption, StoreOptions,
};

const MGMT: &str = "010203040506070801020304050607080102030405060708";
const PIN: &str = "654321";
const NAMES: [&str; 4] = ["a", "b", "c", "vault"];
const SIZES: [usize; 6] = [1, 40, 300, 1500, 3500, 7000];

// ---------------------------------------------------------------------------
// The scheduler
// ---------------------------------------------------------------------------

thread_local! {
    static CLIENT: Cell<Option<usize>> = const { Cell::new(None) };
}

fn me() -> Option<usize> {
    CLIENT.with(Cell::get)
}

struct State {
    rng: SmallRng,
    /// The client whose turn it is.
    running: Option<usize>,
    /// Clients waiting for their turn.
    ready: BTreeSet<usize>,
    /// Clients waiting for the card lock.
    blocked: BTreeSet<usize>,
    owner: Option<usize>,
    depth: Vec<usize>,
    /// The lock order: how many outermost locks were taken so far.
    seq: u64,
    /// Each client's last outermost lock.
    last: Vec<u64>,
    /// The chance that a command interrupts its client.
    crash: f64,
    /// Whether the lock excludes anyone (off: a test that the oracle can
    /// fail).
    locking: bool,
}

/// A deterministic [`CardScheduler`]: one client runs at a time, and the
/// seeded generator picks the next one at every command and lock request.
struct Scheduler {
    state: Mutex<State>,
    turn: Condvar,
}

impl Scheduler {
    fn new(seed: u64, clients: usize, crash: f64, locking: bool) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                rng: SmallRng::seed_from_u64(seed),
                running: None,
                ready: BTreeSet::new(),
                blocked: BTreeSet::new(),
                owner: None,
                depth: vec![0; clients],
                seq: 0,
                last: vec![0; clients],
                crash,
                locking,
            }),
            turn: Condvar::new(),
        })
    }

    /// Give the turn to a ready client, chosen by the generator.
    fn schedule(s: &mut State) {
        let ready: Vec<usize> = s.ready.iter().copied().collect();
        s.running = if ready.is_empty() {
            assert!(s.blocked.is_empty(), "every client waits for the lock");
            None
        } else {
            let next = ready[s.rng.gen_range(0..ready.len())];
            s.ready.remove(&next);
            Some(next)
        };
    }

    fn wait_turn<'a>(
        &'a self,
        mut s: std::sync::MutexGuard<'a, State>,
        c: usize,
    ) -> std::sync::MutexGuard<'a, State> {
        self.turn.notify_all();
        while s.running != Some(c) {
            s = self.turn.wait(s).unwrap();
        }
        s
    }

    /// Let another ready client run, then wait for the turn again.
    fn yield_turn<'a>(
        &'a self,
        mut s: std::sync::MutexGuard<'a, State>,
        c: usize,
    ) -> std::sync::MutexGuard<'a, State> {
        s.ready.insert(c);
        Self::schedule(&mut s);
        self.wait_turn(s, c)
    }

    /// Run `body` as client `c`: it starts on its turn, and gives the turn
    /// away when done.
    fn run_client<T>(&self, c: usize, body: impl FnOnce() -> T) -> T {
        CLIENT.with(|cell| cell.set(Some(c)));
        {
            let mut s = self.state.lock().unwrap();
            s.ready.insert(c);
            drop(self.wait_turn(s, c));
        }
        let result = body();
        let mut s = self.state.lock().unwrap();
        assert_eq!(s.depth[c], 0, "client {c} ended holding the lock");
        Self::schedule(&mut s);
        self.turn.notify_all();
        result
    }

    fn last_lock(&self, c: usize) -> u64 {
        self.state.lock().unwrap().last[c]
    }

    /// Give the first turn, once all `clients` are ready.
    fn release(&self, clients: usize) {
        loop {
            let mut s = self.state.lock().unwrap();
            if s.ready.len() == clients {
                Self::schedule(&mut s);
                self.turn.notify_all();
                return;
            }
            drop(s);
            std::thread::yield_now();
        }
    }
}

impl CardScheduler for Scheduler {
    fn lock(&self) {
        let Some(c) = me() else { return };
        let mut s = self.yield_turn(self.state.lock().unwrap(), c);
        loop {
            if !s.locking || s.owner.is_none() || s.owner == Some(c) {
                if s.locking {
                    s.owner = Some(c);
                }
                s.depth[c] += 1;
                return;
            }
            s.blocked.insert(c);
            Self::schedule(&mut s);
            s = self.wait_turn(s, c);
        }
    }

    /// An outermost lock for a sequence (a whole read, a write): the
    /// operation's position in lock order.
    fn sequence(&self) {
        let Some(c) = me() else { return };
        let mut s = self.state.lock().unwrap();
        if s.depth[c] == 1 {
            s.seq += 1;
            s.last[c] = s.seq;
        }
    }

    fn unlock(&self) {
        let Some(c) = me() else { return };
        let mut s = self.state.lock().unwrap();
        s.depth[c] -= 1;
        if s.depth[c] == 0 && s.owner == Some(c) {
            s.owner = None;
            let blocked = std::mem::take(&mut s.blocked);
            s.ready.extend(blocked);
        }
    }

    fn command(&self) -> anyhow::Result<()> {
        let Some(c) = me() else { return Ok(()) };
        let mut s = self.yield_turn(self.state.lock().unwrap(), c);
        let crash = s.crash;
        if crash > 0.0 && s.rng.gen_bool(crash) {
            anyhow::bail!("simulated crash");
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Clients and their log
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
enum Op {
    Store(String, Vec<u8>),
    Remove(String),
    Fetch(String),
    List,
    /// Snapshot sessions (spec 0049): refresh the snapshot.
    Refresh,
    /// A question to the snapshot: the blob's content.
    SnapFetch(String),
    /// A store from the snapshot, with or without `IF_UNCHANGED`.
    SnapStore(String, Vec<u8>, bool),
}

#[derive(Clone, Debug, PartialEq)]
enum Outcome {
    Stored,
    Full,
    Removed(usize),
    Content(Option<Vec<u8>>),
    Names(Vec<String>),
    Changed,
    Refreshed,
    /// Interrupted (a simulated crash): took effect or not.
    Interrupted,
    Failed(String),
}

#[derive(Clone, Debug)]
struct Record {
    client: usize,
    op: Op,
    outcome: Outcome,
    /// The op's last outermost lock (0: it took none).
    pos: u64,
    /// For a snapshot op: the position of the snapshot it used.
    snap_pos: u64,
}

fn plain() -> StoreOptions<'static> {
    StoreOptions {
        encryption: Encryption::None,
        compression: Compression::None,
    }
}

fn outcome_of<T>(r: anyhow::Result<T>, ok: impl FnOnce(T) -> Outcome) -> Outcome {
    match r {
        Ok(v) => ok(v),
        Err(e) if e.downcast_ref::<BlobChanged>().is_some() => Outcome::Changed,
        Err(e) if format!("{e:#}").contains("simulated crash") => Outcome::Interrupted,
        Err(e) => Outcome::Failed(format!("{e:#}")),
    }
}

/// One client's session: plain (every op reads the card), or with a
/// snapshot (spec 0049).
struct Session<'a> {
    piv: &'a VirtualPiv,
    reader: String,
    sched: &'a Scheduler,
    client: usize,
    snapshot: Option<(Store, u64)>,
}

impl Session<'_> {
    fn run(&mut self, op: &Op) -> Record {
        let (piv, reader, c) = (self.piv, self.reader.clone(), self.client);
        let before = self.sched.last_lock(c);
        let mut snap_pos = 0;
        let look = || Store::from_device(&reader, piv);
        let outcome = match op {
            Op::Store(name, data) => outcome_of(
                look().and_then(|mut s| store_blob(&mut s, piv, name, data, plain(), MGMT, None)),
                |ok| if ok { Outcome::Stored } else { Outcome::Full },
            ),
            Op::Remove(name) => outcome_of(
                look().and_then(|mut s| remove_blobs(&mut s, piv, &[name], MGMT)),
                Outcome::Removed,
            ),
            Op::Fetch(name) => outcome_of(
                look().and_then(|s| fetch_blob(&s, piv, &reader, name, Some(PIN), false)),
                Outcome::Content,
            ),
            Op::List => outcome_of(look(), |s| {
                Outcome::Names(list_blobs(&s).into_iter().map(|b| b.name).collect())
            }),
            Op::Refresh => {
                let r = look();
                let out = outcome_of(
                    r.as_ref().map(|_| ()).map_err(|e| anyhow::anyhow!("{e:#}")),
                    |()| Outcome::Refreshed,
                );
                if let Ok(s) = r {
                    self.snapshot = Some((s, self.sched.last_lock(c)));
                }
                out
            }
            Op::SnapFetch(name) => {
                let (s, p) = self.snapshot.as_ref().expect("a snapshot");
                snap_pos = *p;
                // The snapshot answers: no card command for the content.
                let found = s.find_head(name).is_some();
                let content = if found {
                    fetch_blob(s, piv, &reader, name, Some(PIN), false)
                } else {
                    Ok(None)
                };
                outcome_of(content, Outcome::Content)
            }
            Op::SnapStore(name, data, if_unchanged) => {
                let (snap, p) = self.snapshot.clone().expect("a snapshot");
                snap_pos = p;
                let mut working = snap.clone();
                let check = unchanged_since(&snap, name);
                let r = store_blob_checked(
                    &mut working,
                    piv,
                    name,
                    data,
                    plain(),
                    MGMT,
                    None,
                    if *if_unchanged { Some(&check) } else { None },
                );
                let out = outcome_of(r, |ok| if ok { Outcome::Stored } else { Outcome::Full });
                // The write's whole read under the lock replaced the
                // snapshot; a write refused from the snapshot alone (no
                // room) took no lock, and left it as it was.
                let now = self.sched.last_lock(c);
                let pos = if now != before { now } else { p };
                match out {
                    Outcome::Stored | Outcome::Full | Outcome::Changed => {
                        self.snapshot = Some((working, pos));
                    }
                    // A failed write leaves no snapshot to trust: the next
                    // op refreshes.
                    _ => self.snapshot = None,
                }
                out
            }
        };
        let after = self.sched.last_lock(c);
        Record {
            client: c,
            op: op.clone(),
            outcome,
            pos: if after != before { after } else { 0 },
            snap_pos,
        }
    }
}

// ---------------------------------------------------------------------------
// The oracle
// ---------------------------------------------------------------------------

/// What a blob may hold: several candidates after an interrupted write
/// (old or new), one otherwise.  Each candidate carries the version (the
/// count of writes to the blob) that made it.
type Candidates = Vec<(Option<Vec<u8>>, u32)>;

#[derive(Clone, Default, Debug)]
struct Model {
    blobs: BTreeMap<String, Candidates>,
}

impl Model {
    fn get(&mut self, name: &str) -> &mut Candidates {
        self.blobs
            .entry(name.to_owned())
            .or_insert_with(|| vec![(None, 0)])
    }

    /// Keep the candidates that `keep` accepts; none left is a violation.
    fn observe(
        &mut self,
        name: &str,
        what: &str,
        keep: impl Fn(&Option<Vec<u8>>) -> bool,
    ) -> Result<(), String> {
        let c = self.get(name);
        c.retain(|(v, _)| keep(v));
        if c.is_empty() {
            return Err(format!("{what}: no serial order explains '{name}'"));
        }
        Ok(())
    }

    fn version(&mut self, name: &str) -> u32 {
        self.get(name).iter().map(|(_, v)| *v).max().unwrap_or(0)
    }

    fn set(&mut self, name: &str, content: Option<Vec<u8>>) {
        let v = self.version(name) + 1;
        *self.get(name) = vec![(content, v)];
    }

    fn maybe(&mut self, name: &str, content: Option<Vec<u8>>) {
        let v = self.version(name) + 1;
        self.get(name).push((content, v));
    }

    /// What `IF_UNCHANGED` must answer between two states, if certain
    /// (spec 0049, S4): it compares the blob as it is, so a blob that
    /// changed and came back (created, then removed) may pass either way.
    fn conflict(a: &mut Model, b: &mut Model, name: &str) -> Option<bool> {
        let (va, vb) = (a.get(name).clone(), b.get(name).clone());
        if va.len() != 1 || vb.len() != 1 {
            return None;
        }
        let ((ca, na), (cb, nb)) = (&va[0], &vb[0]);
        if ca != cb {
            Some(true)
        } else if na == nb {
            Some(false)
        } else {
            None
        }
    }
}

fn short(op: &Op) -> String {
    match op {
        Op::Store(n, d) => format!("store {n} ({} bytes)", d.len()),
        Op::SnapStore(n, d, f) => {
            format!("snapshot store {n} ({} bytes, if unchanged: {f})", d.len())
        }
        other => format!("{other:?}"),
    }
}

/// Replay `log` in lock order on the model; check every answer and the
/// final store `end` (name → content).
fn check(log: &[Record], end: &BTreeMap<String, Vec<u8>>) -> Result<Stats, String> {
    let mut stats = Stats::default();
    let mut ops: Vec<&Record> = log
        .iter()
        .filter(|r| r.pos != 0 || r.snap_pos != 0)
        .collect();
    // A snapshot question is answered at its snapshot's position.
    ops.sort_by_key(|r| match r.op {
        Op::SnapFetch(_) => r.snap_pos,
        _ => r.pos,
    });
    let mut model = Model::default();
    let mut history: BTreeMap<u64, Model> = BTreeMap::new();
    history.insert(0, model.clone());
    let trace = std::env::var_os("YB_FUZZ_TRACE").is_some();
    for r in ops {
        if trace {
            eprintln!(
                "lock {:3} snap {:3} client {} {} -> {:?}",
                r.pos,
                r.snap_pos,
                r.client,
                short(&r.op),
                match &r.outcome {
                    Outcome::Content(Some(c)) => format!("{} bytes", c.len()),
                    o => format!("{o:?}"),
                }
            );
        }
        let at = |what: &str| {
            format!(
                "{what} (client {}, {}, lock {})",
                r.client,
                short(&r.op),
                r.pos
            )
        };
        if let Outcome::Failed(e) = &r.outcome {
            return Err(at(&format!("unexpected error: {e}")));
        }
        match (&r.op, &r.outcome) {
            (_, Outcome::Interrupted) => {
                stats.interrupted += 1;
                match &r.op {
                    Op::Store(n, d) | Op::SnapStore(n, d, _) => model.maybe(n, Some(d.clone())),
                    Op::Remove(n) => model.maybe(n, None),
                    _ => {}
                }
            }
            (Op::Store(n, d) | Op::SnapStore(n, d, _), Outcome::Stored) => {
                if let Op::SnapStore(_, _, true) = &r.op {
                    let mut then = history.range(..=r.snap_pos).last().unwrap().1.clone();
                    if Model::conflict(&mut then, &mut model, n) == Some(true) {
                        return Err(at("stored despite IF_UNCHANGED, though the blob changed"));
                    }
                }
                stats.stored += 1;
                model.set(n, Some(d.clone()));
            }
            (Op::Store(..) | Op::SnapStore(..), Outcome::Full) => stats.full += 1,
            (Op::SnapStore(n, _, true), Outcome::Changed) => {
                let mut then = history.range(..=r.snap_pos).last().unwrap().1.clone();
                if Model::conflict(&mut then, &mut model, n) == Some(false) {
                    return Err(at("CHANGED, though the blob did not change"));
                }
                stats.changed += 1;
            }
            (Op::Remove(n), Outcome::Removed(k)) => {
                model.observe(n, &at("remove"), |v| v.is_some() == (*k == 1))?;
                // Removing an absent blob writes nothing.
                if *k == 1 {
                    model.set(n, None);
                }
            }
            (Op::Fetch(n), Outcome::Content(got)) => {
                model.observe(n, &at("fetch"), |v| v == got)?;
                stats.reads += 1;
            }
            (Op::SnapFetch(n), Outcome::Content(got)) => {
                let mut then = history.range(..=r.snap_pos).last().unwrap().1.clone();
                then.observe(n, &at("snapshot fetch"), |v| v == got)?;
                stats.reads += 1;
            }
            (Op::List, Outcome::Names(names)) => {
                for n in NAMES {
                    let present = names.iter().any(|x| x == n);
                    model.observe(n, &at("list"), |v| v.is_some() == present)?;
                }
                stats.reads += 1;
            }
            (Op::Refresh, Outcome::Refreshed) => {}
            (op, out) => return Err(format!("unexpected outcome {out:?} for {op:?}")),
        }
        let key = match r.op {
            Op::SnapFetch(_) => continue,
            _ => r.pos,
        };
        history.insert(key, model.clone());
    }
    for n in NAMES {
        let got = end.get(n).cloned();
        model.observe(n, "the final store", |v| *v == got)?;
    }
    Ok(stats)
}

#[derive(Default, Debug)]
struct Stats {
    stored: usize,
    full: usize,
    changed: usize,
    interrupted: usize,
    reads: usize,
}

// ---------------------------------------------------------------------------
// A run
// ---------------------------------------------------------------------------

struct Run {
    seed: u64,
    clients: usize,
    ops: usize,
    crash: f64,
    locking: bool,
    /// Clients that use a snapshot session (spec 0049).
    snapshot_clients: usize,
    /// Each client's `i`-th op, instead of random ones.
    script: Option<fn(usize, usize) -> Op>,
}

fn new_piv() -> VirtualPiv {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/with_key.yaml");
    VirtualPiv::from_fixture(&fixture).unwrap()
}

/// A random op for client `c`'s `i`-th turn.  The content names the write,
/// so that every write is told apart.
fn random_op(rng: &mut SmallRng, c: usize, i: usize, snapshot: bool, has_snapshot: bool) -> Op {
    let name = NAMES[rng.gen_range(0..NAMES.len())].to_owned();
    let size = SIZES[rng.gen_range(0..SIZES.len())];
    let tag = format!("{c}:{i};");
    let content: Vec<u8> = tag.bytes().cycle().take(size.max(tag.len())).collect();
    let pick = rng.gen_range(0..10);
    if snapshot {
        if !has_snapshot {
            return Op::Refresh;
        }
        return match pick {
            0..=1 => Op::Refresh,
            2..=4 => Op::SnapFetch(name),
            5..=7 => Op::SnapStore(name, content, true),
            _ => Op::SnapStore(name, content, false),
        };
    }
    match pick {
        0..=3 => Op::Store(name, content),
        4 => Op::Remove(name),
        5..=7 => Op::Fetch(name),
        _ => Op::List,
    }
}

fn run(cfg: &Run) -> Result<Stats, String> {
    let piv = new_piv();
    let reader = piv.reader_name();
    Store::format(&reader, &piv, 8, 0x82, MGMT).unwrap();
    let sched = Scheduler::new(cfg.seed, cfg.clients, cfg.crash, cfg.locking);
    piv.set_scheduler(sched.clone());

    let log: Vec<Record> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..cfg.clients)
            .map(|c| {
                let (piv, sched, reader) = (&piv, &*sched, reader.clone());
                let mut rng =
                    SmallRng::seed_from_u64(cfg.seed.wrapping_mul(1000).wrapping_add(c as u64));
                let snapshot = c < cfg.snapshot_clients;
                scope.spawn(move || {
                    sched.run_client(c, || {
                        let mut session = Session {
                            piv,
                            reader,
                            sched,
                            client: c,
                            snapshot: None,
                        };
                        (0..cfg.ops)
                            .map(|i| {
                                let op = match cfg.script {
                                    Some(script) => script(c, i),
                                    None => random_op(
                                        &mut rng,
                                        c,
                                        i,
                                        snapshot,
                                        session.snapshot.is_some(),
                                    ),
                                };
                                session.run(&op)
                            })
                            .collect::<Vec<_>>()
                    })
                })
            })
            .collect();
        // The first turn, once every client is ready: the run depends on
        // the seed only.
        sched.release(cfg.clients);
        handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect()
    });

    // The final store, read alone.
    let store = Store::from_device(&reader, &piv).map_err(|e| format!("final read: {e:#}"))?;
    let mut end = BTreeMap::new();
    for b in list_blobs(&store) {
        let data = fetch_blob(&store, &piv, &reader, &b.name, Some(PIN), false)
            .map_err(|e| format!("final fetch of {}: {e:#}", b.name))?
            .expect("listed");
        end.insert(b.name, data);
    }
    check(&log, &end)
}

fn run_seeds(seeds: std::ops::Range<u64>, cfg: impl Fn(u64) -> Run) -> Stats {
    let mut total = Stats::default();
    for seed in seeds {
        match run(&cfg(seed)) {
            Ok(s) => {
                total.stored += s.stored;
                total.full += s.full;
                total.changed += s.changed;
                total.interrupted += s.interrupted;
                total.reads += s.reads;
            }
            Err(e) => panic!("seed {seed}: {e}"),
        }
    }
    total
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Invariant 0020: concurrent stores, removals, fetches and listings, with
/// interruptions, are serializable in lock order.
#[test]
fn concurrent_operations_are_serializable() {
    let stats = run_seeds(0..40, |seed| Run {
        seed,
        clients: 3,
        ops: 12,
        crash: 0.002,
        locking: true,
        snapshot_clients: 0,
        script: None,
    });
    eprintln!("{stats:?}");
    // The runs exercise what they claim to.
    assert!(stats.stored > 100 && stats.reads > 100, "{stats:?}");
    assert!(stats.interrupted > 5 && stats.full > 0, "{stats:?}");
}

/// Invariant 0020: without the lock, the fuzzer finds a violation: the
/// test can fail.
#[test]
fn without_the_lock_the_fuzzer_finds_a_violation() {
    let failing = (0..40)
        .filter_map(|seed| {
            run(&Run {
                seed,
                clients: 3,
                ops: 12,
                crash: 0.0,
                locking: false,
                snapshot_clients: 0,
                script: None,
            })
            .err()
        })
        .inspect(|e| eprintln!("without the lock: {e}"))
        .count();
    assert!(failing > 0, "no seed found a violation without the lock");
}

/// Invariant 0020: a reader never misses a blob that another client keeps
/// replacing (spec 0048's read in the middle of a write); without the
/// lock, it does.
#[test]
fn a_reader_never_misses_a_blob_being_replaced() {
    fn script(c: usize, i: usize) -> Op {
        match c {
            0 => Op::Store(
                "vault".into(),
                format!("{i};").repeat(1 + i * 97 % 900).into_bytes(),
            ),
            _ => Op::Fetch("vault".into()),
        }
    }
    let cfg = |seed, locking| Run {
        seed,
        clients: 2,
        ops: 15,
        crash: 0.0,
        locking,
        snapshot_clients: 0,
        script: Some(script),
    };
    for seed in 0..40 {
        if let Err(e) = run(&cfg(seed, true)) {
            panic!("seed {seed}: {e}");
        }
    }
    let missed = (0..40)
        .filter(|&seed| run(&cfg(seed, false)).is_err())
        .count();
    assert!(missed > 0, "without the lock, the reader never missed");
}

/// Invariant 0021: snapshot sessions answer as of their snapshot, plan
/// their writes from the card, and IF_UNCHANGED is exact.
#[test]
fn snapshot_sessions_are_serializable() {
    let stats = run_seeds(0..40, |seed| Run {
        seed,
        clients: 3,
        ops: 12,
        crash: 0.002,
        locking: true,
        snapshot_clients: 2,
        script: None,
    });
    eprintln!("{stats:?}");
    assert!(stats.changed > 5 && stats.stored > 50, "{stats:?}");
}

/// The long run, for the scheduled CI job: `YB_FUZZ_SEEDS` seeds from
/// `YB_FUZZ_FIRST` (default: random), printed on failure.
#[test]
#[ignore]
fn fuzz_long() {
    let first = std::env::var("YB_FUZZ_FIRST")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(rand::random::<u32>) as u64;
    let count: u64 = std::env::var("YB_FUZZ_SEEDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2000);
    eprintln!("fuzz_long: seeds {first}..{}", first + count);
    let stats = run_seeds(first..first + count, |seed| Run {
        seed,
        clients: 2 + (seed % 3) as usize,
        ops: 20,
        crash: 0.002,
        locking: true,
        snapshot_clients: (seed % 3) as usize,
        script: None,
    });
    eprintln!("fuzz_long: {stats:?}");
}

// ---------------------------------------------------------------------------
// Invariant 0021, case by case: another program writes between a snapshot
// and a write from it.
// ---------------------------------------------------------------------------

/// A card with `blobs`, and a snapshot of it.
fn card_and_snapshot(objects: u8, blobs: &[(&str, &[u8])]) -> (VirtualPiv, String, Store) {
    let piv = new_piv();
    let reader = piv.reader_name();
    let mut store = Store::format(&reader, &piv, objects, 0x82, MGMT).unwrap();
    for (name, data) in blobs {
        assert!(store_blob(&mut store, &piv, name, data, plain(), MGMT, None).unwrap());
    }
    let snapshot = Store::from_device(&reader, &piv).unwrap();
    (piv, reader, snapshot)
}

/// What another program does, from its own read of the card.
fn other_stores(piv: &VirtualPiv, reader: &str, name: &str, data: &[u8]) {
    let mut store = Store::from_device(reader, piv).unwrap();
    assert!(store_blob(&mut store, piv, name, data, plain(), MGMT, None).unwrap());
}

fn content(piv: &VirtualPiv, reader: &str, name: &str) -> Option<Vec<u8>> {
    let store = Store::from_device(reader, piv).unwrap();
    fetch_blob(&store, piv, reader, name, Some(PIN), false).unwrap()
}

/// A write from `snapshot`, checked against it if `if_unchanged`.
fn write_from(
    piv: &VirtualPiv,
    snapshot: &Store,
    name: &str,
    data: &[u8],
    if_unchanged: bool,
) -> anyhow::Result<bool> {
    let mut working = snapshot.clone();
    let check = unchanged_since(snapshot, name);
    store_blob_checked(
        &mut working,
        piv,
        name,
        data,
        plain(),
        MGMT,
        None,
        if_unchanged.then_some(&check as _),
    )
}

fn is_changed(r: anyhow::Result<bool>) -> bool {
    r.is_err_and(|e| e.downcast_ref::<BlobChanged>().is_some())
}

/// Another blob put into objects the snapshot shows free: the write goes
/// elsewhere, and both blobs are intact.
#[test]
fn a_write_from_a_snapshot_avoids_objects_taken_since() {
    let (piv, reader, snapshot) = card_and_snapshot(8, &[]);
    other_stores(&piv, &reader, "other", &[0x0B; 3000]);
    assert!(write_from(&piv, &snapshot, "vault", b"mine", true).unwrap());
    assert_eq!(content(&piv, &reader, "other").unwrap(), vec![0x0B; 3000]);
    assert_eq!(content(&piv, &reader, "vault").unwrap(), b"mine");
}

/// The same blob replaced since: IF_UNCHANGED refuses, writing nothing;
/// without it, the write lands (the last writer wins) and nothing else
/// is touched.
#[test]
fn a_blob_replaced_since_the_snapshot() {
    let (piv, reader, snapshot) = card_and_snapshot(8, &[("vault", b"v1"), ("other", b"o")]);
    other_stores(&piv, &reader, "vault", b"v2");
    let writes = piv.write_count();
    assert!(is_changed(write_from(
        &piv, &snapshot, "vault", b"v3", true
    )));
    assert_eq!(piv.write_count(), writes, "nothing was written");
    assert_eq!(content(&piv, &reader, "vault").unwrap(), b"v2");
    assert!(write_from(&piv, &snapshot, "vault", b"v3", false).unwrap());
    assert_eq!(content(&piv, &reader, "vault").unwrap(), b"v3");
    assert_eq!(content(&piv, &reader, "other").unwrap(), b"o");
}

/// The same blob removed since, or created since: IF_UNCHANGED refuses.
#[test]
fn a_blob_removed_or_created_since_the_snapshot() {
    let (piv, reader, snapshot) = card_and_snapshot(8, &[("vault", b"v1")]);
    let mut store = Store::from_device(&reader, &piv).unwrap();
    remove_blobs(&mut store, &piv, &["vault"], MGMT).unwrap();
    assert!(is_changed(write_from(
        &piv, &snapshot, "vault", b"v2", true
    )));
    assert_eq!(content(&piv, &reader, "vault"), None);

    let (piv, reader, snapshot) = card_and_snapshot(8, &[]);
    other_stores(&piv, &reader, "vault", b"theirs");
    assert!(is_changed(write_from(
        &piv, &snapshot, "vault", b"mine", true
    )));
    assert_eq!(content(&piv, &reader, "vault").unwrap(), b"theirs");
}

/// The store formatted again since: with other dimensions, the write is
/// refused; with the same, it plans from the new, empty store (and
/// IF_UNCHANGED sees the blob gone).
#[test]
fn a_store_formatted_again_since_the_snapshot() {
    let (piv, reader, snapshot) = card_and_snapshot(8, &[("vault", b"v1")]);
    Store::format(&reader, &piv, 6, 0x82, MGMT).unwrap();
    let err = write_from(&piv, &snapshot, "vault", b"v2", false).unwrap_err();
    assert!(format!("{err:#}").contains("formatted again"), "{err:#}");

    let (piv, reader, snapshot) = card_and_snapshot(8, &[("vault", b"v1")]);
    Store::format(&reader, &piv, 8, 0x82, MGMT).unwrap();
    assert!(is_changed(write_from(
        &piv, &snapshot, "vault", b"v2", true
    )));
    assert!(write_from(&piv, &snapshot, "vault", b"v2", false).unwrap());
    assert_eq!(content(&piv, &reader, "vault").unwrap(), b"v2");
}

/// The store filled since: the write is refused for room, writing
/// nothing.
#[test]
fn a_store_filled_since_the_snapshot() {
    let (piv, reader, snapshot) = card_and_snapshot(4, &[]);
    other_stores(&piv, &reader, "big", &[0x0B; 7000]);
    let writes = piv.write_count();
    assert!(!write_from(&piv, &snapshot, "vault", &[0x0A; 3000], false).unwrap());
    assert_eq!(piv.write_count(), writes, "nothing was written");
    assert_eq!(content(&piv, &reader, "big").unwrap(), vec![0x0B; 7000]);
}

// ---------------------------------------------------------------------------
// The memory scan (`yb fsck --nvm`) sees one state of the card
// ---------------------------------------------------------------------------

/// The memory scan's figures, as a tuple.
fn memory(piv: &VirtualPiv, reader: &str) -> (usize, usize, usize) {
    let usage = yb_core::scan_store_memory(reader, piv).unwrap();
    (usage.store_bytes, usage.other_bytes, usage.free_bytes)
}

/// Scans while another client stores and removes a blob: under the lock,
/// each scan gives the figures of a quiet card, with or without the blob
/// (spec 0048, invariant 0020).  Returns whether every seed did.
fn scans_see_one_state(locking: bool) -> bool {
    let blob = vec![0x5A_u8; 5000];
    // The two quiet states.
    let quiet = {
        let piv = new_piv();
        let reader = piv.reader_name();
        let mut store = Store::format(&reader, &piv, 8, 0x82, MGMT).unwrap();
        let without = memory(&piv, &reader);
        assert!(store_blob(&mut store, &piv, "vault", &blob, plain(), MGMT, None).unwrap());
        [without, memory(&piv, &reader)]
    };
    (0..60).all(|seed| {
        let piv = new_piv();
        let reader = piv.reader_name();
        Store::format(&reader, &piv, 8, 0x82, MGMT).unwrap();
        let sched = Scheduler::new(seed, 2, 0.0, locking);
        piv.set_scheduler(sched.clone());
        let scans = std::thread::scope(|scope| {
            let (piv, sched, reader) = (&piv, &*sched, reader.as_str());
            let blob = &blob;
            let writer = scope.spawn(move || {
                sched.run_client(0, || {
                    for _ in 0..8 {
                        let mut s = Store::from_device(reader, piv).unwrap();
                        assert!(
                            store_blob(&mut s, piv, "vault", blob, plain(), MGMT, None).unwrap()
                        );
                        let mut s = Store::from_device(reader, piv).unwrap();
                        remove_blobs(&mut s, piv, &["vault"], MGMT).unwrap();
                    }
                })
            });
            let scanner = scope.spawn(move || {
                sched.run_client(1, || {
                    (0..12).map(|_| memory(piv, reader)).collect::<Vec<_>>()
                })
            });
            sched.release(2);
            writer.join().unwrap();
            scanner.join().unwrap()
        });
        scans.iter().all(|scan| quiet.contains(scan))
    })
}

#[test]
fn the_memory_scan_sees_one_state() {
    assert!(
        scans_see_one_state(true),
        "a scan saw a card in the middle of a write"
    );
    assert!(
        !scans_see_one_state(false),
        "without the lock, no scan saw a write in the middle: the test cannot fail"
    );
}
