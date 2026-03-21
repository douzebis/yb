// SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Test primitives: `ToyFilesystem` and `OperationGenerator`.
//!
//! Available under `#[cfg(any(test, feature = "test-utils"))]` and also
//! re-exported from the crate root when the `test-utils` feature is enabled,
//! so the `yb` CLI binary can use them for the `self-test` command.

use std::collections::{HashMap, HashSet};

use rand::{rngs::SmallRng, Rng, SeedableRng};

// ---------------------------------------------------------------------------
// ToyFilesystem
// ---------------------------------------------------------------------------

/// In-memory ground-truth store used to verify real store operations.
///
/// Maps blob name → `(payload, mtime)`.
pub struct ToyFilesystem {
    files: HashMap<String, (Vec<u8>, u32)>,
}

impl ToyFilesystem {
    pub fn new() -> Self {
        Self {
            files: HashMap::new(),
        }
    }

    pub fn store(&mut self, name: &str, payload: Vec<u8>, mtime: u32) {
        self.files.insert(name.to_owned(), (payload, mtime));
    }

    /// Returns `Some(&(payload, mtime))` if present.
    pub fn fetch(&self, name: &str) -> Option<&(Vec<u8>, u32)> {
        self.files.get(name)
    }

    /// Removes the entry.  Returns `true` if it existed.
    pub fn remove(&mut self, name: &str) -> bool {
        self.files.remove(name).is_some()
    }

    /// Sorted list of all names.
    pub fn list(&self) -> Vec<String> {
        let mut names: Vec<String> = self.files.keys().cloned().collect();
        names.sort();
        names
    }
}

impl Default for ToyFilesystem {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Operation types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpType {
    Store,
    Fetch,
    Remove,
    List,
}

#[derive(Debug, Clone)]
pub struct Operation {
    pub op_type: OpType,
    pub name: String,
    /// Non-empty only for `Store`.
    pub payload: Vec<u8>,
    /// For `Store`: whether to encrypt.
    pub encrypted: bool,
}

// ---------------------------------------------------------------------------
// OperationGenerator
// ---------------------------------------------------------------------------

const NAME_POOL: &[&str] = &[
    "config",
    "secret",
    "backup",
    "key",
    "cert",
    "data",
    "log",
    "cache",
    "index",
    "metadata",
    "state",
    "info",
    "settings",
    "profile",
    "session",
    "token",
    "auth",
    "creds",
    "database",
    "schema",
    "archive",
    "snapshot",
    "checkpoint",
    "manifest",
];

/// Produces a deterministic pseudo-random sequence of store/fetch/remove/list
/// operations suitable for driving both in-memory (`VirtualPiv`) tests and the
/// real-hardware `yb self-test` command.
pub struct OperationGenerator {
    rng: SmallRng,
    max_capacity: usize,
    existing: HashSet<String>,
}

impl OperationGenerator {
    /// `seed`: fixed seed for reproducibility.
    /// `max_capacity`: treat the store as full at this many distinct names.
    pub fn new(seed: u64, max_capacity: usize) -> Self {
        Self {
            rng: SmallRng::seed_from_u64(seed),
            max_capacity,
            existing: HashSet::new(),
        }
    }

    /// Generate `count` operations.  `encryption_ratio` is the fraction of
    /// `Store` operations that should set `encrypted = true` (0.0 = none).
    pub fn generate(&mut self, count: usize, encryption_ratio: f64) -> Vec<Operation> {
        let mut ops = Vec::with_capacity(count);
        for _ in 0..count {
            let op = self.next_op(encryption_ratio);
            ops.push(op);
        }
        ops
    }

    fn next_op(&mut self, encryption_ratio: f64) -> Operation {
        let fill = self.existing.len();
        let op_type = self.choose_op_type(fill);

        match op_type {
            OpType::Store => self.make_store(encryption_ratio),
            OpType::Fetch => self.make_fetch(),
            OpType::Remove => self.make_remove(),
            OpType::List => Operation {
                op_type: OpType::List,
                name: String::new(),
                payload: Vec::new(),
                encrypted: false,
            },
        }
    }

    fn choose_op_type(&mut self, fill: usize) -> OpType {
        if fill == 0 {
            return OpType::Store;
        }
        // weights: [Store, Fetch, Remove, List]
        let weights: [u32; 4] = if fill >= self.max_capacity {
            [20, 40, 30, 10]
        } else if fill * 10 >= self.max_capacity * 8 {
            [25, 35, 25, 15]
        } else {
            [40, 35, 15, 10]
        };
        let total: u32 = weights.iter().sum();
        let r: u32 = self.rng.gen_range(0..total);
        let mut acc = 0u32;
        for (i, &w) in weights.iter().enumerate() {
            acc += w;
            if r < acc {
                return match i {
                    0 => OpType::Store,
                    1 => OpType::Fetch,
                    2 => OpType::Remove,
                    _ => OpType::List,
                };
            }
        }
        OpType::List
    }

    fn make_store(&mut self, encryption_ratio: f64) -> Operation {
        let at_capacity = self.existing.len() >= self.max_capacity;
        let name = if at_capacity || (!self.existing.is_empty() && self.rng.gen::<f64>() < 0.3) {
            // Update an existing file.
            let existing_vec: Vec<String> = self.existing.iter().cloned().collect();
            let idx = self.rng.gen_range(0..existing_vec.len());
            existing_vec[idx].clone()
        } else {
            // Create a new file — pick from pool, add suffix if collision.
            let idx = self.rng.gen_range(0..NAME_POOL.len());
            let base = NAME_POOL[idx];
            if self.existing.contains(base) {
                let suffix: u16 = self.rng.gen_range(1000..9999);
                format!("{base}-{suffix}")
            } else {
                base.to_owned()
            }
        };

        let size = self.choose_payload_size();
        let payload: Vec<u8> = (0..size).map(|_| self.rng.gen::<u8>()).collect();
        let encrypted = self.rng.gen::<f64>() < encryption_ratio;

        self.existing.insert(name.clone());
        Operation {
            op_type: OpType::Store,
            name,
            payload,
            encrypted,
        }
    }

    fn make_fetch(&mut self) -> Operation {
        let name = if self.rng.gen::<f64>() < 0.1 {
            // Non-existent probe.
            let suffix: u16 = self.rng.gen_range(1000..9999);
            format!("nonexistent-{suffix}")
        } else {
            let existing_vec: Vec<String> = self.existing.iter().cloned().collect();
            let idx = self.rng.gen_range(0..existing_vec.len());
            existing_vec[idx].clone()
        };
        Operation {
            op_type: OpType::Fetch,
            name,
            payload: Vec::new(),
            encrypted: false,
        }
    }

    fn make_remove(&mut self) -> Operation {
        let name = if self.rng.gen::<f64>() < 0.1 {
            let suffix: u16 = self.rng.gen_range(1000..9999);
            format!("nonexistent-{suffix}")
        } else {
            let existing_vec: Vec<String> = self.existing.iter().cloned().collect();
            let idx = self.rng.gen_range(0..existing_vec.len());
            let n = existing_vec[idx].clone();
            self.existing.remove(&n);
            n
        };
        Operation {
            op_type: OpType::Remove,
            name,
            payload: Vec::new(),
            encrypted: false,
        }
    }

    fn choose_payload_size(&mut self) -> usize {
        let r = self.rng.gen::<f64>();
        if r < 0.70 {
            self.rng.gen_range(1..=1024)
        } else if r < 0.95 {
            self.rng.gen_range(1025..=5120)
        } else {
            self.rng.gen_range(5121..=16384)
        }
    }
}
