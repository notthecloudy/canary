//! ProgramDatabase — global analysis state for whole-program analysis.
//!
//! This is the single source of truth for all discovered facts during
//! a whole-program analysis session.

use indexmap::{IndexMap, IndexSet};
use std::collections::VecDeque;

/// Global state for a whole-program analysis session.
///
/// Contains everything needed to track discovery progress, relate functions
/// to each other, and drive the analysis pipeline.
pub struct ProgramDatabase {
    /// All function addresses that have been discovered (including those pending analysis).
    pub discovered: IndexSet<u64>,
    /// Functions whose CFG has been fully lifted and SSA built.
    pub analyzed: IndexSet<u64>,
    /// Functions that failed to lift (e.g. decode error, unsupported instructions).
    pub failed: IndexSet<u64>,
    /// BFS work queue of addresses pending analysis.
    pub pending: VecDeque<u64>,
    /// Import Address Table: virtual address → symbol name.
    /// Used to avoid enqueueing imports as internal functions.
    pub import_map: IndexMap<u64, String>,
    /// Export table: virtual address → export name.
    pub export_map: IndexMap<u64, String>,
    /// Module cluster assignments derived from call graph locality.
    /// Maps function VA → cluster/module name.
    pub module_assignments: IndexMap<u64, String>,
}

impl ProgramDatabase {
    pub fn new() -> Self {
        Self {
            discovered: IndexSet::new(),
            analyzed: IndexSet::new(),
            failed: IndexSet::new(),
            pending: VecDeque::new(),
            import_map: IndexMap::new(),
            export_map: IndexMap::new(),
            module_assignments: IndexMap::new(),
        }
    }

    /// Enqueues a function address for analysis if not already seen.
    /// Returns true if the address was newly added.
    pub fn enqueue(&mut self, addr: u64) -> bool {
        if self.discovered.insert(addr) {
            self.pending.push_back(addr);
            true
        } else {
            false
        }
    }

    /// Dequeues the next address to analyze.
    pub fn next(&mut self) -> Option<u64> {
        self.pending.pop_front()
    }

    /// Marks an address as successfully analyzed.
    pub fn mark_analyzed(&mut self, addr: u64) {
        self.analyzed.insert(addr);
    }

    /// Marks an address as failed.
    pub fn mark_failed(&mut self, addr: u64) {
        self.failed.insert(addr);
    }

    /// Returns true if an address is a known import (should not be lifted).
    pub fn is_import(&self, addr: u64) -> bool {
        self.import_map.contains_key(&addr)
    }

    /// Returns the symbol name for an address if it is a known import.
    pub fn import_name(&self, addr: u64) -> Option<&str> {
        self.import_map.get(&addr).map(|s| s.as_str())
    }

    /// Summary statistics.
    pub fn stats(&self) -> ProgramStats {
        ProgramStats {
            discovered: self.discovered.len(),
            analyzed: self.analyzed.len(),
            failed: self.failed.len(),
            pending: self.pending.len(),
            imports: self.import_map.len(),
            exports: self.export_map.len(),
        }
    }
}

impl Default for ProgramDatabase {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct ProgramStats {
    pub discovered: usize,
    pub analyzed: usize,
    pub failed: usize,
    pub pending: usize,
    pub imports: usize,
    pub exports: usize,
}
