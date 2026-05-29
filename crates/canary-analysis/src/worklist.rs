//! Generic worklist algorithm utilities.
//!
//! Many data-flow analyses share a common structure:
//! 1. Initialize a set of facts
//! 2. Process blocks from a worklist, propagating facts
//! 3. Add predecessors/successors to the worklist when facts change
//! 4. Repeat until fixpoint
//!
//! This module provides that framework.

use canary_ir::cfg::BlockId;
use indexmap::IndexSet;
use std::collections::VecDeque;

/// A worklist for iterative data-flow analysis.
pub struct Worklist {
    queue: VecDeque<BlockId>,
    in_queue: IndexSet<BlockId>,
}

impl Worklist {
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            in_queue: IndexSet::new(),
        }
    }

    /// Pushes `block` onto the worklist if it is not already present.
    pub fn push(&mut self, block: BlockId) {
        if self.in_queue.insert(block) {
            self.queue.push_back(block);
        }
    }

    /// Pops the next block from the worklist, or returns `None` if empty.
    pub fn pop(&mut self) -> Option<BlockId> {
        let b = self.queue.pop_front()?;
        self.in_queue.remove(&b);
        Some(b)
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

impl Default for Worklist {
    fn default() -> Self {
        Self::new()
    }
}
