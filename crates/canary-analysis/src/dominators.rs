//! Dominator tree computation using the Lengauer-Tarjan algorithm.
//!
//! The dominator tree is fundamental to:
//! - SSA construction (phi-node placement)
//! - Loop identification
//! - Control flow unflattening
//!
//! # Algorithm
//!
//! We implement the simple Cooper et al. (2001) "A Simple, Fast Dominance
//! Algorithm" for Phase 1. The Lengauer-Tarjan algorithm will be substituted
//! in Phase 2 for better performance on large functions.

use canary_ir::cfg::{BlockId, ControlFlowGraph, EdgeKind};
use indexmap::IndexMap;
use smallvec::SmallVec;

/// The computed dominator tree for a CFG.
///
/// For each block `b`, `idom[b]` is its **immediate dominator** — the closest
/// block that dominates `b` on every path from the entry.
#[derive(Debug)]
pub struct DominatorTree {
    /// Immediate dominator for each block. Entry block has no idom.
    pub idom: IndexMap<BlockId, BlockId>,
    /// Children in the dominator tree (blocks immediately dominated by key).
    pub children: IndexMap<BlockId, SmallVec<[BlockId; 4]>>,
}

/// Dominance query interface.
pub struct DominanceInfo {
    pub tree: DominatorTree,
    /// Post-order traversal number for each block.
    pub postorder: Vec<BlockId>,
}

impl DominanceInfo {
    /// Returns `true` if `a` dominates `b` (i.e., every path from entry to `b`
    /// goes through `a`).
    pub fn dominates(&self, a: BlockId, b: BlockId) -> bool {
        if a == b {
            return true;
        }
        let mut current = b;
        loop {
            match self.tree.idom.get(&current) {
                Some(&idom) => {
                    if idom == a {
                        return true;
                    }
                    current = idom;
                }
                None => return false,
            }
        }
    }

    /// Returns `true` if `a` strictly dominates `b` (dominates but is not equal to `b`).
    pub fn strictly_dominates(&self, a: BlockId, b: BlockId) -> bool {
        a != b && self.dominates(a, b)
    }
}

/// Computes the dominator tree for `cfg` using the Cooper et al. algorithm.
///
/// Returns `None` if the CFG has no entry block.
pub fn compute_dominators(cfg: &ControlFlowGraph) -> Option<DominanceInfo> {
    let entry = cfg.entry()?;

    // Compute post-order traversal
    let postorder = postorder_traversal(cfg, entry);
    let n = postorder.len();

    // Map block → post-order index
    let mut po_index: IndexMap<BlockId, usize> = IndexMap::new();
    for (i, &b) in postorder.iter().enumerate() {
        po_index.insert(b, i);
    }

    // Initialize idom: entry dominates itself; others unset (use n as sentinel)
    let mut idom: Vec<Option<usize>> = vec![None; n];
    let entry_po = *po_index.get(&entry)?;
    idom[entry_po] = Some(entry_po);

    // Cooper et al. iterative algorithm
    let mut changed = true;
    while changed {
        changed = false;
        // Iterate in reverse post-order (excluding entry)
        for i in (0..n).rev() {
            let b = postorder[i];
            if b == entry {
                continue;
            }

            let block = cfg.block(b)?;
            let preds: Vec<usize> = block
                .predecessors
                .iter()
                .filter_map(|p| po_index.get(p).copied())
                .filter(|&p_idx| idom[p_idx].is_some())
                .collect();

            if preds.is_empty() {
                continue;
            }

            let mut new_idom = preds[0];
            for &p in &preds[1..] {
                new_idom = intersect(&idom, new_idom, p);
            }

            if idom[i] != Some(new_idom) {
                idom[i] = Some(new_idom);
                changed = true;
            }
        }
    }

    // Build the DominatorTree from the idom array
    let mut idom_map: IndexMap<BlockId, BlockId> = IndexMap::new();
    let mut children: IndexMap<BlockId, SmallVec<[BlockId; 4]>> = IndexMap::new();

    for (i, &b) in postorder.iter().enumerate() {
        if b == entry {
            continue;
        }
        if let Some(idom_idx) = idom[i] {
            let idom_block = postorder[idom_idx];
            idom_map.insert(b, idom_block);
            children.entry(idom_block).or_default().push(b);
        }
    }

    Some(DominanceInfo {
        tree: DominatorTree {
            idom: idom_map,
            children,
        },
        postorder,
    })
}

/// Finger intersection for Cooper's algorithm.
fn intersect(idom: &[Option<usize>], mut a: usize, mut b: usize) -> usize {
    while a != b {
        while a < b {
            a = idom[a].unwrap_or(a);
        }
        while b < a {
            b = idom[b].unwrap_or(b);
        }
    }
    a
}

/// Computes a post-order traversal of the CFG from `entry`.
fn postorder_traversal(cfg: &ControlFlowGraph, entry: BlockId) -> Vec<BlockId> {
    let mut visited = indexmap::IndexSet::new();
    let mut order = Vec::new();
    dfs_postorder(cfg, entry, &mut visited, &mut order);
    order
}

fn dfs_postorder(
    cfg: &ControlFlowGraph,
    block: BlockId,
    visited: &mut indexmap::IndexSet<BlockId>,
    order: &mut Vec<BlockId>,
) {
    if !visited.insert(block) {
        return;
    }
    if let Some(b) = cfg.block(block) {
        for edge in &b.successors {
            dfs_postorder(cfg, edge.target, visited, order);
        }
    }
    order.push(block);
}

/// Identifies and marks back-edges in the CFG using dominance information.
/// An edge (A -> B) is a back-edge if B dominates A.
pub fn mark_back_edges(cfg: &mut ControlFlowGraph, dom_info: &DominanceInfo) {
    for block in cfg.blocks_mut() {
        for edge in &mut block.successors {
            if dom_info.dominates(edge.target, edge.source) {
                edge.kind = EdgeKind::Back;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use canary_ir::cfg::{ControlFlowGraph, EdgeKind};

    fn simple_diamond() -> ControlFlowGraph {
        let mut cfg = ControlFlowGraph::new();
        let entry = cfg.alloc_block(0x1000);
        let left = cfg.alloc_block(0x1010);
        let right = cfg.alloc_block(0x1020);
        let merge = cfg.alloc_block(0x1030);
        cfg.set_entry(entry);
        cfg.add_edge(entry, left, EdgeKind::True);
        cfg.add_edge(entry, right, EdgeKind::False);
        cfg.add_edge(left, merge, EdgeKind::Unconditional);
        cfg.add_edge(right, merge, EdgeKind::Unconditional);
        cfg
    }

    #[test]
    fn diamond_dominators() {
        let cfg = simple_diamond();
        let info = compute_dominators(&cfg).expect("dominators should compute");
        let entry = cfg.entry().unwrap();

        // Entry dominates everything
        for block in cfg.blocks() {
            assert!(
                info.dominates(entry, block.id),
                "entry should dominate all blocks"
            );
        }
    }
}
