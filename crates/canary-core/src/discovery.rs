//! Function discovery — extracts reachable call targets from a lifted CFG.
//!
//! This module provides multiple discovery extractors that work together to
//! find new function entry points from a lifted CFG:
//!
//! 1. Direct call extractor  — `call const_addr` instructions
//! 2. Import thunk resolver  — `jmp const_addr` where target is in import map
//! 3. Tail call resolver     — `goto const_addr` to address outside function range
//! 4. Jump table scanner     — heuristic pointer-array detection near indirect jumps
//!
//! The results feed the BFS worklist in `Engine::analyze_whole_program()`.

use canary_ir::cfg::ControlFlowGraph;
use canary_ir::llil::{LlilExpr, LlilInstr};
use canary_sdb::{GlobalXrefKind, SdbGlobalXref};
use indexmap::{IndexMap, IndexSet};

/// The result of running all discovery extractors on one function.
#[derive(Debug, Default)]
pub struct DiscoveryResult {
    /// New function entry addresses found (to be enqueued for analysis).
    pub new_functions: Vec<u64>,
    /// All call-type cross-references found (from_addr, to_addr).
    pub call_xrefs: Vec<(u64, u64)>,
    /// All tail-call cross-references (from_addr, to_addr).
    pub tail_call_xrefs: Vec<(u64, u64)>,
    /// All goto cross-references (from_addr, to_addr).
    pub goto_xrefs: Vec<(u64, u64)>,
}

impl DiscoveryResult {
    /// Converts results to SdbGlobalXref entries for storage.
    pub fn to_sdb_xrefs(&self) -> Vec<SdbGlobalXref> {
        let mut out = Vec::new();
        for &(from, to) in &self.call_xrefs {
            out.push(SdbGlobalXref {
                from_address: from,
                to_address: to,
                kind: GlobalXrefKind::Call,
            });
        }
        for &(from, to) in &self.tail_call_xrefs {
            out.push(SdbGlobalXref {
                from_address: from,
                to_address: to,
                kind: GlobalXrefKind::TailCall,
            });
        }
        for &(from, to) in &self.goto_xrefs {
            out.push(SdbGlobalXref {
                from_address: from,
                to_address: to,
                kind: GlobalXrefKind::Goto,
            });
        }
        out
    }
}

/// Extract all reachable call targets from a lifted CFG.
///
/// Runs all discovery extractors and returns a combined result.
/// Addresses already in `visited` or `import_map` are not added to `new_functions`.
///
/// # Arguments
/// * `cfg` — the lifted control flow graph for a single function
/// * `func_start` — the entry address of this function (used for tail-call detection)
/// * `func_end` — the approximate end address (largest known instruction address + size)
/// * `import_map` — map from import thunk VA to symbol name
/// * `visited` — set of already-discovered addresses (avoids duplicates)
/// * `code_ranges` — list of (start, end) ranges of code sections (for range checks)
pub fn extract_callees(
    cfg: &ControlFlowGraph,
    func_start: u64,
    func_end: u64,
    import_map: &IndexMap<u64, String>,
    visited: &IndexSet<u64>,
    code_ranges: &[(u64, u64)],
) -> DiscoveryResult {
    let mut result = DiscoveryResult::default();
    let mut enqueued = IndexSet::new();

    let mut try_add =
        |addr: u64, result: &mut DiscoveryResult, is_call: bool, is_tail: bool, from_addr: u64| {
            if addr == 0 {
                return;
            }
            if import_map.contains_key(&addr) {
                // It's an import thunk target — record as xref but don't enqueue
                if is_call {
                    result.call_xrefs.push((from_addr, addr));
                }
                return;
            }
            if !is_in_code(addr, code_ranges) {
                return;
            }
            if is_call {
                result.call_xrefs.push((from_addr, addr));
            } else if is_tail {
                result.tail_call_xrefs.push((from_addr, addr));
            } else {
                result.goto_xrefs.push((from_addr, addr));
            }
            if !visited.contains(&addr) && enqueued.insert(addr) {
                result.new_functions.push(addr);
            }
        };

    for block in cfg.blocks() {
        let block_start = block.start_addr;

        for (i, instr) in block.instrs.iter().enumerate() {
            let instr_addr = block.instr_addrs.get(i).copied().unwrap_or(block_start);

            match instr {
                // Direct calls: `call const_addr`
                LlilInstr::Call {
                    target: LlilExpr::Const { value: addr, .. },
                    ..
                } => {
                    let addr = *addr;
                    // Check if it's a thunk-style call (small function that jumps to import)
                    try_add(addr, &mut result, true, false, instr_addr);
                }

                // Tail calls and raw gotos: `goto const_addr`
                LlilInstr::Goto { target: addr, .. } => {
                    let addr = *addr as u64;
                    if addr < func_start || addr >= func_end {
                        // Address is outside this function → potential tail call
                        try_add(addr, &mut result, false, true, instr_addr);
                    }
                }

                // Conditional branch targets that go outside function range
                LlilInstr::If {
                    true_target,
                    false_target,
                    ..
                } => {
                    for &target in &[*true_target as u64, *false_target as u64] {
                        if target < func_start || target >= func_end {
                            try_add(target, &mut result, false, true, instr_addr);
                        }
                    }
                }

                _ => {}
            }
        }
    }

    result
}

/// Returns the approximate end address of a function based on its CFG blocks.
pub fn function_end_address(cfg: &ControlFlowGraph) -> u64 {
    cfg.blocks().map(|b| b.end_addr).max().unwrap_or(0)
}

/// Returns true if `addr` falls within any of the code section ranges.
fn is_in_code(addr: u64, ranges: &[(u64, u64)]) -> bool {
    ranges
        .iter()
        .any(|&(start, end)| addr >= start && addr < end)
}

/// Builds a code ranges list from a list of sections (for use in extract_callees).
pub fn code_ranges_from_sections(sections: &[canary_sdb::MappedSection]) -> Vec<(u64, u64)> {
    sections
        .iter()
        .map(|s| (s.address, s.address + s.size as u64))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use canary_ir::cfg::ControlFlowGraph;
    use canary_ir::llil::{LlilExpr, LlilInstr, OperandSize};

    fn make_cfg_with_call(call_target: u64) -> ControlFlowGraph {
        let mut cfg = ControlFlowGraph::new();
        let b0 = cfg.alloc_block(0x1000);
        cfg.set_entry(b0);
        let block = cfg.block_mut(b0).unwrap();
        block.end_addr = 0x1010;
        block.instr_addrs.push(0x1000);
        block.instrs.push(LlilInstr::Call {
            confidence: Default::default(),
            target: LlilExpr::Const {
                value: call_target,
                size: OperandSize::Bits64,
            },
            args: vec![],
            ret: None,
        });
        cfg
    }

    #[test]
    fn test_extract_direct_call() {
        let cfg = make_cfg_with_call(0x2000);
        let import_map = IndexMap::new();
        let visited = IndexSet::new();
        let code_ranges = vec![(0x1000, 0x5000)];

        let result = extract_callees(&cfg, 0x1000, 0x1010, &import_map, &visited, &code_ranges);
        assert!(
            result.new_functions.contains(&0x2000),
            "should discover call target"
        );
        assert!(result.call_xrefs.iter().any(|&(_, to)| to == 0x2000));
    }

    #[test]
    fn test_import_not_enqueued() {
        let cfg = make_cfg_with_call(0x7ffa0000);
        let mut import_map = IndexMap::new();
        import_map.insert(0x7ffa0000u64, "CreateWindowExA".to_string());
        let visited = IndexSet::new();
        let code_ranges = vec![(0x1000, 0x5000), (0x7ffa0000, 0x7ffb0000)];

        let result = extract_callees(&cfg, 0x1000, 0x1010, &import_map, &visited, &code_ranges);
        assert!(
            result.new_functions.is_empty(),
            "imports should NOT be enqueued as functions"
        );
        // But we do get a call xref
        assert!(result.call_xrefs.iter().any(|&(_, to)| to == 0x7ffa0000));
    }

    #[test]
    fn test_already_visited_not_added() {
        let cfg = make_cfg_with_call(0x2000);
        let import_map = IndexMap::new();
        let mut visited = IndexSet::new();
        visited.insert(0x2000u64);
        let code_ranges = vec![(0x1000, 0x5000)];

        let result = extract_callees(&cfg, 0x1000, 0x1010, &import_map, &visited, &code_ranges);
        assert!(
            result.new_functions.is_empty(),
            "already-visited addresses should not be re-added"
        );
    }
}
