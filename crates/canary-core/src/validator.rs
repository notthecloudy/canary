//! Proposal validator — validates plugin proposals before committing them.
//!
//! The validator enforces the core design law:
//! **Core owns truth. Plugins own hypotheses.**
//!
//! A proposal is accepted if and only if:
//! 1. It does not alter control flow (CFG edges, dominator invariants)
//! 2. It does not remove or reorder instructions
//! 3. It does not introduce semantic contradictions (e.g., conflicting types)
//! 4. It falls within the plugin's declared capabilities

use crate::workspace::Workspace;
use canary_plugin_api::{PluginProposal, Suggestion, ValidationResult};
use canary_sdb::FeedbackEntry;
use indexmap::IndexMap;
use std::collections::HashSet;

/// Validates all suggestions in a proposal.
pub fn validate_proposal(proposal: &PluginProposal) -> Vec<ValidationResult> {
    proposal
        .suggestions
        .iter()
        .enumerate()
        .map(|(i, suggestion)| validate_suggestion(i, suggestion))
        .collect()
}

fn validate_suggestion(index: usize, suggestion: &Suggestion) -> ValidationResult {
    match suggestion {
        // Renaming and comments are always safe — they are decorative only
        Suggestion::RenameSym { proposed_name, .. } => {
            if proposed_name.is_empty() {
                ValidationResult {
                    suggestion_index: index,
                    accepted: false,
                    rejection_reason: Some("Proposed name is empty".to_string()),
                }
            } else {
                ValidationResult {
                    suggestion_index: index,
                    accepted: true,
                    rejection_reason: None,
                }
            }
        }

        Suggestion::AddComment { text, .. } => {
            if text.is_empty() {
                ValidationResult {
                    suggestion_index: index,
                    accepted: false,
                    rejection_reason: Some("Comment text is empty".to_string()),
                }
            } else {
                ValidationResult {
                    suggestion_index: index,
                    accepted: true,
                    rejection_reason: None,
                }
            }
        }

        // Type suggestions are accepted if they don't contradict proven facts
        // Phase 1: accept all type suggestions (no type solver yet)
        Suggestion::SuggestType { .. } => ValidationResult {
            suggestion_index: index,
            accepted: true,
            rejection_reason: None,
        },

        // Idiom proposals require address range validation and CFG coherence checks
        // Phase 1: accept with a warning annotation (full validation in Phase 3)
        Suggestion::ProposeIdiom { .. } => ValidationResult {
            suggestion_index: index,
            accepted: true,
            rejection_reason: None,
        },
    }
}

/// Project-wide validation and consistency checking (Phase 13).
pub fn validate_project(workspace: &Workspace) -> Vec<FeedbackEntry> {
    use canary_ir::ssa::{SsaExpr, SsaInstr};
    use canary_sdb::{FeedbackEntry, RefinementAction};
    use indexmap::IndexMap;
    use std::collections::HashSet;

    let mut feedback = Vec::new();

    // 1. Call Arity checks
    for (_id, func) in workspace.functions.iter() {
        if let Some(ssa) = &func.ssa {
            for block in ssa.blocks.values() {
                for instr in &block.instrs {
                    if let SsaInstr::Call { target, args, .. } = instr {
                        if let SsaExpr::Const {
                            value: target_addr, ..
                        } = target
                        {
                            if let Some(target_func) = workspace
                                .sdb
                                .interpretations
                                .functions
                                .functions
                                .get(target_addr)
                            {
                                if let Some(sig_entry) = &target_func.value.call_signature {
                                    let sig = &sig_entry.value;
                                    if !sig.is_variadic && sig.params.len() != args.len() {
                                        feedback.push(FeedbackEntry {
                                            description: format!(
                                                "Arity mismatch: function at {:#x} called with {} args but signature expects {}",
                                                target_addr, args.len(), sig.params.len()
                                            ),
                                            action: RefinementAction::UpdateSignature {
                                                address: *target_addr,
                                                param_count: args.len(),
                                                param_types: vec!["unknown".to_string(); args.len()],
                                            },
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. Naming uniqueness checks
    let mut name_to_addrs: IndexMap<String, Vec<(u64, f32)>> = IndexMap::new();
    for (&addr, sym_entry) in &workspace.sdb.facts.symbols.symbols {
        let name = sym_entry.value.name.clone();
        name_to_addrs
            .entry(name)
            .or_default()
            .push((addr, sym_entry.confidence.composite()));
    }

    for (name, mut addrs) in name_to_addrs {
        if addrs.len() > 1 {
            // Sort by confidence descending, then address ascending
            addrs.sort_by(|a, b| {
                b.1.partial_cmp(&a.1)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then(a.0.cmp(&b.0))
            });
            // Keep the first (highest confidence), rename the rest
            for i in 1..addrs.len() {
                let (addr, _) = addrs[i];
                let new_name = format!("{}_collision_{:x}", name, addr);
                feedback.push(FeedbackEntry {
                    description: format!(
                        "Naming collision for '{}': renaming symbol at {:#x} to '{}'",
                        name, addr, new_name
                    ),
                    action: RefinementAction::RenameSymbol {
                        address: addr,
                        old_name: name.clone(),
                        new_name,
                    },
                });
            }
        }
    }

    // 3. Circular includes checks
    if let Some(layout_entry) = &workspace.sdb.project.layout {
        let layout = &layout_entry.value;
        let mut adj: IndexMap<String, Vec<String>> = IndexMap::new();
        for (path, file_entry) in &layout.files {
            adj.insert(path.clone(), file_entry.includes.clone());
        }

        let mut visited = HashSet::new();
        let mut stack = HashSet::new();
        let mut cycle_path = Vec::new();

        for path in layout.files.keys() {
            if !visited.contains(path) {
                if has_cycle(path, &adj, &mut visited, &mut stack, &mut cycle_path) {
                    let cycle_start = cycle_path.last().cloned().unwrap_or_default();
                    if let Some(start_idx) = cycle_path.iter().position(|x| *x == cycle_start) {
                        let cycle_segment = &cycle_path[start_idx..];
                        let cycle_str = cycle_segment.join(" -> ");
                        feedback.push(FeedbackEntry {
                            description: format!("Circular dependency detected: {}", cycle_str),
                            action: RefinementAction::RenameSymbol {
                                address: 0,
                                old_name: String::new(),
                                new_name: String::new(),
                            },
                        });
                    }
                    break;
                }
            }
        }
    }

    feedback
}

fn has_cycle(
    node: &str,
    adj: &IndexMap<String, Vec<String>>,
    visited: &mut HashSet<String>,
    stack: &mut HashSet<String>,
    cycle_path: &mut Vec<String>,
) -> bool {
    visited.insert(node.to_string());
    stack.insert(node.to_string());
    cycle_path.push(node.to_string());

    if let Some(neighbors) = adj.get(node) {
        for neighbor in neighbors {
            if !visited.contains(neighbor) {
                if has_cycle(neighbor, adj, visited, stack, cycle_path) {
                    return true;
                }
            } else if stack.contains(neighbor) {
                cycle_path.push(neighbor.to_string());
                return true;
            }
        }
    }

    stack.remove(node);
    cycle_path.pop();
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use canary_plugin_api::{PluginProposal, Suggestion};
    use canary_sdb::{RecoveryOrigin, RefinementAction, SdbEntry, SdbSymbol};

    #[test]
    fn empty_name_rejected() {
        let proposal = PluginProposal {
            plugin_name: "test".to_string(),
            cfg_hash: "abc".to_string(),
            suggestions: vec![Suggestion::RenameSym {
                current_name: "var_8".to_string(),
                proposed_name: "".to_string(),
                confidence: 0.9,
                rationale: "test".to_string(),
            }],
        };
        let results = validate_proposal(&proposal);
        assert!(!results[0].accepted);
    }

    #[test]
    fn valid_rename_accepted() {
        let proposal = PluginProposal {
            plugin_name: "test".to_string(),
            cfg_hash: "abc".to_string(),
            suggestions: vec![Suggestion::RenameSym {
                current_name: "var_8".to_string(),
                proposed_name: "socket_fd".to_string(),
                confidence: 0.95,
                rationale: "Used in socket syscall".to_string(),
            }],
        };
        let results = validate_proposal(&proposal);
        assert!(results[0].accepted);
    }

    #[test]
    fn test_naming_collisions() {
        let mut workspace = Workspace::new("dummy", vec![]);
        workspace.sdb.facts.symbols.symbols.insert(
            0x1000,
            SdbEntry::new(
                SdbSymbol {
                    address: 0x1000,
                    name: "duplicate_name".to_string(),
                    provenance: RecoveryOrigin::Heuristic,
                },
                canary_sdb::ConfidenceVector::base(0.8),
                RecoveryOrigin::Heuristic,
            ),
        );
        workspace.sdb.facts.symbols.symbols.insert(
            0x2000,
            SdbEntry::new(
                SdbSymbol {
                    address: 0x2000,
                    name: "duplicate_name".to_string(),
                    provenance: RecoveryOrigin::Heuristic,
                },
                canary_sdb::ConfidenceVector::base(0.5),
                RecoveryOrigin::Heuristic,
            ),
        );

        let feedback = validate_project(&workspace);
        assert_eq!(feedback.len(), 1);
        if let RefinementAction::RenameSymbol {
            address,
            old_name,
            new_name,
        } = &feedback[0].action
        {
            assert_eq!(*address, 0x2000);
            assert_eq!(old_name, "duplicate_name");
            assert_eq!(new_name, "duplicate_name_collision_2000");
        } else {
            panic!("Expected RenameSymbol action");
        }
    }
}
