//! Lowers SSA/MLIL representation into Semantic IR.

use canary_ir::semantic::{SemanticBlock, SemanticFunction, SemanticInstr, StateTransition};
use canary_ir::ssa::{SsaExpr, SsaFunction, SsaInstr};
use std::collections::BTreeMap;

pub fn lower_to_semantic(func: &SsaFunction) -> SemanticFunction {
    lower_to_semantic_with_resolver(func, |_| None)
}

pub fn lower_to_semantic_with_sdb(
    func: &SsaFunction,
    sdb: &canary_sdb::SemanticDatabase,
) -> SemanticFunction {
    lower_to_semantic_with_resolver(func, |addr| {
        if let Some(import) = sdb
            .facts
            .binary
            .imports
            .iter()
            .find(|imp| imp.value.address == addr)
        {
            return Some(import.value.symbol_name.clone());
        }

        sdb.interpretations
            .functions
            .functions
            .get(&addr)
            .and_then(|func| func.value.name.clone())
    })
}

fn lower_to_semantic_with_resolver(
    func: &SsaFunction,
    resolve_symbol: impl Fn(u64) -> Option<String>,
) -> SemanticFunction {
    let mut blocks = BTreeMap::new();
    let mut instr_id = 0;

    for (block_id, ssa_block) in &func.blocks {
        let mut instrs = Vec::new();

        for ssa_instr in &ssa_block.instrs {
            match ssa_instr {
                SsaInstr::Call {
                    target, confidence, ..
                } => {
                    if let SsaExpr::Const { value, .. } = target {
                        let transition = resolve_symbol(*value)
                            .and_then(|name| classify_call(*value, &name))
                            .unwrap_or_else(|| {
                                StateTransition::UpdateState(*value, "DirectCall".to_string())
                            });

                        instrs.push(SemanticInstr {
                            id: instr_id,
                            address: *value,
                            transition,
                            confidence: confidence.clone(),
                        });
                        instr_id += 1;
                    }
                }
                SsaInstr::Store {
                    addr, confidence, ..
                } => {
                    if let SsaExpr::Const { value, .. } = addr {
                        instrs.push(SemanticInstr {
                            id: instr_id,
                            address: *value,
                            transition: StateTransition::UpdateState(
                                *value,
                                "MemoryWrite".to_string(),
                            ),
                            confidence: confidence.clone(),
                        });
                        instr_id += 1;
                    }
                }
                _ => {}
            }
        }

        blocks.insert(block_id.0 as usize, SemanticBlock { instrs });
    }

    SemanticFunction { blocks }
}

fn classify_call(target: u64, symbol_name: &str) -> Option<StateTransition> {
    let normalized = symbol_name.trim_start_matches('_').to_ascii_lowercase();
    let acquire_apis = [
        "createfilea",
        "createfilew",
        "openprocess",
        "openthread",
        "socket",
        "accept",
        "malloc",
        "calloc",
        "realloc",
        "operator new",
    ];
    let release_apis = [
        "closehandle",
        "closesocket",
        "free",
        "operator delete",
        "deletefilea",
        "deletefilew",
    ];

    if acquire_apis.iter().any(|name| normalized == *name) {
        Some(StateTransition::AcquireResource(target))
    } else if release_apis.iter().any(|name| normalized == *name) {
        Some(StateTransition::ReleaseResource(target))
    } else {
        Some(StateTransition::UpdateState(
            target,
            format!("Call:{symbol_name}"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use canary_ir::cfg::BlockId;
    use canary_ir::llil::OperandSize;
    use canary_ir::ssa::{SsaBlock, SsaFunction};

    #[test]
    fn unknown_constant_call_is_not_resource_transition() {
        let mut blocks = indexmap::IndexMap::new();
        blocks.insert(
            BlockId(0),
            SsaBlock {
                id: BlockId(0),
                phis: Vec::new(),
                instrs: vec![SsaInstr::Call {
                    target: SsaExpr::Const {
                        value: 0x1001,
                        size: OperandSize::Bits64,
                    },
                    args: Vec::new(),
                    ret: None,
                    confidence: Default::default(),
                }],
            },
        );
        let func = SsaFunction {
            entry_addr: 0x1000,
            name: String::new(),
            blocks,
        };

        let semantic = lower_to_semantic(&func);
        let transition = &semantic.blocks[&0].instrs[0].transition;

        assert!(
            matches!(transition, StateTransition::UpdateState(0x1001, label) if label == "DirectCall")
        );
    }

    #[test]
    fn resolved_closehandle_is_release_transition() {
        let transition = classify_call(0x2000, "CloseHandle").unwrap();
        assert!(matches!(
            transition,
            StateTransition::ReleaseResource(0x2000)
        ));
    }
}
