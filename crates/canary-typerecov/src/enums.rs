use canary_ir::function::FunctionArena;
use canary_ir::llil::LlilOp;
use canary_ir::ssa::{SsaExpr, SsaInstr, SsaName};
use canary_sdb::types::{EnumVariant, SdbEnum};
use canary_sdb::{RecoveryOrigin, SdbEntry, SemanticDatabase};
use indexmap::{IndexMap, IndexSet};

pub fn recover_enums(sdb: &mut SemanticDatabase, functions: &FunctionArena) {
    let mut enum_counter = 0;

    for (_, func) in functions.iter() {
        if let Some(ssa) = &func.ssa {
            let mut comparisons: IndexMap<SsaName, IndexSet<i64>> = IndexMap::new();

            for block in ssa.blocks.values() {
                for instr in &block.instrs {
                    // Check Assign
                    if let SsaInstr::Assign { expr, .. } = instr {
                        if let SsaExpr::BinOp {
                            op: LlilOp::CmpE,
                            lhs,
                            rhs,
                            ..
                        } = expr
                        {
                            if let (SsaExpr::Reg { reg, .. }, SsaExpr::Const { value, .. }) =
                                (&**lhs, &**rhs)
                            {
                                comparisons.entry(*reg).or_default().insert(*value as i64);
                            } else if let (SsaExpr::Const { value, .. }, SsaExpr::Reg { reg, .. }) =
                                (&**lhs, &**rhs)
                            {
                                comparisons.entry(*reg).or_default().insert(*value as i64);
                            }
                        }
                    }

                    // Check If
                    if let SsaInstr::If { cond, .. } = instr {
                        if let SsaExpr::BinOp {
                            op: LlilOp::CmpE,
                            lhs,
                            rhs,
                            ..
                        } = cond
                        {
                            if let (SsaExpr::Reg { reg, .. }, SsaExpr::Const { value, .. }) =
                                (&**lhs, &**rhs)
                            {
                                comparisons.entry(*reg).or_default().insert(*value as i64);
                            } else if let (SsaExpr::Const { value, .. }, SsaExpr::Reg { reg, .. }) =
                                (&**lhs, &**rhs)
                            {
                                comparisons.entry(*reg).or_default().insert(*value as i64);
                            }
                        }
                    }
                }
            }

            for (_reg, values) in comparisons {
                if values.len() >= 3 {
                    let mut variants = Vec::new();
                    let mut sorted_vals: Vec<i64> = values.into_iter().collect();
                    sorted_vals.sort_unstable();

                    for val in sorted_vals {
                        variants.push(EnumVariant {
                            discriminant: val,
                            name: format!("State_{}", val),
                        });
                    }

                    sdb.interpretations.types.enums.push(SdbEntry::new(
                        SdbEnum {
                            name: format!("Enum_{}_{}", func.name, enum_counter),
                            variants,
                        },
                        canary_sdb::ConfidenceVector::base(0.7),
                        RecoveryOrigin::Heuristic,
                    ));
                    enum_counter += 1;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use canary_ir::cfg::BlockId;
    use canary_ir::llil::{OperandSize, Reg};
    use canary_ir::ssa::{SsaBlock, SsaFunction, SsaName};

    #[test]
    fn test_recover_enums() {
        let mut sdb = SemanticDatabase::new();
        let mut arena = FunctionArena::new();

        let mut func = canary_ir::function::Function {
            entry_addr: 0,
            name: "sub_100".into(),
            cfg: canary_ir::cfg::ControlFlowGraph::new(),
            ssa: None,
            semantic: None,
            mlil: None,
            is_lifted: true,
        };

        let mut ssa_func = SsaFunction {
            entry_addr: 0,
            name: "sub_100".into(),
            blocks: indexmap::IndexMap::new(),
        };
        let block = SsaBlock {
            id: BlockId(0),
            phis: vec![],
            instrs: vec![
                SsaInstr::If {
                    confidence: Default::default(),
                    cond: SsaExpr::BinOp {
                        op: LlilOp::CmpE,
                        lhs: Box::new(SsaExpr::Reg {
                            reg: SsaName {
                                reg: Reg(0),
                                version: 1,
                            },
                            size: OperandSize::Bits32,
                        }),
                        rhs: Box::new(SsaExpr::Const {
                            value: 0,
                            size: OperandSize::Bits32,
                        }),
                        size: OperandSize::Bits8,
                    },
                    true_target: 1,
                    false_target: 2,
                },
                SsaInstr::If {
                    confidence: Default::default(),
                    cond: SsaExpr::BinOp {
                        op: LlilOp::CmpE,
                        lhs: Box::new(SsaExpr::Reg {
                            reg: SsaName {
                                reg: Reg(0),
                                version: 1,
                            },
                            size: OperandSize::Bits32,
                        }),
                        rhs: Box::new(SsaExpr::Const {
                            value: 1,
                            size: OperandSize::Bits32,
                        }),
                        size: OperandSize::Bits8,
                    },
                    true_target: 3,
                    false_target: 4,
                },
                SsaInstr::If {
                    confidence: Default::default(),
                    cond: SsaExpr::BinOp {
                        op: LlilOp::CmpE,
                        lhs: Box::new(SsaExpr::Reg {
                            reg: SsaName {
                                reg: Reg(0),
                                version: 1,
                            },
                            size: OperandSize::Bits32,
                        }),
                        rhs: Box::new(SsaExpr::Const {
                            value: 5,
                            size: OperandSize::Bits32,
                        }),
                        size: OperandSize::Bits8,
                    },
                    true_target: 5,
                    false_target: 6,
                },
            ],
        };
        ssa_func.blocks.insert(BlockId(0), block);
        func.ssa = Some(ssa_func);

        arena.alloc(func);

        recover_enums(&mut sdb, &arena);

        assert_eq!(sdb.interpretations.types.enums.len(), 1);
        let e = &sdb.interpretations.types.enums[0].value;
        assert_eq!(e.variants.len(), 3);
        assert_eq!(e.variants[2].discriminant, 5);
        assert_eq!(e.variants[2].name, "State_5");
    }
}
