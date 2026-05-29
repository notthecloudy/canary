use canary_ir::function::FunctionArena;
use canary_ir::llil::LlilOp;
use canary_ir::ssa::{SsaExpr, SsaInstr};
use canary_sdb::types::SdbArray;
use canary_sdb::{RecoveryOrigin, SdbEntry, SemanticDatabase};

/// Maps an array element stride (in bytes) to a concrete element type name.
pub fn stride_to_element_ty(stride: usize) -> String {
    match stride {
        1 => "u8".to_string(),
        2 => "u16".to_string(),
        4 => "u32".to_string(),
        8 => "u64".to_string(),
        16 => "__m128".to_string(),
        s => format!("[u8; {}]", s),
    }
}

pub fn recover_arrays(sdb: &mut SemanticDatabase, functions: &FunctionArena) {
    for (_, func) in functions.iter() {
        if let Some(ssa) = &func.ssa {
            for block in ssa.blocks.values() {
                for instr in &block.instrs {
                    let mut check_expr = |expr: &SsaExpr| {
                        // Looking for Load or Store address expressions that look like: base + (index * stride)
                        let addr = match expr {
                            SsaExpr::Load { addr, .. } => &**addr,
                            _ => return,
                        };

                        if let SsaExpr::BinOp {
                            op: LlilOp::Add,
                            lhs,
                            rhs,
                            ..
                        } = addr
                        {
                            let (mut base, mut offset) = (None, None);

                            if let SsaExpr::Reg { reg, .. } = &**lhs {
                                base = Some(*reg);
                            }
                            if let SsaExpr::BinOp {
                                op: LlilOp::MuluDp, ..
                            }
                            | SsaExpr::BinOp {
                                op: LlilOp::MulsDp, ..
                            } = &**lhs
                            {
                                offset = Some(&**lhs);
                            }

                            if let SsaExpr::Reg { reg, .. } = &**rhs {
                                base = Some(*reg);
                            }
                            if let SsaExpr::BinOp {
                                op: LlilOp::MuluDp, ..
                            }
                            | SsaExpr::BinOp {
                                op: LlilOp::MulsDp, ..
                            } = &**rhs
                            {
                                offset = Some(&**rhs);
                            }

                            if let (
                                Some(_base),
                                Some(SsaExpr::BinOp {
                                    op: _,
                                    lhs: offset_lhs,
                                    rhs: offset_rhs,
                                    ..
                                }),
                            ) = (base, offset)
                            {
                                let mut stride = None;
                                if let SsaExpr::Const { value, .. } = &**offset_lhs {
                                    stride = Some(*value);
                                }
                                if let SsaExpr::Const { value, .. } = &**offset_rhs {
                                    stride = Some(*value);
                                }

                                if let Some(s) = stride {
                                    let stride_usize = s as usize;
                                    sdb.interpretations.types.arrays.push(SdbEntry::new(
                                        SdbArray {
                                            element_ty: stride_to_element_ty(stride_usize),
                                            stride: stride_usize,
                                            count_hint: None,
                                        },
                                        canary_sdb::ConfidenceVector::base(0.6),
                                        RecoveryOrigin::Pattern,
                                    ));
                                }
                            }
                        }
                    };

                    match instr {
                        SsaInstr::Assign { expr, .. } => check_expr(expr),
                        SsaInstr::Store { addr, value, .. } => {
                            check_expr(&SsaExpr::Load {
                                addr: Box::new(addr.clone()),
                                size: canary_ir::llil::OperandSize::Bits32,
                            });
                            check_expr(value);
                        }
                        SsaInstr::If { cond, .. } => check_expr(cond),
                        SsaInstr::Call { target, args, .. } => {
                            check_expr(target);
                            for arg in args {
                                check_expr(arg);
                            }
                        }
                        _ => {}
                    }
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
    use canary_ir::ssa::{SsaBlock, SsaDest, SsaFunction, SsaName};

    #[test]
    fn test_stride_to_element_ty() {
        assert_eq!(stride_to_element_ty(1), "u8");
        assert_eq!(stride_to_element_ty(2), "u16");
        assert_eq!(stride_to_element_ty(4), "u32");
        assert_eq!(stride_to_element_ty(8), "u64");
        assert_eq!(stride_to_element_ty(16), "__m128");
        assert_eq!(stride_to_element_ty(12), "[u8; 12]");
        assert_eq!(stride_to_element_ty(24), "[u8; 24]");
    }

    #[test]
    fn test_recover_arrays() {
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
            instrs: vec![SsaInstr::Assign {
                confidence: Default::default(),
                dest: SsaDest::Reg(SsaName {
                    reg: Reg(10),
                    version: 1,
                }),
                expr: SsaExpr::Load {
                    addr: Box::new(SsaExpr::BinOp {
                        op: LlilOp::Add,
                        lhs: Box::new(SsaExpr::Reg {
                            reg: SsaName {
                                reg: Reg(0),
                                version: 1,
                            },
                            size: OperandSize::Bits64,
                        }),
                        rhs: Box::new(SsaExpr::BinOp {
                            op: LlilOp::MuluDp,
                            lhs: Box::new(SsaExpr::Reg {
                                reg: SsaName {
                                    reg: Reg(1),
                                    version: 1,
                                },
                                size: OperandSize::Bits64,
                            }),
                            rhs: Box::new(SsaExpr::Const {
                                value: 8,
                                size: OperandSize::Bits64,
                            }),
                            size: OperandSize::Bits64,
                        }),
                        size: OperandSize::Bits64,
                    }),
                    size: OperandSize::Bits64,
                },
            }],
        };
        ssa_func.blocks.insert(BlockId(0), block);
        func.ssa = Some(ssa_func);

        arena.alloc(func);

        recover_arrays(&mut sdb, &arena);

        assert_eq!(sdb.interpretations.types.arrays.len(), 1);
        let arr = &sdb.interpretations.types.arrays[0].value;
        assert_eq!(arr.stride, 8);
        assert_eq!(arr.element_ty, "u64");
    }
}
