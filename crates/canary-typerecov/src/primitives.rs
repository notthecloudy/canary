use canary_ir::llil::{LlilOp, OperandSize};
use canary_ir::ssa::{SsaDest, SsaExpr, SsaFunction, SsaInstr, SsaName};
use canary_ir::types::IrType;
use indexmap::IndexMap;

pub fn propagate_primitives(func: &SsaFunction) -> IndexMap<SsaName, IrType> {
    let mut types = IndexMap::new();

    let mut assign_type = |name: SsaName, ty: IrType| {
        types.insert(name, ty);
    };

    let size_to_int_ty = |size: OperandSize, signed: bool| -> IrType {
        IrType::Int {
            bit_width: size.bytes() * 8,
            signed,
        }
    };

    for block in func.blocks.values() {
        for instr in &block.instrs {
            match instr {
                SsaInstr::Assign { dest, expr, .. } => {
                    if let SsaDest::Reg(name) = dest {
                        match expr {
                            SsaExpr::BinOp { op, lhs, rhs, size } => {
                                let signed = match op {
                                    LlilOp::CmpSgt
                                    | LlilOp::CmpSge
                                    | LlilOp::CmpSlt
                                    | LlilOp::CmpSle
                                    | LlilOp::Divs
                                    | LlilOp::Mods => true,
                                    LlilOp::CmpUgt
                                    | LlilOp::CmpUge
                                    | LlilOp::CmpUlt
                                    | LlilOp::CmpUle
                                    | LlilOp::Divu
                                    | LlilOp::Modu => false,
                                    _ => false, // Default to unsigned for Add/Sub/etc if unknown
                                };
                                assign_type(*name, size_to_int_ty(*size, signed));

                                // If operands are regs, type them too
                                if let SsaExpr::Reg { reg, size: rsize } = &**lhs {
                                    assign_type(*reg, size_to_int_ty(*rsize, signed));
                                }
                                if let SsaExpr::Reg { reg, size: rsize } = &**rhs {
                                    assign_type(*reg, size_to_int_ty(*rsize, signed));
                                }
                            }
                            SsaExpr::UnOp {
                                op: _,
                                operand,
                                size,
                            } => {
                                let signed = false; // Negation/Not
                                assign_type(*name, size_to_int_ty(*size, signed));
                                if let SsaExpr::Reg { reg, size: rsize } = &**operand {
                                    assign_type(*reg, size_to_int_ty(*rsize, signed));
                                }
                            }
                            SsaExpr::Load { addr: _, size } => {
                                assign_type(*name, size_to_int_ty(*size, false));
                            }
                            _ => {}
                        }
                    }
                }
                SsaInstr::Store {
                    addr: _,
                    value: _,
                    size: _,
                    ..
                } => {}
                SsaInstr::If { cond, .. } => {
                    if let SsaExpr::BinOp { op, lhs, rhs, .. } = cond {
                        let signed = match op {
                            LlilOp::CmpSgt | LlilOp::CmpSge | LlilOp::CmpSlt | LlilOp::CmpSle => {
                                true
                            }
                            _ => false,
                        };
                        if let SsaExpr::Reg { reg, size } = &**lhs {
                            assign_type(*reg, size_to_int_ty(*size, signed));
                        }
                        if let SsaExpr::Reg { reg, size } = &**rhs {
                            assign_type(*reg, size_to_int_ty(*size, signed));
                        }
                    }
                }
                _ => {}
            }
        }
    }

    types
}

#[cfg(test)]
mod tests {
    use super::*;
    use canary_ir::cfg::BlockId;
    use canary_ir::llil::Reg;
    use canary_ir::ssa::SsaBlock;

    #[test]
    fn test_propagate_primitives() {
        let mut func = SsaFunction {
            entry_addr: 0,
            name: "".into(),
            blocks: indexmap::IndexMap::new(),
        };

        let block = SsaBlock {
            id: BlockId(0),
            phis: vec![],
            instrs: vec![
                SsaInstr::Assign {
                    confidence: Default::default(),
                    dest: SsaDest::Reg(SsaName {
                        reg: Reg(10),
                        version: 1,
                    }),
                    expr: SsaExpr::BinOp {
                        op: LlilOp::Add,
                        lhs: Box::new(SsaExpr::Reg {
                            reg: SsaName {
                                reg: Reg(0),
                                version: 0,
                            },
                            size: OperandSize::Bits32,
                        }),
                        rhs: Box::new(SsaExpr::Const {
                            value: 4,
                            size: OperandSize::Bits32,
                        }),
                        size: OperandSize::Bits32,
                    },
                },
                SsaInstr::If {
                    confidence: Default::default(),
                    cond: SsaExpr::BinOp {
                        op: LlilOp::CmpSlt,
                        lhs: Box::new(SsaExpr::Reg {
                            reg: SsaName {
                                reg: Reg(10),
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
            ],
        };
        func.blocks.insert(BlockId(0), block);

        let types = propagate_primitives(&func);
        assert!(types.contains_key(&SsaName {
            reg: Reg(0),
            version: 0
        }));
        assert!(types.contains_key(&SsaName {
            reg: Reg(10),
            version: 1
        }));

        match &types[&SsaName {
            reg: Reg(10),
            version: 1,
        }] {
            IrType::Int { bit_width, signed } => {
                assert_eq!(*bit_width, 32);
                assert!(*signed); // From CmpSlt
            }
            _ => panic!("Expected Int type"),
        }
    }
}
