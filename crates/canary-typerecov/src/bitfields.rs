use canary_ir::function::FunctionArena;
use canary_ir::llil::LlilOp;
use canary_ir::ssa::{SsaExpr, SsaInstr};
use canary_sdb::types::{SdbStruct, StructField};
use canary_sdb::{RecoveryOrigin, SdbEntry, SemanticDatabase};

/// Count the number of set bits in a mask value.
fn popcount(mask: u64) -> u8 {
    mask.count_ones() as u8
}

pub fn recover_bitfields(sdb: &mut SemanticDatabase, functions: &FunctionArena) {
    for (_, func) in functions.iter() {
        if let Some(ssa) = &func.ssa {
            for block in ssa.blocks.values() {
                for instr in &block.instrs {
                    let mut check_expr = |expr: &SsaExpr| {
                        // Looking for (value & CONST_MASK) >> CONST_SHIFT or similar
                        // In SsaExpr this would be BinOp { Lsr, lhs: BinOp { And, .. }, rhs: Const }
                        if let SsaExpr::BinOp {
                            op: LlilOp::Lsr,
                            lhs,
                            rhs: shift_expr,
                            ..
                        } = expr
                        {
                            if let (
                                SsaExpr::BinOp {
                                    op: LlilOp::And,
                                    lhs: val_expr,
                                    rhs: mask_expr,
                                    ..
                                },
                                SsaExpr::Const {
                                    value: shift_val, ..
                                },
                            ) = (&**lhs, &**shift_expr)
                            {
                                let mut mask_val = None;
                                if let SsaExpr::Const { value, .. } = &**mask_expr {
                                    mask_val = Some(*value);
                                }
                                if let SsaExpr::Const { value, .. } = &**val_expr {
                                    mask_val = Some(*value);
                                } // Commutative

                                if let Some(mask) = mask_val {
                                    let bit_width = popcount(mask);
                                    let bit_shift = (*shift_val).min(u8::MAX as u64) as u8;

                                    // Try to find a matching struct field by offset, then annotate it.
                                    // We use bit_shift as a byte-offset approximation (shift / 8) for lookup.
                                    let byte_offset = (bit_shift / 8) as i64;
                                    let matched_struct_idx =
                                        sdb.interpretations.types.structs.iter().position(|s| {
                                            s.value.fields.iter().any(|f| f.offset == byte_offset)
                                        });

                                    if let Some(si) = matched_struct_idx {
                                        // Annotate the first matching field in that struct
                                        let struct_entry =
                                            &mut sdb.interpretations.types.structs[si];
                                        if let Some(field) = struct_entry
                                            .value
                                            .fields
                                            .iter_mut()
                                            .find(|f| f.offset == byte_offset)
                                        {
                                            field.bit_mask = Some(mask);
                                            field.bit_shift = Some(bit_shift);
                                            field.bit_width = Some(bit_width);
                                        }
                                    } else {
                                        // No matching struct found — create an anonymous bitfield container.
                                        sdb.interpretations.types.structs.push(SdbEntry::new(
                                            SdbStruct {
                                                name: format!(
                                                    "__bitfield_shift{}_width{}",
                                                    bit_shift, bit_width
                                                ),
                                                total_size: ((bit_shift as usize
                                                    + bit_width as usize)
                                                    + 7)
                                                    / 8,
                                                fields: vec![StructField {
                                                    offset: byte_offset,
                                                    size: ((bit_width as usize) + 7) / 8,
                                                    name: Some(format!(
                                                        "field_s{}_w{}",
                                                        bit_shift, bit_width
                                                    )),
                                                    ty_hint: None,
                                                    bit_mask: Some(mask),
                                                    bit_shift: Some(bit_shift),
                                                    bit_width: Some(bit_width),
                                                }],
                                            },
                                            canary_sdb::ConfidenceVector::base(0.65),
                                            RecoveryOrigin::Pattern,
                                        ));
                                    }
                                }
                            }
                        }
                    };

                    match instr {
                        SsaInstr::Assign { expr, .. } => check_expr(expr),
                        SsaInstr::Store { addr, value, .. } => {
                            check_expr(addr);
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
    fn test_recover_bitfields() {
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

        // Pattern: (r0_v1 & 0xF0) >> 4
        // mask = 0xF0 = 4 bits set, shift = 4
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
                expr: SsaExpr::BinOp {
                    op: LlilOp::Lsr,
                    lhs: Box::new(SsaExpr::BinOp {
                        op: LlilOp::And,
                        lhs: Box::new(SsaExpr::Reg {
                            reg: SsaName {
                                reg: Reg(0),
                                version: 1,
                            },
                            size: OperandSize::Bits32,
                        }),
                        rhs: Box::new(SsaExpr::Const {
                            value: 0xF0,
                            size: OperandSize::Bits32,
                        }),
                        size: OperandSize::Bits32,
                    }),
                    rhs: Box::new(SsaExpr::Const {
                        value: 4,
                        size: OperandSize::Bits32,
                    }),
                    size: OperandSize::Bits32,
                },
            }],
        };
        ssa_func.blocks.insert(BlockId(0), block);
        func.ssa = Some(ssa_func);

        arena.alloc(func);

        recover_bitfields(&mut sdb, &arena);

        // Should have created one anonymous bitfield struct
        assert_eq!(sdb.interpretations.types.structs.len(), 1);
        let s = &sdb.interpretations.types.structs[0].value;
        assert_eq!(s.fields.len(), 1);
        let f = &s.fields[0];
        assert_eq!(f.bit_mask, Some(0xF0));
        assert_eq!(f.bit_shift, Some(4));
        assert_eq!(f.bit_width, Some(4)); // 0xF0 has 4 set bits
    }
}
