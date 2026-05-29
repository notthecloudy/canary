//! Struct Layout Inference
//!
//! Infers `IrType::Struct` layouts from clustered memory accesses.

use crate::vsa::{PtrBase, ValueSet, VsaResult};
use canary_ir::ssa::{SsaDest, SsaExpr, SsaFunction, SsaInstr, SsaName};
use canary_ir::types::{IrType, StructField, TypeArena, TypeId};
use indexmap::IndexMap;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct StructAccess {
    pub base: SsaName,
    pub offset: i64,
    pub size: u8,
    pub is_write: bool,
}

pub fn collect_struct_accesses(func: &SsaFunction, vsa: &VsaResult) -> Vec<StructAccess> {
    let mut accesses = Vec::new();

    fn walk_expr(expr: &SsaExpr, accesses: &mut Vec<StructAccess>, is_write: bool) {
        match expr {
            SsaExpr::Load { addr, size } => {
                if let SsaExpr::BinOp {
                    op: canary_ir::llil::LlilOp::Add,
                    lhs,
                    rhs,
                    ..
                } = &**addr
                {
                    if let (SsaExpr::Reg { reg, .. }, SsaExpr::Const { value, .. }) =
                        (&**lhs, &**rhs)
                    {
                        accesses.push(StructAccess {
                            base: *reg,
                            offset: *value as i64,
                            size: size.bytes(),
                            is_write,
                        });
                    }
                    if let (SsaExpr::Const { value, .. }, SsaExpr::Reg { reg, .. }) =
                        (&**lhs, &**rhs)
                    {
                        accesses.push(StructAccess {
                            base: *reg,
                            offset: *value as i64,
                            size: size.bytes(),
                            is_write,
                        });
                    }
                }
                if let SsaExpr::Reg { reg, .. } = &**addr {
                    accesses.push(StructAccess {
                        base: *reg,
                        offset: 0,
                        size: size.bytes(),
                        is_write,
                    });
                }
                walk_expr(addr, accesses, false);
            }
            SsaExpr::BinOp { lhs, rhs, .. } => {
                walk_expr(lhs, accesses, false);
                walk_expr(rhs, accesses, false);
            }
            SsaExpr::UnOp { operand, .. } => {
                walk_expr(operand, accesses, false);
            }
            SsaExpr::Sx { expr, .. } | SsaExpr::Zx { expr, .. } => {
                walk_expr(expr, accesses, false);
            }
            _ => {}
        }
    }

    for block in func.blocks.values() {
        for instr in &block.instrs {
            match instr {
                SsaInstr::Assign { dest, expr, .. } => {
                    if let SsaDest::Mem { addr, size } = dest {
                        if let SsaExpr::BinOp {
                            op: canary_ir::llil::LlilOp::Add,
                            lhs,
                            rhs,
                            ..
                        } = addr
                        {
                            if let (SsaExpr::Reg { reg, .. }, SsaExpr::Const { value, .. }) =
                                (&**lhs, &**rhs)
                            {
                                accesses.push(StructAccess {
                                    base: *reg,
                                    offset: *value as i64,
                                    size: size.bytes(),
                                    is_write: true,
                                });
                            }
                            if let (SsaExpr::Const { value, .. }, SsaExpr::Reg { reg, .. }) =
                                (&**lhs, &**rhs)
                            {
                                accesses.push(StructAccess {
                                    base: *reg,
                                    offset: *value as i64,
                                    size: size.bytes(),
                                    is_write: true,
                                });
                            }
                        }
                        if let SsaExpr::Reg { reg, .. } = addr {
                            accesses.push(StructAccess {
                                base: *reg,
                                offset: 0,
                                size: size.bytes(),
                                is_write: true,
                            });
                        }
                        walk_expr(addr, &mut accesses, false);
                    }
                    walk_expr(expr, &mut accesses, false);
                }
                SsaInstr::Store {
                    addr, value, size, ..
                } => {
                    if let SsaExpr::BinOp {
                        op: canary_ir::llil::LlilOp::Add,
                        lhs,
                        rhs,
                        ..
                    } = addr
                    {
                        if let (SsaExpr::Reg { reg, .. }, SsaExpr::Const { value: c, .. }) =
                            (&**lhs, &**rhs)
                        {
                            accesses.push(StructAccess {
                                base: *reg,
                                offset: *c as i64,
                                size: size.bytes(),
                                is_write: true,
                            });
                        }
                        if let (SsaExpr::Const { value: c, .. }, SsaExpr::Reg { reg, .. }) =
                            (&**lhs, &**rhs)
                        {
                            accesses.push(StructAccess {
                                base: *reg,
                                offset: *c as i64,
                                size: size.bytes(),
                                is_write: true,
                            });
                        }
                    }
                    if let SsaExpr::Reg { reg, .. } = addr {
                        accesses.push(StructAccess {
                            base: *reg,
                            offset: 0,
                            size: size.bytes(),
                            is_write: true,
                        });
                    }
                    walk_expr(addr, &mut accesses, false);
                    walk_expr(value, &mut accesses, false);
                }
                SsaInstr::If { cond, .. } => walk_expr(cond, &mut accesses, false),
                SsaInstr::Call { target, args, .. } => {
                    walk_expr(target, &mut accesses, false);
                    for arg in args {
                        walk_expr(arg, &mut accesses, false);
                    }
                }
                SsaInstr::Return { value: Some(v), .. } => walk_expr(v, &mut accesses, false),
                SsaInstr::Intrinsic { inputs, .. } => {
                    for input in inputs {
                        walk_expr(input, &mut accesses, false);
                    }
                }
                SsaInstr::SetFlags { lhs, rhs, .. } => {
                    walk_expr(lhs, &mut accesses, false);
                    walk_expr(rhs, &mut accesses, false);
                }
                _ => {}
            }
        }
    }

    let mut filtered = Vec::new();
    for acc in accesses {
        if let Some(ValueSet::PtrOffset {
            base: PtrBase::StackFrame,
            ..
        }) = vsa.values.get(&acc.base)
        {
            continue;
        }
        filtered.push(acc);
    }
    filtered
}

pub fn infer_struct_layouts(
    accesses: &[StructAccess],
    type_arena: &mut TypeArena,
) -> IndexMap<SsaName, TypeId> {
    let mut groups: IndexMap<SsaName, BTreeMap<i64, u8>> = IndexMap::new();

    for acc in accesses {
        let entry = groups.entry(acc.base).or_default();
        let max_size = entry.entry(acc.offset).or_insert(acc.size);
        if acc.size > *max_size {
            *max_size = acc.size;
        }
    }

    let mut result = IndexMap::new();

    for (base, group) in groups {
        if group.len() < 2 {
            continue;
        }

        // Handle aliased fields: if fields overlap, take the max size and drop the enclosed one
        let mut clustered: Vec<(i64, u8)> = Vec::new();
        for (offset, size) in group {
            if let Some(last) = clustered.last_mut() {
                let last_end = last.0 + (last.1 as i64);
                if offset < last_end {
                    let new_end = std::cmp::max(last_end, offset + (size as i64));
                    last.1 = (new_end - last.0) as u8;
                    continue;
                }
            }
            clustered.push((offset, size));
        }

        let mut fields = Vec::new();
        let mut current_offset = 0i64;
        let mut has_vtable_pattern = false;

        for (offset, size) in clustered {
            if offset < 0 {
                continue;
            }

            if offset > current_offset {
                let pad_size = offset - current_offset;
                let element_ty = type_arena.alloc(IrType::Int {
                    bit_width: 8,
                    signed: false,
                });
                let array_ty = type_arena.alloc(IrType::Array {
                    element: element_ty,
                    count: pad_size as u64,
                });
                fields.push(StructField {
                    offset: current_offset as u64,
                    name: format!("pad_0x{:x}", current_offset),
                    ty: array_ty,
                });
            }

            // Vtable pattern heuristic: First field is pointer sized (8 bytes on 64-bit)
            if offset == 0 && size == 8 {
                has_vtable_pattern = true;
            }

            // Enum / Bitfield heuristic: Size is small (e.g. 1 or 2 bytes) but accessed sequentially
            let field_name = if size == 1 {
                format!("bitfield_0x{:x}", offset)
            } else if offset == 0 && has_vtable_pattern {
                "vtable".to_string()
            } else {
                format!("field_0x{:x}", offset)
            };

            fields.push(StructField {
                offset: offset as u64,
                name: field_name,
                ty: type_arena.alloc(IrType::Int {
                    bit_width: size * 8,
                    signed: false,
                }),
            });

            current_offset = offset + (size as i64);
        }

        if !fields.is_empty() {
            let mut struct_name = format!("Struct_{}_{}", base.reg, base.version);
            if has_vtable_pattern {
                struct_name = format!("Class_{}_{}", base.reg, base.version);
            }

            let struct_ty = IrType::Struct {
                name: Some(struct_name),
                fields,
            };
            let id = type_arena.alloc(struct_ty);
            result.insert(base, id);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use canary_ir::cfg::BlockId;
    use canary_ir::llil::{OperandSize, Reg};
    use canary_ir::ssa::SsaBlock;

    fn make_test_vsa() -> VsaResult {
        VsaResult {
            values: indexmap::IndexMap::new(),
        }
    }

    #[test]
    fn struct_two_fields() {
        let vsa = make_test_vsa();
        let mut func = SsaFunction {
            entry_addr: 0,
            name: "".into(),
            blocks: indexmap::IndexMap::new(),
        };

        let ptr = SsaName {
            reg: Reg(10),
            version: 1,
        };

        let block = SsaBlock {
            id: BlockId(0),
            phis: vec![],
            instrs: vec![
                SsaInstr::Store {
                    confidence: Default::default(),
                    addr: SsaExpr::Reg {
                        reg: ptr,
                        size: OperandSize::Bits64,
                    },
                    value: SsaExpr::Const {
                        value: 0,
                        size: OperandSize::Bits64,
                    },
                    size: OperandSize::Bits64,
                },
                SsaInstr::Store {
                    confidence: Default::default(),
                    addr: SsaExpr::BinOp {
                        op: canary_ir::llil::LlilOp::Add,
                        lhs: Box::new(SsaExpr::Reg {
                            reg: ptr,
                            size: OperandSize::Bits64,
                        }),
                        rhs: Box::new(SsaExpr::Const {
                            value: 8,
                            size: OperandSize::Bits64,
                        }),
                        size: OperandSize::Bits64,
                    },
                    value: SsaExpr::Const {
                        value: 0,
                        size: OperandSize::Bits32,
                    },
                    size: OperandSize::Bits32,
                },
            ],
        };
        func.blocks.insert(BlockId(0), block);

        let accesses = collect_struct_accesses(&func, &vsa);
        assert_eq!(accesses.len(), 2);

        let mut arena = TypeArena::new();
        let layouts = infer_struct_layouts(&accesses, &mut arena);

        assert!(layouts.contains_key(&ptr));
        let ty_id = layouts[&ptr];

        if let IrType::Struct { fields, .. } = arena.get(ty_id).unwrap() {
            assert_eq!(fields.len(), 2);
            assert_eq!(fields[0].offset, 0);
            assert_eq!(fields[1].offset, 8);
        } else {
            panic!("Expected struct type");
        }
    }

    #[test]
    fn struct_aliased_fields() {
        let vsa = make_test_vsa();
        let mut func = SsaFunction {
            entry_addr: 0,
            name: "".into(),
            blocks: indexmap::IndexMap::new(),
        };

        let ptr = SsaName {
            reg: Reg(10),
            version: 1,
        };

        let block = SsaBlock {
            id: BlockId(0),
            phis: vec![],
            instrs: vec![
                SsaInstr::Store {
                    confidence: Default::default(),
                    addr: SsaExpr::Reg {
                        reg: ptr,
                        size: OperandSize::Bits64,
                    },
                    value: SsaExpr::Const {
                        value: 0,
                        size: OperandSize::Bits64,
                    },
                    size: OperandSize::Bits64,
                },
                SsaInstr::Store {
                    confidence: Default::default(),
                    addr: SsaExpr::Reg {
                        reg: ptr,
                        size: OperandSize::Bits64,
                    },
                    value: SsaExpr::Const {
                        value: 0,
                        size: OperandSize::Bits32,
                    },
                    size: OperandSize::Bits32,
                },
            ],
        };
        func.blocks.insert(BlockId(0), block);

        let accesses = collect_struct_accesses(&func, &vsa);
        let mut arena = TypeArena::new();
        let layouts = infer_struct_layouts(&accesses, &mut arena);

        // Len is < 2 (only offset 0 is accessed), so no struct inferred!
        assert!(!layouts.contains_key(&ptr));
    }

    #[test]
    fn struct_padding_inserted() {
        let vsa = make_test_vsa();
        let mut func = SsaFunction {
            entry_addr: 0,
            name: "".into(),
            blocks: indexmap::IndexMap::new(),
        };

        let ptr = SsaName {
            reg: Reg(10),
            version: 1,
        };

        let block = SsaBlock {
            id: BlockId(0),
            phis: vec![],
            instrs: vec![
                SsaInstr::Store {
                    confidence: Default::default(),
                    addr: SsaExpr::Reg {
                        reg: ptr,
                        size: OperandSize::Bits64,
                    },
                    value: SsaExpr::Const {
                        value: 0,
                        size: OperandSize::Bits32,
                    }, // 4 bytes at offset 0
                    size: OperandSize::Bits32,
                },
                SsaInstr::Store {
                    confidence: Default::default(),
                    addr: SsaExpr::BinOp {
                        op: canary_ir::llil::LlilOp::Add,
                        lhs: Box::new(SsaExpr::Reg {
                            reg: ptr,
                            size: OperandSize::Bits64,
                        }),
                        rhs: Box::new(SsaExpr::Const {
                            value: 12,
                            size: OperandSize::Bits64,
                        }),
                        size: OperandSize::Bits64,
                    },
                    value: SsaExpr::Const {
                        value: 0,
                        size: OperandSize::Bits32,
                    }, // 4 bytes at offset 12
                    size: OperandSize::Bits32,
                },
            ],
        };
        func.blocks.insert(BlockId(0), block);

        let accesses = collect_struct_accesses(&func, &vsa);
        let mut arena = TypeArena::new();
        let layouts = infer_struct_layouts(&accesses, &mut arena);

        assert!(layouts.contains_key(&ptr));
        let ty_id = layouts[&ptr];

        if let IrType::Struct { fields, .. } = arena.get(ty_id).unwrap() {
            assert_eq!(fields.len(), 3); // field_0, pad_4, field_12
            assert_eq!(fields[0].offset, 0);
            assert_eq!(fields[1].offset, 4);
            assert!(fields[1].name.starts_with("pad_"));
            assert_eq!(fields[2].offset, 12);
        } else {
            panic!("Expected struct type");
        }
    }

    #[test]
    fn struct_no_pattern() {
        let vsa = make_test_vsa();
        let mut func = SsaFunction {
            entry_addr: 0,
            name: "".into(),
            blocks: indexmap::IndexMap::new(),
        };

        let ptr = SsaName {
            reg: Reg(10),
            version: 1,
        };

        let block = SsaBlock {
            id: BlockId(0),
            phis: vec![],
            instrs: vec![SsaInstr::Store {
                confidence: Default::default(),
                addr: SsaExpr::Reg {
                    reg: ptr,
                    size: OperandSize::Bits64,
                },
                value: SsaExpr::Const {
                    value: 0,
                    size: OperandSize::Bits64,
                },
                size: OperandSize::Bits64,
            }],
        };
        func.blocks.insert(BlockId(0), block);

        let accesses = collect_struct_accesses(&func, &vsa);
        let mut arena = TypeArena::new();
        let layouts = infer_struct_layouts(&accesses, &mut arena);

        assert!(!layouts.contains_key(&ptr));
    }
}
