//! Stack Variable Recovery
//!
//! Maps stack frame offsets found by VSA into typed named variables.

use crate::vsa::{PtrBase, ValueSet, VsaResult};
use canary_ir::ssa::{SsaDest, SsaExpr, SsaFunction, SsaInstr};
use canary_ir::types::IrType;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackVar {
    pub offset: i64,
    pub size: u8,
    pub name: String,
    pub ty: IrType,
}

pub struct StackFrame {
    pub vars: Vec<StackVar>,
    pub frame_size: u64,
}

pub fn recover_stack_vars(func: &SsaFunction, vsa: &VsaResult) -> StackFrame {
    let mut accesses: BTreeMap<i64, u8> = BTreeMap::new();

    let mut add_access = |addr: &SsaExpr, size: u8| {
        if let SsaExpr::Reg { reg, .. } = addr {
            if let Some(ValueSet::PtrOffset {
                base: PtrBase::StackFrame,
                offset,
            }) = vsa.values.get(reg)
            {
                let current_size = accesses.entry(*offset).or_insert(size);
                if size > *current_size {
                    *current_size = size;
                }
            }
        }
    };

    fn walk_expr(expr: &SsaExpr, add_access: &mut impl FnMut(&SsaExpr, u8)) {
        match expr {
            SsaExpr::Load { addr, size } => {
                add_access(addr, size.bytes());
                walk_expr(addr, add_access);
            }
            SsaExpr::BinOp { lhs, rhs, .. } => {
                walk_expr(lhs, add_access);
                walk_expr(rhs, add_access);
            }
            SsaExpr::UnOp { operand, .. } => {
                walk_expr(operand, add_access);
            }
            SsaExpr::Sx { expr, .. } | SsaExpr::Zx { expr, .. } => {
                walk_expr(expr, add_access);
            }
            _ => {}
        }
    }

    for block in func.blocks.values() {
        for instr in &block.instrs {
            match instr {
                SsaInstr::Assign { dest, expr, .. } => {
                    if let SsaDest::Mem { addr, size } = dest {
                        add_access(addr, size.bytes());
                        walk_expr(addr, &mut add_access);
                    }
                    walk_expr(expr, &mut add_access);
                }
                SsaInstr::Store {
                    addr, value, size, ..
                } => {
                    add_access(addr, size.bytes());
                    walk_expr(addr, &mut add_access);
                    walk_expr(value, &mut add_access);
                }
                SsaInstr::If { cond, .. } => {
                    walk_expr(cond, &mut add_access);
                }
                SsaInstr::Call { target, args, .. } => {
                    walk_expr(target, &mut add_access);
                    for arg in args {
                        walk_expr(arg, &mut add_access);
                    }
                }
                SsaInstr::Return {
                    value: Some(val), ..
                } => {
                    walk_expr(val, &mut add_access);
                }
                SsaInstr::Intrinsic { inputs, .. } => {
                    for input in inputs {
                        walk_expr(input, &mut add_access);
                    }
                }
                SsaInstr::SetFlags { lhs, rhs, .. } => {
                    walk_expr(lhs, &mut add_access);
                    walk_expr(rhs, &mut add_access);
                }
                _ => {}
            }
        }
    }

    // Cluster overlapping/adjacent accesses
    let mut clustered: Vec<(i64, u8)> = Vec::new();
    for (offset, size) in accesses {
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

    let mut vars = Vec::new();
    let mut min_offset = 0i64;

    for (offset, size) in clustered {
        if offset < min_offset {
            min_offset = offset;
        }

        let name = if offset < 0 {
            format!("local_0x{:x}", -offset)
        } else {
            format!("arg_0x{:x}", offset)
        };

        vars.push(StackVar {
            offset,
            size,
            name,
            ty: IrType::Int {
                bit_width: size * 8,
                signed: false,
            },
        });
    }

    let frame_size = if min_offset < 0 {
        (-min_offset) as u64
    } else {
        0
    };

    StackFrame { vars, frame_size }
}

#[cfg(test)]
mod tests {
    use super::*;
    use canary_ir::cfg::BlockId;
    use canary_ir::llil::{OperandSize, Reg};
    use canary_ir::ssa::{SsaBlock, SsaName};

    fn make_test_vsa() -> VsaResult {
        let mut values = indexmap::IndexMap::new();
        let rbp = SsaName {
            reg: Reg(6),
            version: 0,
        };
        values.insert(
            rbp,
            ValueSet::PtrOffset {
                base: PtrBase::StackFrame,
                offset: 0,
            },
        );

        // rbp - 8
        let r1 = SsaName {
            reg: Reg(1),
            version: 1,
        };
        values.insert(
            r1,
            ValueSet::PtrOffset {
                base: PtrBase::StackFrame,
                offset: -8,
            },
        );

        // rbp - 16
        let r2 = SsaName {
            reg: Reg(2),
            version: 1,
        };
        values.insert(
            r2,
            ValueSet::PtrOffset {
                base: PtrBase::StackFrame,
                offset: -16,
            },
        );

        // rbp - 24
        let r3 = SsaName {
            reg: Reg(3),
            version: 1,
        };
        values.insert(
            r3,
            ValueSet::PtrOffset {
                base: PtrBase::StackFrame,
                offset: -24,
            },
        );

        // rbp - 4 (overlapping with rbp-8?) No, rbp-8 is 8 bytes, so end is 0. rbp-4 end is 0.
        let r4 = SsaName {
            reg: Reg(4),
            version: 1,
        };
        values.insert(
            r4,
            ValueSet::PtrOffset {
                base: PtrBase::StackFrame,
                offset: -4,
            },
        );

        VsaResult { values }
    }

    #[test]
    fn stack_single_local() {
        let vsa = make_test_vsa();
        let mut func = SsaFunction {
            entry_addr: 0,
            name: "".into(),
            blocks: indexmap::IndexMap::new(),
        };

        let block = SsaBlock {
            id: BlockId(0),
            phis: vec![],
            instrs: vec![SsaInstr::Store {
                confidence: Default::default(),
                addr: SsaExpr::Reg {
                    reg: SsaName {
                        reg: Reg(1),
                        version: 1,
                    },
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

        let frame = recover_stack_vars(&func, &vsa);
        assert_eq!(frame.vars.len(), 1);
        assert_eq!(frame.vars[0].offset, -8);
        assert_eq!(frame.vars[0].size, 8);
        assert_eq!(frame.vars[0].name, "local_0x8");
        assert_eq!(frame.frame_size, 8);
    }

    #[test]
    fn stack_multiple_locals() {
        let vsa = make_test_vsa();
        let mut func = SsaFunction {
            entry_addr: 0,
            name: "".into(),
            blocks: indexmap::IndexMap::new(),
        };

        let block = SsaBlock {
            id: BlockId(0),
            phis: vec![],
            instrs: vec![
                SsaInstr::Store {
                    confidence: Default::default(),
                    addr: SsaExpr::Reg {
                        reg: SsaName {
                            reg: Reg(1),
                            version: 1,
                        },
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
                        reg: SsaName {
                            reg: Reg(2),
                            version: 1,
                        },
                        size: OperandSize::Bits64,
                    },
                    value: SsaExpr::Const {
                        value: 0,
                        size: OperandSize::Bits64,
                    },
                    size: OperandSize::Bits64,
                },
            ],
        };
        func.blocks.insert(BlockId(0), block);

        let frame = recover_stack_vars(&func, &vsa);
        assert_eq!(frame.vars.len(), 2);
    }

    #[test]
    fn stack_overlapping_accesses() {
        let vsa = make_test_vsa();
        let mut func = SsaFunction {
            entry_addr: 0,
            name: "".into(),
            blocks: indexmap::IndexMap::new(),
        };

        // Write 8 bytes to rbp-8, then 4 bytes to rbp-4
        let block = SsaBlock {
            id: BlockId(0),
            phis: vec![],
            instrs: vec![
                SsaInstr::Store {
                    confidence: Default::default(),
                    addr: SsaExpr::Reg {
                        reg: SsaName {
                            reg: Reg(1),
                            version: 1,
                        },
                        size: OperandSize::Bits64,
                    },
                    value: SsaExpr::Const {
                        value: 0,
                        size: OperandSize::Bits64,
                    },
                    size: OperandSize::Bits64, // 8 bytes at -8 (ends at 0)
                },
                SsaInstr::Store {
                    confidence: Default::default(),
                    addr: SsaExpr::Reg {
                        reg: SsaName {
                            reg: Reg(4),
                            version: 1,
                        },
                        size: OperandSize::Bits64,
                    },
                    value: SsaExpr::Const {
                        value: 0,
                        size: OperandSize::Bits32,
                    },
                    size: OperandSize::Bits32, // 4 bytes at -4 (ends at 0)
                },
            ],
        };
        func.blocks.insert(BlockId(0), block);

        let frame = recover_stack_vars(&func, &vsa);
        assert_eq!(frame.vars.len(), 1); // Should cluster into 1 variable
        assert_eq!(frame.vars[0].offset, -8);
        assert_eq!(frame.vars[0].size, 8); // Max extent is 8
    }

    #[test]
    fn stack_no_stack_frame() {
        let vsa = make_test_vsa();
        let func = SsaFunction {
            entry_addr: 0,
            name: "".into(),
            blocks: indexmap::IndexMap::new(),
        };
        let frame = recover_stack_vars(&func, &vsa);
        assert_eq!(frame.vars.len(), 0);
        assert_eq!(frame.frame_size, 0);
    }
}
