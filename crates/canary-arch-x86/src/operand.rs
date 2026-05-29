use canary_arch::LiftError;
use canary_ir::llil::{LlilDest, LlilExpr, LlilOp, OperandSize};
use capstone::arch::x86::{X86OpMem, X86Operand, X86OperandType};

use crate::registers;

pub fn op_size_from_bytes(bytes: u8) -> OperandSize {
    match bytes {
        1 => OperandSize::Bits8,
        2 => OperandSize::Bits16,
        4 => OperandSize::Bits32,
        8 => OperandSize::Bits64,
        16 => OperandSize::Bits128,
        _ => OperandSize::Bits64,
    }
}

pub fn op_to_expr(
    op: &X86Operand,
    exprs: &mut canary_ir::arena::Arena<LlilExpr>,
) -> Result<LlilExpr, LiftError> {
    let size = op_size_from_bytes(op.size);
    match op.op_type {
        X86OperandType::Reg(r) => {
            if let Some((reg, sz)) = registers::capstone_reg_to_id_and_size(r) {
                // Return the expr with the requested size (e.g. read 32 bits from RAX)
                Ok(LlilExpr::Reg { reg, size: sz })
            } else {
                Err(LiftError::Disassembly {
                    addr: 0,
                    reason: "Unsupported register".to_string(),
                })
            }
        }
        X86OperandType::Imm(imm) => Ok(LlilExpr::Const {
            value: imm as u64,
            size,
        }),
        X86OperandType::Mem(mem) => Ok(LlilExpr::Load {
            addr: {
                let a = mem_addr_expr(&mem, exprs);
                exprs.alloc(a)
            },
            size,
        }),
        _ => Err(LiftError::Disassembly {
            addr: 0,
            reason: "Unsupported operand type".to_string(),
        }),
    }
}

pub fn op_to_dest(
    op: &X86Operand,
    exprs: &mut canary_ir::arena::Arena<LlilExpr>,
) -> Result<LlilDest, LiftError> {
    let size = op_size_from_bytes(op.size);
    match op.op_type {
        X86OperandType::Reg(r) => {
            if let Some((reg, _)) = registers::capstone_reg_to_id_and_size(r) {
                Ok(LlilDest::Reg(reg))
            } else {
                Err(LiftError::Disassembly {
                    addr: 0,
                    reason: "Unsupported register".to_string(),
                })
            }
        }
        X86OperandType::Mem(mem) => Ok(LlilDest::Mem {
            addr: mem_addr_expr(&mem, exprs),
            size,
        }),
        _ => Err(LiftError::Disassembly {
            addr: 0,
            reason: "Operand cannot be a destination".to_string(),
        }),
    }
}

pub fn mem_addr_expr(mem: &X86OpMem, exprs: &mut canary_ir::arena::Arena<LlilExpr>) -> LlilExpr {
    let mut expr = None;

    if let Some((base_reg, size)) = registers::capstone_reg_to_id_and_size(mem.base()) {
        expr = Some(LlilExpr::Reg {
            reg: base_reg,
            size,
        });
    }

    if let Some((index_reg, size)) = registers::capstone_reg_to_id_and_size(mem.index()) {
        let index_expr = LlilExpr::Reg {
            reg: index_reg,
            size,
        };
        let scaled_index = if mem.scale() > 1 {
            LlilExpr::BinOp {
                op: LlilOp::Mul,
                lhs: exprs.alloc(index_expr),
                rhs: exprs.alloc(LlilExpr::Const {
                    value: mem.scale() as u64,
                    size,
                }),
                size,
            }
        } else {
            index_expr
        };

        if let Some(e) = expr {
            expr = Some(LlilExpr::BinOp {
                op: LlilOp::Add,
                lhs: exprs.alloc(e),
                rhs: exprs.alloc(scaled_index),
                size,
            });
        } else {
            expr = Some(scaled_index);
        }
    }

    let disp = mem.disp();
    if disp != 0 || expr.is_none() {
        let disp_expr = LlilExpr::Const {
            value: disp.unsigned_abs(),
            size: OperandSize::Bits64,
        };
        if let Some(e) = expr {
            if disp < 0 {
                expr = Some(LlilExpr::BinOp {
                    op: LlilOp::Sub,
                    lhs: exprs.alloc(e),
                    rhs: exprs.alloc(disp_expr),
                    size: OperandSize::Bits64,
                });
            } else {
                expr = Some(LlilExpr::BinOp {
                    op: LlilOp::Add,
                    lhs: exprs.alloc(e),
                    rhs: exprs.alloc(disp_expr),
                    size: OperandSize::Bits64,
                });
            }
        } else {
            expr = Some(disp_expr);
        }
    }

    expr.unwrap_or(LlilExpr::Const {
        value: 0,
        size: OperandSize::Bits64,
    })
}
