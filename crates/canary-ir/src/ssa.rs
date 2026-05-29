//! SSA (Static Single Assignment) form types.
//!
//! After SSA transformation, every virtual register is defined exactly once.
//! At control flow join points, φ (phi) functions merge definitions from
//! multiple predecessor blocks:
//!
//! ```text
//! x₃ = φ(x₁, x₂)   // x₃ = x₁ if we came from block A, x₂ if from block B
//! ```
//!
//! # Construction
//!
//! SSA construction is performed by `canary-analysis`. This module only
//! defines the types — φ-nodes, use-def chains, and the SSA name space.

use crate::cfg::BlockId;
use crate::llil::Reg;

/// An SSA name — a virtual register with a version suffix.
///
/// Before SSA: `r0` appears multiple times (defined multiple times).
/// After SSA: `r0_v1`, `r0_v2`, ... each defined exactly once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SsaName {
    pub reg: Reg,
    pub version: u32,
}

impl std::fmt::Display for SsaName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}_v{}", self.reg, self.version)
    }
}

/// A φ (phi) function placed at the entry of a join block.
///
/// `result = φ(operands[0], operands[1], ...)`
/// where `operands[i]` is the definition reaching from `blocks[i]`.
#[derive(Debug, Clone)]
pub struct PhiNode {
    /// The SSA name being defined by this phi.
    pub result: SsaName,
    /// The predecessor blocks and corresponding definitions.
    pub operands: Vec<PhiOperand>,
}

/// One arm of a φ-function — the reaching definition from a specific predecessor.
#[derive(Debug, Clone)]
pub struct PhiOperand {
    /// The predecessor block this definition comes from.
    pub block: BlockId,
    /// The SSA name of the reaching definition.
    pub name: SsaName,
}

/// The complete set of φ-nodes for a single basic block.
///
/// φ-nodes are placed at the *entry* of a block, before any other instructions.
#[derive(Debug, Default, Clone)]
pub struct BlockPhis {
    pub phis: Vec<PhiNode>,
}

use crate::llil::{CpuFlag, FlagCondition, LlilOp, LlilUnOp, OperandSize};

#[derive(Debug, Clone, PartialEq)]
pub enum SsaExpr {
    Const {
        value: u64,
        size: OperandSize,
    },
    Reg {
        reg: SsaName,
        size: OperandSize,
    },
    Load {
        addr: Box<SsaExpr>,
        size: OperandSize,
    },
    BinOp {
        op: LlilOp,
        lhs: Box<SsaExpr>,
        rhs: Box<SsaExpr>,
        size: OperandSize,
    },
    UnOp {
        op: LlilUnOp,
        operand: Box<SsaExpr>,
        size: OperandSize,
    },
    Sx {
        from_size: OperandSize,
        to_size: OperandSize,
        expr: Box<SsaExpr>,
    },
    Zx {
        from_size: OperandSize,
        to_size: OperandSize,
        expr: Box<SsaExpr>,
    },
    LabelAddr {
        target: u64,
    },
    Flag {
        flag: CpuFlag,
    },
    FlagCond {
        cond: FlagCondition,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum SsaDest {
    Reg(SsaName),
    Mem { addr: SsaExpr, size: OperandSize },
}

#[derive(Debug, Clone, PartialEq)]
pub enum SsaInstr {
    Assign {
        dest: SsaDest,
        expr: SsaExpr,
        confidence: crate::types::ConfidenceTag,
    },
    Store {
        addr: SsaExpr,
        value: SsaExpr,
        size: OperandSize,
        confidence: crate::types::ConfidenceTag,
    },
    Goto {
        target: u64,
        confidence: crate::types::ConfidenceTag,
    },
    If {
        cond: SsaExpr,
        true_target: u64,
        false_target: u64,
        confidence: crate::types::ConfidenceTag,
    },
    Call {
        target: SsaExpr,
        args: Vec<SsaExpr>,
        ret: Option<SsaName>,
        confidence: crate::types::ConfidenceTag,
    },
    Return {
        value: Option<SsaExpr>,
        confidence: crate::types::ConfidenceTag,
    },
    Undef {
        bytes: Vec<u8>,
        confidence: crate::types::ConfidenceTag,
    },
    Intrinsic {
        name: String,
        inputs: Vec<SsaExpr>,
        outputs: Vec<SsaName>,
        confidence: crate::types::ConfidenceTag,
    },
    SetFlags {
        op: LlilOp,
        lhs: SsaExpr,
        rhs: SsaExpr,
        confidence: crate::types::ConfidenceTag,
    },
    Trap {
        confidence: crate::types::ConfidenceTag,
    },
}

#[derive(Debug, Clone)]
pub struct SsaBlock {
    pub id: BlockId,
    pub phis: Vec<PhiNode>,
    pub instrs: Vec<SsaInstr>,
}

#[derive(Debug, Clone)]
pub struct SsaFunction {
    pub entry_addr: u64,
    pub name: String,
    pub blocks: indexmap::IndexMap<BlockId, SsaBlock>,
}

impl std::fmt::Display for PhiNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} = phi(", self.result)?;
        for (i, op) in self.operands.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "[{}, {}]", op.name, op.block)?;
        }
        write!(f, ")")
    }
}

impl std::fmt::Display for SsaExpr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SsaExpr::Const { value, .. } => write!(f, "{value:#x}"),
            SsaExpr::Reg { reg, .. } => write!(f, "{reg}"),
            SsaExpr::Load { addr, .. } => write!(f, "*({addr})"),
            SsaExpr::BinOp { op, lhs, rhs, .. } => {
                let op_str = match op {
                    LlilOp::Add => "+",
                    LlilOp::Sub => "-",
                    LlilOp::Mul => "*",
                    LlilOp::And => "&",
                    LlilOp::Or => "|",
                    LlilOp::Xor => "^",
                    LlilOp::Lsl => "<<",
                    LlilOp::Lsr => ">>",
                    LlilOp::Asr => ">>",
                    LlilOp::CmpE => "==",
                    LlilOp::CmpNe => "!=",
                    LlilOp::CmpSlt | LlilOp::CmpUlt => "<",
                    LlilOp::CmpSle | LlilOp::CmpUle => "<=",
                    LlilOp::CmpSgt | LlilOp::CmpUgt => ">",
                    LlilOp::CmpSge | LlilOp::CmpUge => ">=",
                    _ => "?",
                };
                write!(f, "({lhs} {op_str} {rhs})")
            }
            SsaExpr::UnOp { op, operand, .. } => {
                let op_str = match op {
                    LlilUnOp::Neg => "-",
                    LlilUnOp::Not => "~",
                    LlilUnOp::Popcount => "popcount",
                    LlilUnOp::Bswap => "bswap",
                    LlilUnOp::Clz => "clz",
                };
                write!(f, "{op_str}({operand})")
            }
            SsaExpr::Sx { expr, .. } => write!(f, "sx({expr})"),
            SsaExpr::Zx { expr, .. } => write!(f, "zx({expr})"),
            SsaExpr::LabelAddr { target } => write!(f, "&&label_{target:#x}"),
            SsaExpr::Flag { flag } => write!(f, "flag_{flag:?}"),
            SsaExpr::FlagCond { cond } => write!(f, "cond_{cond:?}"),
        }
    }
}

impl std::fmt::Display for SsaDest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SsaDest::Reg(reg) => write!(f, "{reg}"),
            SsaDest::Mem { addr, size } => write!(f, "*(uint{}_t*)({addr})", size.bits()),
        }
    }
}

impl std::fmt::Display for SsaInstr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SsaInstr::Assign { dest, expr, .. } => write!(f, "{dest} = {expr}"),
            SsaInstr::Store {
                addr, value, size, ..
            } => write!(f, "*(uint{}_t*)({addr}) = {value}", size.bits()),
            SsaInstr::Goto { target, .. } => write!(f, "goto label_{target:#x}"),
            SsaInstr::If {
                cond,
                true_target,
                false_target,
                ..
            } => {
                write!(
                    f,
                    "if ({cond}) goto label_{true_target:#x} else goto label_{false_target:#x}"
                )
            }
            SsaInstr::Call {
                target, args, ret, ..
            } => {
                if let Some(r) = ret {
                    write!(f, "{r} = ")?;
                }
                write!(f, "{target}(")?;
                for (i, arg) in args.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{arg}")?;
                }
                write!(f, ")")
            }
            SsaInstr::Return { value, .. } => {
                if let Some(v) = value {
                    write!(f, "return {v}")
                } else {
                    write!(f, "return")
                }
            }
            SsaInstr::Undef { bytes, .. } => write!(f, "undef({} bytes)", bytes.len()),
            SsaInstr::Intrinsic {
                name,
                inputs,
                outputs,
                ..
            } => {
                if !outputs.is_empty() {
                    for (i, out) in outputs.iter().enumerate() {
                        if i > 0 {
                            write!(f, ", ")?;
                        }
                        write!(f, "{out}")?;
                    }
                    write!(f, " = ")?;
                }
                write!(f, "__intrinsic_{name}(")?;
                for (i, inp) in inputs.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{inp}")?;
                }
                write!(f, ")")
            }
            SsaInstr::SetFlags { op, lhs, rhs, .. } => write!(f, "setflags({op:?}, {lhs}, {rhs})"),
            SsaInstr::Trap { .. } => write!(f, "trap"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arena::{Arena, NodeId};
    use crate::cfg::BlockId;
    use crate::llil::Reg;

    #[test]
    fn phi_display() {
        let name = SsaName {
            reg: Reg(0),
            version: 3,
        };
        assert_eq!(name.to_string(), "r0_v3");
    }

    #[test]
    fn phi_node_construction() {
        let result = SsaName {
            reg: Reg(2),
            version: 0,
        };
        let phi = PhiNode {
            result,
            operands: vec![
                PhiOperand {
                    block: BlockId(0),
                    name: SsaName {
                        reg: Reg(2),
                        version: 1,
                    },
                },
                PhiOperand {
                    block: BlockId(1),
                    name: SsaName {
                        reg: Reg(2),
                        version: 2,
                    },
                },
            ],
        };
        assert_eq!(phi.operands.len(), 2);
    }
}
