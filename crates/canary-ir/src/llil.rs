//! LLIL
use crate::arena::NodeId;
/// A virtual register in the LLIL. Before SSA transformation,
/// these correspond loosely to physical registers. After SSA,
/// each `Reg` is defined exactly once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Reg(pub u32);

impl std::fmt::Display for Reg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "r{}", self.0)
    }
}

/// The size of an operand in bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperandSize {
    Bits8,
    Bits16,
    Bits32,
    Bits64,
    Bits128,
}

impl OperandSize {
    /// Returns the size in bytes.
    pub fn bytes(self) -> u8 {
        match self {
            Self::Bits8 => 1,
            Self::Bits16 => 2,
            Self::Bits32 => 4,
            Self::Bits64 => 8,
            Self::Bits128 => 16,
        }
    }

    /// Returns the size in bits.
    pub fn bits(self) -> u8 {
        self.bytes() * 8
    }
}

/// An LLIL expression — a pure, side-effect-free computation of a value.
#[derive(Debug, Clone, PartialEq)]
pub enum LlilExpr {
    /// A constant integer value.
    Const { value: u64, size: OperandSize },

    /// Read a virtual register.
    Reg { reg: Reg, size: OperandSize },

    /// Load a value from memory at the given address expression.
    Load {
        addr: NodeId<LlilExpr>,
        size: OperandSize,
    },

    /// Arithmetic / bitwise operations.
    BinOp {
        op: LlilOp,
        lhs: NodeId<LlilExpr>,
        rhs: NodeId<LlilExpr>,
        size: OperandSize,
    },

    /// Unary operations (sign extension, zero extension, negation, not).
    UnOp {
        op: LlilUnOp,
        operand: NodeId<LlilExpr>,
        size: OperandSize,
    },

    /// Sign-extend `expr` from `from_size` to `to_size`.
    Sx {
        from_size: OperandSize,
        to_size: OperandSize,
        expr: NodeId<LlilExpr>,
    },

    /// Zero-extend `expr` from `from_size` to `to_size`.
    Zx {
        from_size: OperandSize,
        to_size: OperandSize,
        expr: NodeId<LlilExpr>,
    },

    /// The address of a label (used for computed jumps).
    LabelAddr { target: u64 },

    /// Read a CPU flag (e.g. ZF, CF, SF, OF after CMP/TEST)
    Flag { flag: CpuFlag },

    /// Combined flag condition (e.g. SF != OF for JL)
    FlagCond { cond: FlagCondition },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CpuFlag {
    CF,
    ZF,
    SF,
    OF,
    PF,
    AF,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlagCondition {
    Equal,      // ZF=1        (JE/JZ)
    NotEqual,   // ZF=0        (JNE/JNZ)
    Less,       // SF!=OF      (JL)
    LessEq,     // ZF | SF!=OF (JLE)
    Greater,    // !ZF & SF=OF (JG)
    GreaterEq,  // SF=OF       (JGE)
    Below,      // CF=1        (JB/JC)
    BelowEq,    // CF | ZF     (JBE)
    Above,      // !CF & !ZF   (JA)
    AboveEq,    // !CF         (JAE)
    Sign,       // SF=1        (JS)
    NoSign,     // SF=0        (JNS)
    Overflow,   // OF=1        (JO)
    NoOverflow, // OF=0        (JNO)
    Parity,     // PF=1        (JP)
    NoParity,   // PF=0        (JNP)
}

/// Binary operation kinds in LLIL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LlilOp {
    Add,
    Sub,
    Mul,
    MulsDp, // Signed double-precision multiply
    MuluDp, // Unsigned double-precision multiply
    Divu,
    Divs,
    Modu,
    Mods,
    And,
    Or,
    Xor,
    Lsl,    // Logical shift left
    Lsr,    // Logical shift right
    Asr,    // Arithmetic shift right
    Rol,    // Rotate left
    Ror,    // Rotate right
    CmpE,   // ==
    CmpNe,  // !=
    CmpSlt, // signed <
    CmpUlt, // unsigned <
    CmpSle, // signed <=
    CmpUle, // unsigned <=
    CmpSge, // signed >=
    CmpUge, // unsigned >=
    CmpSgt, // signed >
    CmpUgt, // unsigned >
}

/// Unary operation kinds in LLIL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LlilUnOp {
    Neg,
    Not,
    Popcount,
    Bswap,
    Clz, // Count leading zeros
}

/// A destination for an assignment instruction.
#[derive(Debug, Clone, PartialEq)]
pub enum LlilDest {
    Reg(Reg),
    Mem { addr: LlilExpr, size: OperandSize },
}

/// An LLIL instruction — a side-effecting statement.
#[derive(Debug, Clone, PartialEq)]
pub enum LlilInstr {
    /// Assign the result of `expr` to `dest`.
    Assign {
        dest: LlilDest,
        expr: LlilExpr,
        confidence: crate::types::ConfidenceTag,
    },

    /// Store `value` to `addr`.
    Store {
        addr: LlilExpr,
        value: LlilExpr,
        size: OperandSize,
        confidence: crate::types::ConfidenceTag,
    },

    /// Unconditional branch to `target`.
    Goto {
        target: u64,
        confidence: crate::types::ConfidenceTag,
    },

    /// Conditional branch: if `cond` is nonzero, jump to `true_target`, else `false_target`.
    If {
        cond: LlilExpr,
        true_target: u64,
        false_target: u64,
        confidence: crate::types::ConfidenceTag,
    },

    /// Call to `target` with `args`. `ret` receives the return value (if any).
    Call {
        target: LlilExpr,
        args: Vec<LlilExpr>,
        ret: Option<Reg>,
        confidence: crate::types::ConfidenceTag,
    },

    /// Return from function, optionally with a return value expression.
    Return {
        value: Option<LlilExpr>,
        confidence: crate::types::ConfidenceTag,
    },

    /// Undefined / unlifted instruction (placeholder for instructions
    /// the lifter does not yet handle).
    Undef {
        /// Original instruction bytes.
        bytes: Vec<u8>,
        confidence: crate::types::ConfidenceTag,
    },

    /// Intrinsic call — a named side-effecting operation with no IR equivalent
    /// (e.g., CPUID, RDTSC, memory barriers).
    Intrinsic {
        name: String,
        inputs: Vec<LlilExpr>,
        outputs: Vec<Reg>,
        confidence: crate::types::ConfidenceTag,
    },

    /// Explicit trap or breakpoint (e.g. int3, ud2)
    Trap {
        confidence: crate::types::ConfidenceTag,
    },

    /// Result of CMP/TEST — writes flag state without a register result
    SetFlags {
        op: LlilOp, // always CmpE, CmpSlt, etc.
        lhs: LlilExpr,
        rhs: LlilExpr,
        confidence: crate::types::ConfidenceTag,
    },
}

impl LlilInstr {
    /// Returns `true` if this instruction terminates a basic block.
    pub fn is_terminator(&self) -> bool {
        matches!(
            self,
            LlilInstr::Goto { .. }
                | LlilInstr::If { .. }
                | LlilInstr::Return { .. }
                | LlilInstr::Trap { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn const_expr() {
        let expr = LlilExpr::Const {
            value: 42,
            size: OperandSize::Bits64,
        };
        assert!(matches!(expr, LlilExpr::Const { value: 42, .. }));
    }

    #[test]
    fn goto_is_terminator() {
        let instr = LlilInstr::Goto {
            confidence: Default::default(),
            target: 0x1000,
        };
        assert!(instr.is_terminator());
    }

    #[test]
    fn store_is_not_terminator() {
        let instr = LlilInstr::Store {
            confidence: Default::default(),
            addr: LlilExpr::Const {
                value: 0,
                size: OperandSize::Bits64,
            },
            value: LlilExpr::Const {
                value: 0,
                size: OperandSize::Bits32,
            },
            size: OperandSize::Bits32,
        };
        assert!(!instr.is_terminator());
    }
}
