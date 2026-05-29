//! Mid-Level Intermediate Representation (MLIL).
//!
//! MLIL introduces variables (replacing physical registers), variable types,
//! and calling convention details.

use crate::cfg::BlockId;
use crate::types::IrType;
use indexmap::IndexMap;

/// A unique identifier for a variable in MLIL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VarId(pub usize);

/// A variable in MLIL, representing a named, typed value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlilVar {
    pub id: VarId,
    pub name: String,
    pub ty: IrType,
    pub source: VarSource,
}

/// The origin of a variable (e.g. which register or stack offset it came from).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VarSource {
    Register(crate::llil::Reg),
    StackOffset(i64),
    Parameter(usize),
    Temporary,
}

/// A block of MLIL instructions.
#[derive(Debug, Clone, PartialEq)]
pub struct MlilBlock {
    pub id: BlockId,
    pub instrs: Vec<MlilInstr>,
}

/// Pointer provenance carried from SSA analyses into MLIL instruction slots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlilProvenance {
    pub base: String,
    pub offset: i64,
    pub alias: String,
}

/// A complete MLIL representation of a function.
#[derive(Debug, Clone, PartialEq)]
pub struct MlilFunction {
    pub blocks: IndexMap<BlockId, MlilBlock>,
    pub vars: IndexMap<VarId, MlilVar>,
    pub instr_provenance: IndexMap<(BlockId, usize), Vec<MlilProvenance>>,
    pub semantic: Option<crate::semantic::SemanticFunction>,
    pub scheduled_order: Vec<String>,
}

/// A target destination for an assignment in MLIL.
#[derive(Debug, Clone, PartialEq)]
pub enum MlilDest {
    Var(VarId),
    Mem {
        addr: Box<MlilExpr>,
        size: crate::llil::OperandSize,
    },
}

/// An instruction in MLIL.
#[derive(Debug, Clone, PartialEq)]
pub enum MlilInstr {
    Assign {
        dest: MlilDest,
        expr: MlilExpr,
        confidence: crate::types::ConfidenceTag,
    },
    Store {
        addr: MlilExpr,
        value: MlilExpr,
        size: crate::llil::OperandSize,
        confidence: crate::types::ConfidenceTag,
    },
    Goto {
        target: u64,
        confidence: crate::types::ConfidenceTag,
    },
    If {
        cond: MlilExpr,
        true_target: u64,
        false_target: u64,
        confidence: crate::types::ConfidenceTag,
    },
    Call {
        target: MlilExpr,
        args: Vec<MlilExpr>,
        ret: Option<VarId>,
        confidence: crate::types::ConfidenceTag,
    },
    Return {
        value: Option<MlilExpr>,
        confidence: crate::types::ConfidenceTag,
    },
    Intrinsic {
        name: String,
        inputs: Vec<MlilExpr>,
        outputs: Vec<VarId>,
        confidence: crate::types::ConfidenceTag,
    },
}

/// An expression in MLIL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MlilExpr {
    Const {
        value: u64,
        size: crate::llil::OperandSize,
    },
    Var(VarId),
    Load {
        addr: Box<MlilExpr>,
        size: crate::llil::OperandSize,
    },
    BinOp {
        op: crate::llil::LlilOp,
        lhs: Box<MlilExpr>,
        rhs: Box<MlilExpr>,
        size: crate::llil::OperandSize,
    },
    UnOp {
        op: crate::llil::LlilUnOp,
        operand: Box<MlilExpr>,
        size: crate::llil::OperandSize,
    },
    Sx {
        from_size: crate::llil::OperandSize,
        to_size: crate::llil::OperandSize,
        expr: Box<MlilExpr>,
    },
    Zx {
        from_size: crate::llil::OperandSize,
        to_size: crate::llil::OperandSize,
        expr: Box<MlilExpr>,
    },
    FlagCond {
        cond: crate::llil::FlagCondition,
    },
    AddressOf(VarId),
}
