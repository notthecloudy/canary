//! `canary-ir` — Canary Intermediate Representation
//!
//! This crate defines the core IR types used throughout the Canary analysis pipeline.
//! The IR is structured in three levels:
//!
//! - **LLIL** (Low-Level IR): Architecture-agnostic register transfer language
//! - **MLIL** (Mid-Level IR): Named variables, explicit calling conventions
//! - **HLIL** (High-Level IR): Structured control flow, dialect-aware nodes
//!
//! # Design Principles
//!
//! IR nodes are **never** heap-allocated individually with `Rc<RefCell<>>`.
//! Instead, they live in typed arenas and are referenced by stable [`NodeId`] values.
//!
//! This enables:
//! - Cache-friendly traversal
//! - Safe parallel reads (arena is `Send + Sync` once written)
//! - Incremental invalidation by ID, not pointer
//! - Guaranteed absence of reference cycles

pub mod arena;
pub mod cfg;
pub mod dialect;
pub mod function;
pub mod llil;
pub mod mlil;
pub mod ssa;
pub mod types;

pub use arena::{Arena, NodeId};
pub use cfg::{cfg_validate, BasicBlock, BlockId, CfgError, ControlFlowGraph, Edge, EdgeKind};
pub use function::{Function, FunctionId};
pub use llil::{LlilExpr, LlilInstr, LlilOp};
pub use mlil::{MlilBlock, MlilDest, MlilExpr, MlilFunction, MlilInstr, MlilVar, VarId, VarSource};
pub use ssa::{PhiNode, PhiOperand, SsaBlock, SsaDest, SsaExpr, SsaFunction, SsaInstr, SsaName};
pub use types::{IrType, TypeId};

pub mod semantic;
